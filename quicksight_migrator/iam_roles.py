"""iam_roles.py – IAM helpers for QuickSight migration

This module centralises every IAM artefact needed by the migration CLI:

* ServiceRolePatch  – patches the default `aws-quicksight-service-role-v0`
* SecretsRolePatch  – creates / updates `aws-quicksight-secretsmanager-role-v0`
* MigrationRole     – transient role assumed by the pipeline itself

All roles receive **only one inline policy**, granting QuickSight *exactly*
what it needs to read your database‑credentials secret (least privilege):

    - secretsmanager:DescribeSecret
    - secretsmanager:GetSecretValue
    - kms:Decrypt   (restricted by `kms:ViaService`)

You may **optionally** attach the AWS‑managed policy
`AWSQuickSightSecretsManagerWritePolicy`; set `SECRETS_MANAGED` below to the
ARN if you want that (the console does). Leave it empty (`""`) to skip.
"""

from __future__ import annotations

import json
import logging
import re
from typing import List

from botocore.exceptions import ClientError

from .config import Config

log = logging.getLogger(__name__)

# ─────────────────────────── constants ───────────────────────────
INLINE_POLICY_NAME = "QS-MigrationSecretsRead"
SERVICE_ROLE_NAME = "aws-quicksight-service-role-v0"
SECRETS_ROLE_NAME = "aws-quicksight-secretsmanager-role-v0"

# Optional managed policy; leave as "" to skip attach/detach.
SECRETS_MANAGED = "arn:aws:iam::aws:policy/AWSQuickSightSecretsManagerWritePolicy"

# -----------------------------------------------------------------


def _inline(secret_arn: str) -> str:
    """Return the inline‑policy JSON string granting QS access to *one* secret."""
    # extract region for kms:ViaService condition
    m = re.match(r"arn:aws:secretsmanager:([\w-]+):", secret_arn)
    region = m.group(1) if m else "*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadDbSecret",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    # "secretsmanager:*"
                ],
                "Resource": secret_arn,
            },
            {
                "Sid": "DecryptSecret",
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": f"secretsmanager.{region}.amazonaws.com"
                    }
                },
            },
        ],
    }

    return json.dumps(policy)


# ───────────────────────── patches / roles ─────────────────────────
class ServiceRolePatch:
    """Add the inline policy to the default QuickSight service role."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.iam = cfg.iam()

    def ensure(self):
        self.iam.put_role_policy(
            RoleName=SERVICE_ROLE_NAME,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=_inline(self.cfg.secret_arn),
        )
        log.info("Inline policy anexada a %s", SERVICE_ROLE_NAME)

    def cleanup(self):
        try:
            self.iam.delete_role_policy(
                RoleName=SERVICE_ROLE_NAME, PolicyName=INLINE_POLICY_NAME
            )
        except ClientError:
            pass


class SecretsRolePatch:
    """Create (or update) the Secrets Manager execution role for QuickSight."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.iam = cfg.iam()

    # --------------- public API ----------------
    def ensure(self):
        try:
            self.iam.get_role(RoleName=SECRETS_ROLE_NAME)
            log.info("Role %s encontrada", SECRETS_ROLE_NAME)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
            log.info("Role %s não encontrada – criando", SECRETS_ROLE_NAME)
            self._create()

        self._attach_policies()

    def cleanup(self):
        """Detach / delete inline & managed, then delete role. All idempotent."""
        steps = [
            (
                "delete inline",
                self.iam.delete_role_policy,
                dict(RoleName=SECRETS_ROLE_NAME, PolicyName=INLINE_POLICY_NAME),
            ),
        ]
        if SECRETS_MANAGED:
            steps.append(
                (
                    "detach managed",
                    self.iam.detach_role_policy,
                    dict(RoleName=SECRETS_ROLE_NAME, PolicyArn=SECRETS_MANAGED),
                )
            )
        steps.append(
            (
                "delete role",
                self.iam.delete_role,
                dict(RoleName=SECRETS_ROLE_NAME),
            )
        )

        for label, fn, kwargs in steps:
            try:
                fn(**kwargs)
                log.debug("%s → ok", label)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.debug("%s → já não existe", label)
                else:
                    raise

    # --------------- helpers -------------------
    def _create(self):
        self.iam.create_role(
            RoleName=SECRETS_ROLE_NAME,
            Path="/service-role/",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "quicksight.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            Description="QuickSight Secrets Manager integration (auto)",
        )
        self.iam.get_waiter("role_exists").wait(RoleName=SECRETS_ROLE_NAME)

    def _attach_policies(self):
        if SECRETS_MANAGED:
            try:
                self.iam.attach_role_policy(
                    RoleName=SECRETS_ROLE_NAME, PolicyArn=SECRETS_MANAGED
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.warning(
                        "Managed policy %s inexistente – seguindo só com inline",
                        SECRETS_MANAGED,
                    )
                else:
                    raise

        # always (re)put inline – idempotent
        self.iam.put_role_policy(
            RoleName=SECRETS_ROLE_NAME,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=_inline(self.cfg.secret_arn),
        )
        log.info("Inline policy anexada a %s", SECRETS_ROLE_NAME)


class MigrationRole:
    """Temporary role that the migration script assumes in the destination account."""

    SERVICE_PRINCIPAL = "quicksight.amazonaws.com"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.iam = cfg.iam()
        self.name = cfg.destination_account_id.role_name
        self.arn = cfg.destination_account_id.role_arn
        self.managed_policies: List[str] = cfg.managed_policies or []

    # --------------- public --------------------
    def ensure(self) -> str:
        try:
            role = self.iam.get_role(RoleName=self.name)["Role"]
            self._patch_trust(role)
            self._put_inline()
            log.info("Role %s já existia – patch aplicado", self.name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
            log.info("Role %s não encontrada – criando", self.name)
            self._create()
        return self.arn

    def cleanup(self):
        for pol in self.managed_policies:
            try:
                self.iam.detach_role_policy(RoleName=self.name, PolicyArn=pol)
            except ClientError:
                pass
        try:
            self.iam.delete_role_policy(
                RoleName=self.name, PolicyName=INLINE_POLICY_NAME
            )
            self.iam.delete_role(RoleName=self.name)
        except ClientError:
            pass

    # --------------- internals -----------------
    def _create(self):
        self.iam.create_role(
            RoleName=self.name,
            AssumeRolePolicyDocument=json.dumps(self._trust_doc()),
            Description="QuickSight migration role (auto)",
        )
        self.iam.get_waiter("role_exists").wait(RoleName=self.name)
        self._attach_policies()
        self._put_inline()
        log.info("Role %s criada", self.name)

    def _attach_policies(self):
        for pol in self.managed_policies:
            try:
                self.iam.attach_role_policy(RoleName=self.name, PolicyArn=pol)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.warning("Managed policy %s não encontrada – ignorando", pol)
                else:
                    raise

    def _put_inline(self):
        self.iam.put_role_policy(
            RoleName=self.name,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=_inline(self.cfg.secret_arn),
        )

    # ---------------- trust --------------------
    def _trust_doc(self):
        principals = [{"Service": self.SERVICE_PRINCIPAL}]
        if getattr(self.cfg, "trust_principal", None):
            principals.append({"AWS": self.cfg.trust_principal})
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": p, "Action": "sts:AssumeRole"}
                for p in principals
            ],
        }

    def _patch_trust(self, role):
        desired = self._trust_doc()
        current = role["AssumeRolePolicyDocument"]
        if json.dumps(current, sort_keys=True) != json.dumps(desired, sort_keys=True):
            self.iam.update_assume_role_policy(
                RoleName=self.name, PolicyDocument=json.dumps(desired)
            )


# ────────────────────────────────────────────────────────────────────────────────
# Role na conta ORIGEM (DEV) que o script na conta DESTINO assume
# ────────────────────────────────────────────────────────────────────────────────
class OriginRoleSetup:
    """
    Garante a existência da role `QS-MigrationOrigin` na conta de origem,
    permitindo ao destino listar/descrever Data Sets.

    Uso:
        OriginRoleSetup(
            session=boto3.Session(profile_name="dev"),     # credenciais na origem
            dest_role_arn="arn:aws:iam::528757801159:role/QS-MigrationDest",
            managed_policy_arn="arn:aws:iam::aws:policy/AWSQuickSightReadOnly"
        ).ensure()
    """

    ROLE_NAME = "QS-MigrationOrigin"

    def __init__(
        self,
        session,
        dest_role_arn: str,
        managed_policy_arn: str | None = None,
    ):
        self.iam = session.client("iam")
        self.dest_role_arn = dest_role_arn
        self.managed_policy_arn = (
            managed_policy_arn
            or "arn:aws:iam::aws:policy/AWSQuickSightReadOnly"  # cobre List/Describe
        )

    # ---------------- public ----------------------------------------------------
    def ensure(self):
        if not self._exists():
            self._create()
        self._attach_policies()
        logging.info("Role %s pronta na conta origem", self.ROLE_NAME)

    # ---------------- internals -------------------------------------------------
    def _exists(self) -> bool:
        try:
            self.iam.get_role(RoleName=self.ROLE_NAME)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    def _create(self):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self.dest_role_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        self.iam.create_role(
            RoleName=self.ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="QuickSight migration origin role (auto)",
        )
        self.iam.get_waiter("role_exists").wait(RoleName=self.ROLE_NAME)

    def _attach_policies(self):
        try:
            self.iam.attach_role_policy(
                RoleName=self.ROLE_NAME, PolicyArn=self.managed_policy_arn
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                logging.warning(
                    "Managed policy %s não encontrada; considere criar uma "
                    "policy custom com List/Describe QuickSight.",
                    self.managed_policy_arn,
                )
            else:
                raise


__all__ = ["ServiceRolePatch", "SecretsRolePatch", "MigrationRole"]
