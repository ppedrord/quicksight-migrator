"""iam_roles.py – IAM helpers for QuickSight migration

Patch 3 aplicado:
* **Registra** a role *QS-MigrationDest* como *QuickSight User (ADMIN)*, garantindo
  autorização para `DescribeDataSet` e demais chamadas à API do QuickSight.
* Adiciona método privado `_register_qs_role()` e invoca-o em
  `MigrationRole.ensure()`.
* Melhora logs quando a policy inline de *AssumeOriginRole* não pôde ser anexada.

A partir desta alteração, a role de destino passa a ser reconhecida pelo
QuickSight, eliminando os erros *AccessDeniedException* observados durante a
replicação de Data Sets.
"""

from __future__ import annotations

import json
import logging
import re
from typing import List, Optional

import boto3
import botocore
from botocore.exceptions import ClientError

from .config import Config

log = logging.getLogger(__name__)

# ─────────────────────────── constants ───────────────────────────
INLINE_POLICY_NAME = "QS-MigrationSecretsRead"
SERVICE_ROLE_NAME = "aws-quicksight-service-role-v0"
SECRETS_ROLE_NAME = "aws-quicksight-secretsmanager-role-v0"

# Optional managed policy; leave as "" to skip attach/detach.
SECRETS_MANAGED = "arn:aws:iam::aws:policy/AWSQuickSightSecretsManagerWritePolicy"

ASSUME_ORIGIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/QS-MigrationOrigin",
        }
    ],
}

QS_READ_WRITE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "quicksight:ListDataSets",
                "quicksight:DescribeDataSet",
                "quicksight:DescribeDataSetPermissions",
                "quicksight:ListIngestions",
                "quicksight:DescribeIngestion",
                "quicksight:PassDataSet",
                "quicksight:UpdateDataSet",
                "quicksight:DeleteDataSet",
                "quicksight:CreateIngestion",
                "quicksight:CancelIngestion",
                "quicksight:UpdateDataSetPermissions",
                "quicksight:CreateDataSet",
                "quicksight:PassDataSource",
            ],
            "Resource": "*",
        }
    ],
}

# -----------------------------------------------------------------


def _inline(secret_arn: str) -> str:
    """Return the inline-policy JSON string granting QS access to *one* secret."""
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
                log.info("%s → ok", label)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    log.info("%s → já não existe", label)
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
                            "Principal": {
                                "Service": "quicksight.amazonaws.com",
                                "AWS": self.cfg.trust_principal,
                            },
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

        # Garante que a role é reconhecida como usuário QuickSight
        self._register_qs_role()
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

    # ---- inline policies ------------------------------------------------------
    def _put_inline(self) -> None:
        # Secrets access
        log.info("Anexando policy inline %s", INLINE_POLICY_NAME)
        self.iam.put_role_policy(
            RoleName=self.name,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=_inline(self.cfg.secret_arn),
        )
        log.info("Anexando policy inline %s", "AllowAssumeOriginRole")
        # AssumeRole na origem
        self.iam.put_role_policy(
            RoleName=self.name,
            PolicyName="AllowAssumeOriginRole",
            PolicyDocument=json.dumps(ASSUME_ORIGIN_POLICY),
        )
        log.info("Anexando policy inline %s", "QS-MigrationQuickSightReadWrite")
        # Permissões QuickSight básicas
        self.iam.put_role_policy(
            RoleName=self.name,
            PolicyName="QS-MigrationQuickSightReadWrite",
            PolicyDocument=json.dumps(QS_READ_WRITE_POLICY),
        )
        log.info(
            "Inline policies QS‑MigrationDest atualizadas (Secrets, AssumeOrigin, QS‑Read)"
        )

    # ---------------- QuickSight registration --------------------
    def _register_qs_role(self):
        """Registra a IAM Role como *QuickSight User* (ADMIN) caso necessário."""
        qs = self.cfg.qs()
        account_id = self.cfg.destination_account_id.account_id
        try:
            qs.describe_user(
                AwsAccountId=account_id,
                Namespace="default",
                UserName=self.name,
            )
            log.info("QuickSight user %s já existe", self.name)
        except qs.exceptions.ResourceNotFoundException:  # type: ignore[attr-defined]
            email = f"noreply+{self.name.lower()}@example.com"
            try:
                qs.register_user(
                    AwsAccountId=account_id,
                    Namespace="default",
                    IdentityType="IAM",
                    IamArn=self.arn,
                    SessionName="qs-migration",
                    UserRole="ADMIN",
                    Email=email,
                )
                log.info("Role %s registrada como QuickSight ADMIN", self.name)
            except qs.exceptions.ResourceExistsException:  # type: ignore[attr-defined]
                log.info("QuickSight user %s já estava registrado", self.name)
            except ClientError as e:
                log.warning("Falha ao registrar role no QuickSight: %s", e)

    # ---------------- trust --------------------
    def _caller_arn(self):
        try:
            sts = boto3.client("sts")
            return sts.get_caller_identity()["Arn"]
        except botocore.exceptions.BotoCoreError:
            return None

    def _trust_doc(self):
        principals = [{"Service": self.SERVICE_PRINCIPAL}]
        if self.cfg.trust_principal:
            principals.append({"AWS": self.cfg.trust_principal})
        else:
            arn = self._caller_arn()
            if arn:
                principals.append({"AWS": arn})
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
    Garante a existência da role *QS-MigrationOrigin* na **conta de origem**
    permitindo que a role de destino faça List/Describe de Data Sets.

    Parameters
    ----------
    session : boto3.Session
        Credenciais já apontando para a conta origem.
    dest_role_arn : str
        ARN completo da role QS-MigrationDest na conta destino.
    managed_policy_arn : str | None, optional
        ARN da policy de leitura QuickSight (padrão = AmazonQuickSightReadOnly).
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
            managed_policy_arn or "arn:aws:iam::aws:policy/AmazonQuickSightReadOnly"
        )

    # ---------------- public ----------------------------------------------------
    def ensure(self) -> str:
        """
        Cria ou atualiza a role e devolve seu ARN.
        """
        if not self._exists():
            self._create()
        self._ensure_trust()
        self._attach_policies()
        arn = f"arn:aws:iam::{self._account_id()}:" f"role/{self.ROLE_NAME}"
        log.info("Role %s pronta na conta origem", self.ROLE_NAME)
        return arn

    # ---------------- internals -------------------------------------------------
    def _account_id(self) -> str:
        return self.iam.get_user()["User"]["Arn"].split(":")[4]

    def _exists(self) -> bool:
        try:
            self.iam.get_role(RoleName=self.ROLE_NAME)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    # ---- creation --------------------------------------------------------------
    def _create(self) -> None:
        trust = self._trust_doc()
        self.iam.create_role(
            RoleName=self.ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="QuickSight migration origin role (auto)",
        )
        self.iam.get_waiter("role_exists").wait(RoleName=self.ROLE_NAME)
        log.info("Role %s criada na conta origem", self.ROLE_NAME)

    # ---- trust policy ----------------------------------------------------------
    def _trust_doc(self) -> dict:
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": self.dest_role_arn},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "quicksight.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }
        log.info(
            "Trust policy de %s atualizada para permitir %s",
            self.ROLE_NAME,
            self.dest_role_arn,
        )
        return doc

    def _ensure_trust(self) -> None:
        current = self.iam.get_role(RoleName=self.ROLE_NAME)["Role"][
            "AssumeRolePolicyDocument"
        ]
        desired = self._trust_doc()
        if json.dumps(current, sort_keys=True) != json.dumps(desired, sort_keys=True):
            self.iam.update_assume_role_policy(
                RoleName=self.ROLE_NAME,
                PolicyDocument=json.dumps(desired),
            )
            log.info(
                "Trust policy de %s atualizada para permitir %s",
                self.ROLE_NAME,
                self.dest_role_arn,
            )

    # ---- permissions -----------------------------------------------------------
    def _attach_policies(self) -> None:
        try:
            self.iam.attach_role_policy(
                RoleName=self.ROLE_NAME, PolicyArn=self.managed_policy_arn
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log.warning(
                    "Managed policy %s não encontrada; criando inline fallback.",
                    self.managed_policy_arn,
                )
                self._put_inline_readonly()
            else:
                raise

    def _put_inline_readonly(self) -> None:
        readonly = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "quicksight:ListDataSets",
                        "quicksight:DescribeDataSet",
                        "quicksight:DescribeDataSetPermissions",
                        "quicksight:ListIngestions",
                        "quicksight:DescribeIngestion",
                    ],
                    "Resource": "*",
                }
            ],
        }
        self.iam.put_role_policy(
            RoleName=self.ROLE_NAME,
            PolicyName="QS-MigrationRead",
            PolicyDocument=json.dumps(readonly),
        )
        log.info("Inline policy QS-MigrationRead anexada a %s", self.ROLE_NAME)


# adicione à lista de exports do módulo
__all__ = [
    "ServiceRolePatch",
    "SecretsRolePatch",
    "MigrationRole",
    "OriginRoleSetup",
]
