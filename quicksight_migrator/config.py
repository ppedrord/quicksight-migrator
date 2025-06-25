"""quicksight_migrator/config.py – shared dataclasses & boto3 helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helper público ─ torna-se visível para importação em todo o pacote
# ─────────────────────────────────────────────────────────────────────────────


def make_boto_session(profile: Optional[str] = None) -> "boto3.session.Session":  # NEW
    """
    Cria uma `boto3` `Session` usando o *AWS profile* informado (ou as variáveis
    de ambiente/default, se `None`).

    Isto padroniza a criação de sessões em todo o pacote.
    """
    return boto3.session.Session(profile_name=profile)


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Account:
    """Representa uma conta AWS + role padrão usada na migração."""

    account_id: str
    role_name: str = "QS-MigrationDest"

    @property
    def role_arn(self) -> str:  # noqa: D401
        return f"arn:aws:iam::{self.account_id}:role/{self.role_name}"


@dataclass
class Config:
    """Configuração compartilhada entre todos os managers (IAM, DataSource etc.)."""

    # required
    region: str
    destination_account_id: Account
    datasource_id: str
    secret_arn: str
    vpc_connection_arn: str

    # optional
    profile: Optional[str] = None
    cleanup: bool = False
    assume_role: bool = False
    trust_principal: Optional[str] = None
    export_path: Optional[str] = None
    managed_policies: Optional[List[str]] = None
    group_arn: Optional[str] = None

    # injectable session factory (tests)
    session_factory: Callable[[Optional[str]], "boto3.session.Session"] = field(
        init=False, repr=False
    )

    # ── init helpers ──────────────────────────────────────────────
    def __post_init__(self) -> None:
        # usa o helper recém-criado
        self.session_factory = make_boto_session
        self._base_session = self.session_factory(self.profile)
        self._assumed_creds: Optional[dict] = None

    # ── convenient alias used by older code ───────────────────────
    @property
    def destination(self):  # noqa: D401
        """Alias retro-compatível para `destination_account_id`."""
        return self.destination_account_id

    # ── boto3 helpers ─────────────────────────────────────────────
    def _assume(self) -> Optional[dict]:
        if not self.assume_role:
            return None
        if self._assumed_creds is None:
            sts = self._base_session.client("sts", region_name=self.region)
            try:
                resp = sts.assume_role(
                    RoleArn=self.destination_account_id.role_arn,
                    RoleSessionName="qs-migration",
                )
                self._assumed_creds = resp["Credentials"]
                logger.debug("Assumed %s", self.destination_account_id.role_arn)
            except ClientError as e:
                if e.response["Error"].get("Code") == "AccessDenied":
                    logger.warning("AssumeRole denied – fallback to profile creds")
                else:
                    raise
        return self._assumed_creds

    def client(self, service: str):
        creds = self._assume()
        if creds:
            return boto3.client(
                service,
                region_name=self.region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        return self._base_session.client(service, region_name=self.region)

    def iam(self):
        return self._base_session.client("iam", region_name=self.region)

    def qs(self):
        return self.client("quicksight")

    def secrets(self):
        return self._base_session.client("secretsmanager", region_name=self.region)


# exporta também o novo helper
__all__ = ["Account", "Config", "make_boto_session"]
