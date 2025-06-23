"""quicksight_migrator/datasource.py
====================================

Aurora‑PostgreSQL Data Source manager encapsulated in a single class.  The
module is intentionally minimal — it fetches the secret, (re‑)creates the data
source if missing, and offers a cleanup helper for rollback scenarios.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from botocore.exceptions import ClientError

from .config import Config

logger = logging.getLogger(__name__)

__all__ = ["DataSourceManager"]


class DataSourceManager:
    """Ensure an Aurora PostgreSQL Data Source exists in QuickSight.

    Parameters
    ----------
    cfg : Config
        Global configuration object produced by *quicksight_migrator.config*.
    """

    TYPE = "AURORA_POSTGRESQL"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.qs = cfg.qs()
        self.arn: Optional[str] = None

    # ------------------------------------------------------------------
    # public helpers
    # ------------------------------------------------------------------

    def ensure(self) -> str:
        """Idempotently create (or fetch) the Data Source and return its ARN."""
        try:
            self.arn = self.qs.describe_data_source(
                AwsAccountId=self.cfg.destination.account_id,
                DataSourceId=self.cfg.datasource_id,
            )["DataSource"]["Arn"]
            logger.info("DataSource already present → %s", self.arn)
        except ClientError as exc:  # not found → create
            if exc.response["Error"].get("Code") != "ResourceNotFoundException":
                # raise
                logger.error(exc)
            try:
                secret = self._secret()
                logger.info("Secret parsed")
            except Exception as e:
                logger.error(e)
            try:
                params = self._build_params(secret)
                logger.info("DataSource params built")
            except Exception as e:
                logger.error(e)
            try:
                self.arn = self.qs.create_data_source(**params)["Arn"]
                logger.info("DataSource created → %s", self.arn)
            except Exception as e:
                logger.error(e)
        return self.arn

    def cleanup(self) -> None:
        """Delete the Data Source if it exists (best‑effort)."""
        try:
            self.qs.delete_data_source(
                AwsAccountId=self.cfg.destination.account_id,
                DataSourceId=self.cfg.datasource_id,
            )
            logger.info("DataSource %s removed", self.cfg.datasource_id)
        except ClientError as exc:
            if exc.response["Error"].get("Code") != "ResourceNotFoundException":
                raise

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _secret(self) -> dict:
        """Load and JSON‑decode the Aurora credentials secret."""
        sec_val = self.cfg.secrets().get_secret_value(SecretId=self.cfg.secret_arn)
        return json.loads(sec_val["SecretString"])

    def _build_params(self, s: dict) -> dict:
        """Translate secret + CLI flags into *create_data_source* parameters."""
        return {
            "AwsAccountId": self.cfg.destination.account_id,
            "DataSourceId": self.cfg.datasource_id,
            "Name": f"Aurora {s.get('dbname', 'postgres')}",
            "Type": self.TYPE,
            "DataSourceParameters": {
                "AuroraPostgreSqlParameters": {
                    "Host": s["host"],
                    "Port": int(s.get("port", 5432)),
                    "Database": s.get("dbname", "postgres"),
                }
            },
            "Credentials": {
                "CredentialPair": {"Username": s["username"], "Password": s["password"]}
            },
            "VpcConnectionProperties": {
                "VpcConnectionArn": self.cfg.vpc_connection_arn,
            },
            "SslProperties": {"DisableSsl": False},
            "Permissions": [
                {
                    # "Principal": self.cfg.destination.role_arn,
                    "Principal": self.cfg.group_arn,
                    "Actions": [
                        "quicksight:UpdateDataSourcePermissions",
                        "quicksight:DescribeDataSourcePermissions",
                        "quicksight:PassDataSource",
                        "quicksight:DescribeDataSource",
                        "quicksight:DeleteDataSource",
                        "quicksight:UpdateDataSource",
                    ],
                }
            ],
        }
