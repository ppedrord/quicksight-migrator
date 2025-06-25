"""
Garante a existência de um grupo QS e adiciona o usuário atual.
"""

from __future__ import annotations
import logging
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


class GroupManager:
    """Garante a existência de um grupo QS e adiciona o usuário atual."""

    def __init__(self, cfg: "Config"):
        self.cfg = cfg
        self.qs = cfg.qs()  # usa perfil/assume-role já configurado
        self.account_id = cfg.destination.account_id

    # ---------- API pública ----------
    def ensure(self, name: str) -> str:
        """Retorna ARN do grupo; cria se não existir e adiciona o usuário."""
        try:
            arn = self._get_group_arn(name)
            if not arn:
                arn = self._create_group(name)
            self._add_current_user(name)
            log.debug("Group '%s' pronta", arn)
            return arn
        except Exception as e:
            log.error(e)
            raise

    # ---------- internos -------------
    def _get_group_arn(self, name: str) -> str | None:
        try:
            log.debug("Verificando grupo '%s'", name)
            grp = self.qs.describe_group(
                AwsAccountId=self.account_id, GroupName=name, Namespace="default"
            )["Group"]
            log.debug("Group '%s' já existe", name)
            return grp["Arn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    def _create_group(self, name: str) -> str:
        try:
            log.debug("Criando grupo '%s'", name)
            grp = self.qs.create_group(
                AwsAccountId=self.account_id,
                GroupName=name,
                Namespace="default",
                Description="QS migration group (auto)",
            )["Group"]
            log.debug("Group '%s' criado", name)
            return grp["Arn"]
        except Exception as e:
            log.error(e)
            raise

    def _add_current_user(self, name: str):
        iam = self.cfg.iam()
        user = iam.get_user()["User"]["Arn"]  # usuário do perfil ativo
        try:
            log.debug("Adicionando usuário %s ao grupo %s", user, name)
            self.qs.create_group_membership(
                MemberName=user.split(":")[5].split("/")[1],
                GroupName=name,
                AwsAccountId=self.account_id,
                Namespace="default",
            )
            log.debug("Usuário %s adicionado ao grupo %s", user, name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceExistsException":
                log.debug("Usuário já estava no grupo")
            else:
                raise
