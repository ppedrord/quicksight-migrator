"""quicksight_migrator/cli.py – library‑first API
===================================================
A camada de *orquestração* agora está 100 % voltada a **uso programático**
(com um CLI opcional para retro‑compatibilidade).  As três fases expõem
funções simples:

```python
from quicksight_migrator.cli import (
    create_destination_datasource,   # Stage 0/1 – cria roles + Data Source
    cleanup_destination_datasource,  # Stage 0/1 – rollback
    replicate_datasets,              # Stage 2   – copia Data Sets Direct‑Query
)
```

---
Esta revisão corrige os *AttributeError* observados:

* converte automaticamente `destination_account_id: str` → `Account`;
* garante que `Config` continua dispondo do alias `.destination`;
* aceita `source_ds_arn` em `replicate_datasets` (indispensável para filtrar
  os Data Sets na origem);
* mantém compatibilidade com chamadas anteriores e com o CLI.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import List, Optional

import boto3
from botocore.config import Config as BotoConfig

from .groups import GroupManager
from .artefacts import Artefacts
from .config import Account, Config as QSConfig
from .datasets import replicate_all_datasets
from .iam_roles import MigrationRole, SecretsRolePatch, ServiceRolePatch
from .datasource import DataSourceManager

log = logging.getLogger("quicksight_migrator")

# ───────────────────────── helpers ─────────────────────────


def _boto3_client(service: str, profile: Optional[str] = None, *, region: str):
    sess = boto3.session.Session(profile_name=profile) if profile else boto3
    return sess.client(
        service, region_name=region, config=BotoConfig(retries={"max_attempts": 10})
    )


def _assume_client(
    service: str,
    role_arn: str,
    session_name: str,
    *,
    region: str,
    profile: str | None = None,
    pre_role_arn: str | None = None,  # NOVO
):
    """
    Devolve boto3.client já autenticado na role_arn.
    Se `pre_role_arn` for fornecido, assume essa role primeiro.
    """
    base = boto3.Session(profile_name=profile, region_name=region)

    # 1º salto (opcional)
    if pre_role_arn:
        cred1 = base.client("sts").assume_role(
            RoleArn=pre_role_arn, RoleSessionName=session_name + "_1"
        )["Credentials"]
        base = boto3.Session(
            aws_access_key_id=cred1["AccessKeyId"],
            aws_secret_access_key=cred1["SecretAccessKey"],
            aws_session_token=cred1["SessionToken"],
            region_name=region,
        )

    # 2º salto – destino final
    cred2 = base.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )["Credentials"]

    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=cred2["AccessKeyId"],
        aws_secret_access_key=cred2["SecretAccessKey"],
        aws_session_token=cred2["SessionToken"],
    )


# ───────────────────────── Stage 0/1 ─────────────────────────


def create_destination_datasource(
    *,
    region: str,
    destination_account_id: str,
    ds_id: str,
    secret_arn: str,
    vpc_connection_arn: str,
    profile: Optional[str] = None,
    export_path: str | Path,
    managed_policies: Optional[List[str]] = None,
    trust_principal: Optional[str] = None,
    group_name: Optional[str] = "Admins",
) -> Artefacts:
    """Cria *QS‑MigrationDest*, aplica patches e provisiona o Data Source."""

    dest = Account(destination_account_id)
    cfg = QSConfig(
        region=region,
        destination_account_id=dest,
        datasource_id=ds_id,
        secret_arn=secret_arn,
        vpc_connection_arn=vpc_connection_arn,
        profile=profile,
        managed_policies=managed_policies or [],
        trust_principal=trust_principal,
    )

    # Stage 0 – IAM
    MigrationRole(cfg).ensure()
    ServiceRolePatch(cfg).ensure()
    SecretsRolePatch(cfg).ensure()

    # 0.1 – garante group
    grp_mgr = GroupManager(cfg)
    group_arn = grp_mgr.ensure(group_name)
    cfg.group_arn = group_arn

    # Stage 1 – Data Source
    datasource_arn = DataSourceManager(cfg).ensure()

    artefacts = Artefacts(
        role_arn=cfg.destination_account_id.role_arn,
        datasource_arn=datasource_arn,
        group_arn=group_arn,
    )
    artefacts.save(export_path)
    log.info("Artefacts salvos em %s", export_path)
    return artefacts


def cleanup_destination_datasource(
    *, region: str, profile: Optional[str], artefacts_path: str | Path
):
    """Rollback total das fases 0/1 com base no artefacts."""

    arts = Artefacts.load(artefacts_path)
    dest = Account(arts.role_arn.split(":")[4])  # extrai account‑id

    cfg = QSConfig(
        region=region,
        destination_account_id=dest,
        datasource_id=os.path.basename(arts.datasource_arn or "unknown"),
        secret_arn="",
        vpc_connection_arn="",
        profile=profile,
    )

    DataSourceManager(cfg).cleanup()
    ServiceRolePatch(cfg).cleanup()
    SecretsRolePatch(cfg).cleanup()
    MigrationRole(cfg).cleanup()
    log.info("Stage 0/1 limpo com sucesso")


# ───────────────────────── Stage 2 ─────────────────────────


def replicate_datasets(
    *,
    region: str,
    source_account_id: str,
    source_role_arn: str,
    source_ds_arn: str,
    artefacts_path: str | Path,
    source_profile: Optional[
        str
    ] = None,  # caso queira usar profile em vez de AssumeRole
) -> dict[str, str]:
    """Replica todos os Data Sets *DIRECT_QUERY* que usam **source_ds_arn**.

    Retorna um mapeamento `{DataSetId: DestArn}` das criações bem‑sucedidas.
    """
    arts = Artefacts.load(artefacts_path)
    dest_account_id = arts.role_arn.split(":")[4]

    qs_src = _assume_client(
        "quicksight",
        role_arn=source_role_arn,  # QS-MigrationOrigin
        pre_role_arn=arts.role_arn,  # QS-MigrationDest (salvo nos artefatos)
        session_name="QSOrig",
        region=region,
        profile=source_profile,  # perfil local que tem acesso à conta destino
    )
    qs_dst = _boto3_client("quicksight", profile=None, region=region)

    mapping = replicate_all_datasets(
        qs_src,
        qs_dst,
        src_account_id=source_account_id,
        dst_account_id=dest_account_id,
        src_ds_arn=source_ds_arn,
        dst_ds_arn=arts.datasource_arn,
        principal_arn=arts.role_arn,
    )
    log.info("DataSets replicados: %s", json.dumps(mapping, indent=2))
    return mapping


# ───────────────────────── CLI opcional ─────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("quicksight_migrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ensure
    ens = sub.add_parser("ensure")
    ens.add_argument("--region", required=True)
    ens.add_argument("--destination-account-id", required=True)
    ens.add_argument("--ds-id", required=True)
    ens.add_argument("--secret-arn", required=True)
    ens.add_argument("--vpc-connection-arn", required=True)
    ens.add_argument("--export-path", required=True)
    ens.add_argument("--profile")

    # cleanup
    cln = sub.add_parser("cleanup")
    cln.add_argument("--region", required=True)
    cln.add_argument("--artefacts", required=True)
    cln.add_argument("--profile")

    # replicate
    rep = sub.add_parser("replicate-datasets")
    rep.add_argument("--region", required=True)
    rep.add_argument("--source-account-id", required=True)
    rep.add_argument("--source-role-arn", required=True)
    rep.add_argument("--source-ds-arn", required=True)
    rep.add_argument("--artefacts", required=True)

    return p


def main(argv: Optional[List[str]] = None):  # noqa: D401
    args = _build_parser().parse_args(argv)

    if args.cmd == "ensure":
        create_destination_datasource(
            region=args.region,
            destination_account_id=args.destination_account_id,
            ds_id=args.ds_id,
            secret_arn=args.secret_arn,
            vpc_connection_arn=args.vpc_connection_arn,
            profile=args.profile,
            export_path=args.export_path,
        )
    elif args.cmd == "cleanup":
        cleanup_destination_datasource(
            region=args.region, profile=args.profile, artefacts_path=args.artefacts
        )
    elif args.cmd == "replicate-datasets":
        replicate_datasets(
            region=args.region,
            source_account_id=args.source_account_id,
            source_role_arn=args.source_role_arn,
            source_ds_arn=args.source_ds_arn,
            artefacts_path=args.artefacts,
        )


# .............................................................................
__all__ = [
    "create_destination_datasource",
    "cleanup_destination_datasource",
    "replicate_datasets",
]
