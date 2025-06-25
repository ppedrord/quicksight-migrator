"""quicksight_migrator/cli.py – orchestration helpers

Esta revisão integra os *fixes* apontados no *code-review* anterior:

* `replicate_datasets` agora devolve **List[str]** (ARNs) em vez de `dict`.
* Carrega o *artefacts* **antes** para descobrir `dest_role_arn`/`dest_ds_arn`
  quando não forem passados por parâmetro.
* Cria um artefacts vazio caso o arquivo ainda não exista.
* Usa `_assume_client` para operar no IAM da conta destino, evitando
  `NoCredentialsError`.
* Corrige os *logs* de identidade, removendo `qs.get_caller_identity()` que
  não existe na API do QuickSight.
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
from botocore.exceptions import ClientError, NoCredentialsError

from .groups import GroupManager
from .artefacts import Artefacts
from .config import Account, Config as QSConfig, make_boto_session
from .datasets import DataSetsManager
from .iam_roles import (
    MigrationRole,
    SecretsRolePatch,
    ServiceRolePatch,
    OriginRoleSetup,
)
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
    pre_role_arn: str | None = None,
):
    """Assume *role_arn* (optionally via *pre_role_arn*) and return a boto3 client."""
    base = boto3.Session(profile_name=profile, region_name=region)

    # 1st hop (optional)
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

    # 2nd hop – final destination
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


# ───────────────────────── Stage 0/1 ─────────────────────────


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
    """Cria *QS-MigrationDest*, aplica patches e provisiona o Data Source."""

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

    # Stage 0 – IAM
    MigrationRole(cfg).ensure()
    ServiceRolePatch(cfg).ensure()
    SecretsRolePatch(cfg).ensure()

    # 0.1 – garante grupo
    grp_mgr = GroupManager(cfg)
    group_arn = grp_mgr.ensure(group_name)
    cfg.group_arn = group_arn

    # Stage 1 – Data Source
    datasource_arn = DataSourceManager(cfg).ensure()

    artefacts = Artefacts(
        destination_role_arn=cfg.destination_account_id.role_arn,
        destination_datasource_arn=datasource_arn,
        group_arn=group_arn,
    )
    artefacts.save(export_path)
    log.debug("Artefacts salvos em %s", export_path)
    return artefacts


def cleanup_destination_datasource(
    *, region: str, profile: Optional[str], artefacts_path: str | Path
):
    """Rollback total das fases 0/1 com base nos artefacts."""

    arts = Artefacts.load(artefacts_path)
    if not arts or not arts.destination_role_arn:
        raise ValueError("Artefacts não contém destination_role_arn")

    dest = Account(arts.destination_role_arn.split(":")[4])
    cfg = QSConfig(
        region=region,
        destination_account_id=dest,
        datasource_id=os.path.basename(arts.destination_datasource_arn or "unknown"),
        secret_arn="",
        vpc_connection_arn="",
        profile=profile,
    )

    DataSourceManager(cfg).cleanup()
    ServiceRolePatch(cfg).cleanup()
    SecretsRolePatch(cfg).cleanup()
    MigrationRole(cfg).cleanup()
    log.debug("Stage 0/1 limpo com sucesso")


# ───────────────────────── Stage 2 ─────────────────────────


def replicate_datasets(
    *,
    region: str,
    source_account_id: str,
    artefacts_path: str | Path,
    # optional overrides
    source_role_arn: Optional[str] = None,
    source_ds_arn: Optional[str] = None,
    dest_ds_arn: Optional[str] = None,
    dest_role_arn: Optional[str] = None,
    source_profile: Optional[str] = None,
    dest_profile: Optional[str] = None,
    save_definitions: bool = False,
    group_arn: Optional[str] = None,
    defs_output_dir: str | Path = "artefacts/datasets",
) -> List[str]:
    """Replica todos os DataSets *DIRECT_QUERY* que utilizam **source_ds_arn**.

    O DataSource de destino é obtido dos *artefacts* (ou do parâmetro
    `dest_ds_arn`).  Retorna **lista** de ARNs dos DataSets criados.
    """

    # ------------------------------------------------------------------
    # Artefacts (pode estar vazio se for primeira execução do pipeline)
    # ------------------------------------------------------------------
    arts = Artefacts.load(artefacts_path)
    if arts is None:
        log.warning(
            "Artefacts não encontrado em %s – criando arquivo vazio", artefacts_path
        )
        arts = Artefacts()
        arts.save(artefacts_path)

    # ------------------------------------------------------------------
    # Resolver ARNs de destino (role + datasource)
    # ------------------------------------------------------------------
    dest_role_arn = dest_role_arn or arts.destination_role_arn
    if not dest_role_arn:
        raise ValueError(
            "destination_role_arn ausente – informe via parâmetro ou artefacts"
        )
    dest_account_id = dest_role_arn.split(":")[4]

    dest_ds_arn = dest_ds_arn or arts.destination_datasource_arn
    if not dest_ds_arn:
        raise ValueError(
            "destination_datasource_arn ausente – informe via parâmetro ou artefacts"
        )

    # ------------------------------------------------------------------
    # Role de origem (provisória) – QS-MigrationOrigin
    # ------------------------------------------------------------------
    origin_role_arn = (
        source_role_arn or f"arn:aws:iam::{source_account_id}:role/QS-MigrationOrigin"
    )
    origin_sess = (
        boto3.Session(profile_name=source_profile)
        if source_profile
        else boto3.Session()
    )
    OriginRoleSetup(session=origin_sess, dest_role_arn=dest_role_arn).ensure()

    # ------------------------------------------------------------------
    # Dest role precisa assumir a origin role – garante policy inline
    # ------------------------------------------------------------------
    iam_dest = _assume_client(
        "iam", dest_role_arn, "IamDest", region=region, profile=dest_profile
    )
    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": origin_role_arn}
        ],
    }
    dest_role_name = dest_role_arn.split("/")[-1]
    log.debug("Anexando policy inline %s", dest_role_name)
    try:
        iam_dest.put_role_policy(
            RoleName=dest_role_name,
            PolicyName="AllowAssumeOriginRole",
            PolicyDocument=json.dumps(assume_policy),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "AccessDenied":
            raise
        log.warning(
            "Não foi possível anexar policy à role destino – verifique permissões"
        )

    # ------------------------------------------------------------------
    # QuickSight clients (source & destination)
    # ------------------------------------------------------------------
    qs_src = _assume_client(
        "quicksight",
        origin_role_arn,
        "QSOrig",
        region=region,
        profile=dest_profile,
        pre_role_arn=dest_role_arn,
    )
    qs_dst = _assume_client(
        "quicksight", dest_role_arn, "QSDest", region=region, profile=dest_profile
    )

    # ------------------------------------------------------------------
    # Replicar DataSets
    # ------------------------------------------------------------------
    if group_arn:
        group_arn = group_arn
    else:
        group_arn = arts.group_arn
    datasets_arns = DataSetsManager().replicate_all_datasets(
        qs_src,
        qs_dst,
        src_account_id=source_account_id,
        dst_account_id=dest_account_id,
        target_ds_arn=dest_ds_arn,
        group_arn=group_arn,
        save_defs=save_definitions,
        defs_dir=defs_output_dir,
    )
    log.debug("DataSets replicados: %s", json.dumps(datasets_arns, indent=2))

    # ------------------------------------------------------------------
    # Persist artefacts
    # ------------------------------------------------------------------
    if datasets_arns:
        arts.datasets_arns = datasets_arns
        if save_definitions:
            arts.datasets_defs_path = str(defs_output_dir)
        arts.save(artefacts_path)
        log.debug("Artefacts atualizados em %s", artefacts_path)

    return datasets_arns


def cleanup_datasets(
    *,
    region: str,
    artefacts_path: str | Path,
    profile: Optional[str] = None,
    dest_role_arn: Optional[str] = None,
    delete_definitions: bool = False,
) -> None:
    """Remove todos os DataSets listados em *artefacts* (Stage 2 rollback)."""

    arts = Artefacts.load(artefacts_path)
    if not arts or not arts.datasets_arns:
        log.debug("Nenhum DataSet registrado em artefacts – nada a fazer")
        return

    # ---------------- QuickSight client ----------------
    if dest_role_arn:
        qs = _assume_client("quicksight", dest_role_arn, "QSCleanup", region=region)
        account_id = dest_role_arn.split(":")[4]
    else:
        sess = make_boto_session(profile)
        qs = sess.client("quicksight", region_name=region)
        account_id = sess.client("sts", region_name=region).get_caller_identity()[
            "Account"
        ]

    # ---------------- delete ---------------------------
    removed, errors = [], []
    for ds_arn in arts.datasets_arns:
        ds_id = ds_arn.rsplit("/", 1)[-1]
        try:
            qs.delete_data_set(AwsAccountId=account_id, DataSetId=ds_id)
            removed.append(ds_id)
            log.debug("DataSet %s removido", ds_id)
        except Exception as e:
            errors.append((ds_id, str(e)))
            log.error("Falha ao remover %s: %s", ds_id, e)

    # ---------------- optional JSON defs ---------------
    if delete_definitions and arts.datasets_defs_path:
        defs_dir = Path(arts.datasets_defs_path)
        for f in defs_dir.glob("*.json"):
            try:
                f.unlink()
            except OSError:
                log.warning("Não consegui deletar %s", f)

    # ---------------- update artefacts -----------------
    arts.datasets_arns = [a for a, _ in errors] if errors else None
    if delete_definitions:
        arts.datasets_defs_path = None
    arts.save(artefacts_path)

    # ---------------- resumo ---------------------------
    if removed:
        log.debug("Cleanup Stage 2 concluído – %d DataSets removidos", len(removed))
    if errors:
        log.warning("Alguns DataSets não puderam ser removidos: %s", errors)


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
    rep.add_argument("--artefacts", required=True)
    rep.add_argument("--source-role-arn")
    rep.add_argument("--source-ds-arn")
    rep.add_argument("--dest-role-arn")
    rep.add_argument("--dest-ds-arn")
    rep.add_argument("--save-defs", action="store_true")

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
            artefacts_path=args.artefacts,
            source_role_arn=args.source_role_arn,
            source_ds_arn=args.source_ds_arn,
            dest_role_arn=args.dest_role_arn,
            dest_ds_arn=args.dest_ds_arn,
            save_definitions=args.save_defs,
        )


__all__ = [
    "create_destination_datasource",
    "cleanup_destination_datasource",
    "replicate_datasets",
    "cleanup_datasets",
]
