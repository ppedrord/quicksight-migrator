"""datasets.py – Stage 2 · Replicação de Data Sets Direct Query."""

from __future__ import annotations

import logging
import re
import time
from typing import Dict, List, Tuple

from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────────
def _physical_tables_use_source_ds(physical_map: Dict, source_ds_arn: str) -> bool:
    """True se qualquer PhysicalTable referir o DataSource da origem."""
    for pt in physical_map.values():
        if "RelationalTable" in pt:
            if pt["RelationalTable"].get("DataSourceArn") == source_ds_arn:
                return True
        elif "CustomSql" in pt:
            if pt["CustomSql"].get("DataSourceArn") == source_ds_arn:
                return True
    return False


def _swap_ds_arn(physical_map: Dict, new_ds_arn: str) -> Dict:
    """Clona o PhysicalTableMap trocando o DataSourceArn."""
    clone = {}
    for k, v in physical_map.items():
        pt = json.loads(json.dumps(v))  # deep-copy via JSON
        if "RelationalTable" in pt:
            pt["RelationalTable"]["DataSourceArn"] = new_ds_arn
        elif "CustomSql" in pt:
            pt["CustomSql"]["DataSourceArn"] = new_ds_arn
        clone[k] = pt
    return clone


# ────────────────────────────────────────────────────────────────────────────────
# Público
# ────────────────────────────────────────────────────────────────────────────────
def replicate_all_datasets(
    qs_src,
    qs_dst,
    src_account_id: str,
    dst_account_id: str,
    src_ds_arn: str,
    dst_ds_arn: str,
    principal_arn: str,
) -> Dict[str, str]:
    """
    Replica todos os Data Sets DIRECT_QUERY que usem *src_ds_arn*.

    Retorna `{DataSetId: DestDataSetArn}` para sucesso; falhas ficam ausentes.
    """
    mapping: Dict[str, str] = {}
    paginator = qs_src.get_paginator("list_data_sets")

    for page in paginator.paginate(AwsAccountId=src_account_id):
        for summary in page.get("DataSetSummaries", []):
            ds_id = summary["DataSetId"]

            # 1 – describe na origem
            try:
                src_ds = qs_src.describe_data_set(
                    AwsAccountId=src_account_id, DataSetId=ds_id
                )["DataSet"]
            except ClientError as e:
                log.warning("describe_data_set falhou p/ %s: %s", ds_id, e)
                continue

            if src_ds["ImportMode"] != "DIRECT_QUERY":
                continue
            if not _physical_tables_use_source_ds(
                src_ds["PhysicalTableMap"], src_ds_arn
            ):
                continue  # não relacionado ao DS de origem

            # 2 – verifica existência no destino
            try:
                dst_ds = qs_dst.describe_data_set(
                    AwsAccountId=dst_account_id, DataSetId=ds_id
                )["DataSet"]
                mapping[ds_id] = dst_ds["Arn"]
                log.info("DataSet %s já existe em %s – pulando", ds_id, dst_account_id)
                continue
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    log.error(
                        "Erro inesperado ao descrever DS %s no destino: %s", ds_id, e
                    )
                    continue  # parte para o próximo
                # não existe → cria

            # 3 – prepara payload
            payload = {
                "AwsAccountId": dst_account_id,
                "DataSetId": ds_id,
                "Name": src_ds["Name"],
                "ImportMode": "DIRECT_QUERY",
                "PhysicalTableMap": _swap_ds_arn(
                    src_ds["PhysicalTableMap"], dst_ds_arn
                ),
                "LogicalTableMap": src_ds.get("LogicalTableMap", {}),
                "Permissions": [
                    {
                        "Principal": principal_arn,
                        "Actions": [
                            "quicksight:DescribeDataSet",
                            "quicksight:DescribeDataSetPermissions",
                            "quicksight:PassDataSet",
                            "quicksight:DescribeIngestion",
                            "quicksight:ListIngestions",
                            "quicksight:UpdateDataSet",
                            "quicksight:DeleteDataSet",
                            "quicksight:CreateIngestion",
                            "quicksight:CancelIngestion",
                            "quicksight:UpdateDataSetPermissions",
                        ],
                    }
                ],
            }
            # copia opcionais se existirem
            for key in (
                "RowLevelPermissionDataSet",
                "ColumnLevelPermissionRules",
                "DataSetUsageConfiguration",
                "FieldFolders",
                "ColumnGroups",
            ):
                if src_ds.get(key):
                    payload[key] = src_ds[key]

            # 4 – create
            try:
                resp = qs_dst.create_data_set(**payload)
                mapping[ds_id] = resp["Arn"]
                log.info("→ DataSet %s replicado (%s)", ds_id, resp["Arn"])
                time.sleep(2)  # leve espera para propagação
            except ClientError as e:
                log.error("Falha ao criar DataSet %s: %s", ds_id, e)

    return mapping
