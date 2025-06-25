"""datasets.py – Stage 2 · Replicação de Data Sets Direct Query."""

from __future__ import annotations

import logging
import re
import time
import json
from token import OP
from pathlib import Path
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from .config import Config

log = logging.getLogger(__name__)


class DataSetsManager:
    def __init__(self):
        pass

    # ────────────────────────────────────────────────────────────────────────────────
    # Helpers
    # ────────────────────────────────────────────────────────────────────────────────
    def _physical_tables_use_source_ds(
        self, physical_map: Dict, source_ds_arn: str
    ) -> bool:
        """True se qualquer PhysicalTable referir o DataSource da origem."""
        # aceita coincidência exata OU apenas pelo DataSourceId
        src_id = source_ds_arn.split("/")[-1]  # ex.: autoplan_db
        for pt in physical_map.values():
            arn = None
            if "RelationalTable" in pt:
                arn = pt["RelationalTable"].get("DataSourceArn")
            elif "CustomSql" in pt:
                arn = pt["CustomSql"].get("DataSourceArn")
            if arn:
                if arn == source_ds_arn or arn.split("/")[-1] == src_id:
                    return True
        return False

    def _swap_ds_arn(self, physical_map: Dict, new_ds_arn: str) -> Dict:
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
        self,
        qs_src,
        qs_dst,
        src_account_id: str,
        dst_account_id: str,
        target_ds_arn: str,
        group_arn: str,
        save_defs: Optional[bool] = False,
        defs_dir: Optional[str | Path] = None,
    ) -> List[str]:
        """
        Replica **todos** os Data Sets *DIRECT_QUERY* da conta origem, redirecionando
        cada *PhysicalTable* para ``target_ds_arn``.

        Retorna **uma lista** contendo os ARNs dos Data Sets replicados com sucesso.
        """
        log.debug("Listando Data Sets na conta de origem")
        paginator = qs_src.get_paginator("list_data_sets")
        dest_map: Dict[str, str] = {}
        total = 0

        for page in paginator.paginate(AwsAccountId=src_account_id):
            for summary in page.get("DataSetSummaries", []):
                ds_id = summary["DataSetId"]
                total += 1
                try:
                    describe_resp = qs_src.describe_data_set(
                        AwsAccountId=src_account_id, DataSetId=ds_id
                    )
                    ds = describe_resp["DataSet"]

                    # opcional: salva JSON bruto
                    if save_defs and defs_dir:
                        out = Path(defs_dir) / f"{ds_id}.json"
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_text(json.dumps(describe_resp, indent=2, default=str))

                    if ds["ImportMode"] != "DIRECT_QUERY":
                        log.debug(
                            "%s ignorado (ImportMode=%s)", ds_id, ds["ImportMode"]
                        )
                        continue

                    dest_arn = self._replicate_single(
                        ds, qs_dst, dst_account_id, target_ds_arn, group_arn
                    )
                    if dest_arn:
                        dest_map[ds_id] = dest_arn
                except ClientError as e:
                    log.warning("Falha ao processar %s: %s", ds_id, e)
                    continue

        log.debug("Encontrados %d Data Sets; replicados %d", total, len(dest_map))
        replicated_arns = list(dest_map.values())
        return replicated_arns

    # ---------------------------------------------------------------------------

    def _replicate_single(
        self,
        src_ds: dict,
        qs_dst,
        dst_account_id: str,
        target_ds_arn: str,
        group_arn: str,
    ) -> str | None:
        """Cria no destino um clone de *src_ds* apontando para *target_ds_arn*."""
        ds_id = src_ds["DataSetId"]

        # Se já existir no destino, devolve ARN existente
        try:
            dst_resp = qs_dst.describe_data_set(
                AwsAccountId=dst_account_id, DataSetId=ds_id
            )
            log.debug("%s já existe no destino → %s", ds_id, dst_resp["DataSet"]["Arn"])
            return dst_resp["DataSet"]["Arn"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

        payload = {
            "AwsAccountId": dst_account_id,
            "DataSetId": ds_id,
            "Name": src_ds["Name"],
            "ImportMode": "DIRECT_QUERY",
            "PhysicalTableMap": {},
            "LogicalTableMap": src_ds.get("LogicalTableMap", {}),
            "Permissions": [
                {
                    "Principal": group_arn,
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

        # log.debug(f"Payload: \n{json.dumps(payload, indent=2, default=str)}")

        # Substitui DataSourceArn em cada PhysicalTable
        for tbl_id, tbl in src_ds.get("PhysicalTableMap", {}).items():
            if "RelationalTable" in tbl:
                tbl["RelationalTable"]["DataSourceArn"] = target_ds_arn
            elif "CustomSql" in tbl:
                tbl["CustomSql"]["DataSourceArn"] = target_ds_arn
            payload["PhysicalTableMap"][tbl_id] = tbl

        # Campos opcionais
        for key in (
            "RowLevelPermissionDataSet",
            "ColumnLevelPermissionRules",
            "FieldFolders",
            "DataSetUsageConfiguration",
        ):
            if src_ds.get(key):
                payload[key] = src_ds[key]

        # Remove nulos que quebram a API
        payload = {k: v for k, v in payload.items() if v}
        try:
            payload.pop("RowLevelPermissionDataSet")
        except KeyError:
            pass

        # Cria no destino
        try:
            resp = qs_dst.create_data_set(**payload)
            dst_arn = resp["Arn"]
            log.debug("%s replicado → %s", ds_id, dst_arn)
            # Espera curta para propagação
            time.sleep(5)
            return dst_arn
        except ClientError as e:
            log.error("Erro ao criar %s: %s", ds_id, e)
            log.error("Payload: \n%s", json.dumps(payload, indent=2, default=str))
            return None
