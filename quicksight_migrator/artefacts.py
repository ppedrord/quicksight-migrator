"""quicksight_migrator/artefacts.py – Persistência de ARNs e metadados

Pequeno *refactor* para corrigir bugs apontados no patch 1.

* Remove import inútil `from ast import List`.
* `load()` agora decodifica corretamente `StreamingBody` vindo do S3.
* Assinatura de `load()` passa a retornar `Optional[Artefacts]` (ou raise).
* `__str__` usa `destination_datasource_arn` (atributo atual).
"""

from __future__ import annotations

import json
import os
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    import boto3
except ImportError:  # tests / local
    boto3 = None  # type: ignore


@dataclass
class Artefacts:
    """Container tipado para os recursos criados no Stage 0/1."""

    destination_role_arn: Optional[str] = None
    destination_datasource_arn: Optional[str] = None
    group_arn: Optional[str] = None
    datasets_arns: Optional[list[str]] = None
    datasets_defs_path: Optional[str] = None

    # ------------------------------------------------------------------
    # compat
    # ------------------------------------------------------------------
    def __post_init__(self):
        # migra versões antigas (datasource_arn -> destination_datasource_arn)
        legacy = getattr(self, "datasource_arn", None)
        if legacy and not self.destination_datasource_arn:
            self.destination_datasource_arn = legacy

    # ------------------------------------------------------------------
    # load/save helpers
    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> Optional["Artefacts"]:
        """Carrega de arquivo local, S3 (``s3://``) ou SSM (``ssm://``)."""
        path = str(path) if isinstance(path, Path) else path

        # S3
        if path.startswith("s3://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para leitura de S3")
            bucket, key = path[5:].split("/", 1)
            body = boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
            data: Dict[str, Any] = json.loads(body.decode())
            return cls(**data)

        # SSM Parameter Store
        if path.startswith("ssm://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para leitura de SSM")
            param = path[6:]
            raw = boto3.client("ssm").get_parameter(Name=param, WithDecryption=True)
            data: Dict[str, Any] = json.loads(raw["Parameter"]["Value"])
            return cls(**data)

        # Arquivo local
        try:
            with Path(path).expanduser().open("r", encoding="utf-8") as fh:
                data: Dict[str, Any] = json.load(fh)
            return cls(**data)
        except FileNotFoundError:
            log.error("Artefacts file not found: %s", path)
            return None

    def save(self, path: str | Path) -> None:
        """Salva em arquivo local, S3 (``s3://``) ou SSM (``ssm://``)."""
        payload = json.dumps(asdict(self), indent=2)
        path = str(path) if isinstance(path, Path) else path

        if path.startswith("s3://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para upload S3")
            bucket, key = path[5:].split("/", 1)
            boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=payload.encode())
            return

        if path.startswith("ssm://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para gravação SSM")
            param = path[6:]
            boto3.client("ssm").put_parameter(
                Name=param, Value=payload, Type="String", Overwrite=True
            )
            return

        # local file
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        with Path(path).expanduser().open("w", encoding="utf-8") as fh:
            fh.write(payload)

    # ------------------------------------------------------------------
    # dunder helpers
    # ------------------------------------------------------------------
    def __str__(self) -> str:  # pragma: no cover – purely cosmetic
        parts = [f"role → {self.destination_role_arn}"]
        if self.destination_datasource_arn:
            parts.append(f"datasource → {self.destination_datasource_arn}")
        return ", ".join(filter(None, parts))

    # ------------------------------------------------------------------
    # convenience
    # ------------------------------------------------------------------
    def update(self, **kwargs: str) -> None:
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
