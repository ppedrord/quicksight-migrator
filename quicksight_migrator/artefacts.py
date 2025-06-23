"""quicksight_migrator/artefacts.py
====================================

Utilitário para persistir/recuperar os ARNs gerados no estágio 0/1 (role + data source).
Suporta arquivo local, S3 e Parameter Store (SSM).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# Se boto3 não existir, só habilita local file.
try:
    import boto3
except ImportError:
    boto3 = None


@dataclass
class Artefacts:
    """Container tipado para os recursos criados no Stage 0/1."""

    role_arn: str
    datasource_arn: Optional[str] = None
    group_arn: Optional[str] = None

    @classmethod
    def load(cls, path: str | Path) -> "Artefacts":
        """Carrega de um arquivo local, S3 (s3://) ou SSM (ssm://)."""
        if isinstance(path, Path):
            path = str(path)
        if path.startswith("s3://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para leitura de S3")
            bucket, key = path[5:].split("/", 1)
            s3 = boto3.client("s3")
            resp = s3.get_object(Bucket=bucket, Key=key)
            data = json.load(resp["Body"])
            return cls(**data)
        elif path.startswith("ssm://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para leitura de SSM")
            param = path[6:]
            ssm = boto3.client("ssm")
            resp = ssm.get_parameter(Name=param, WithDecryption=True)
            data = json.loads(resp["Parameter"]["Value"])
            return cls(**data)
        else:
            with Path(path).expanduser().open("r", encoding="utf-8") as fh:
                data: Dict[str, Any] = json.load(fh)
            return cls(**data)

    def save(self, path: str | Path) -> None:
        """Salva o objeto em arquivo local, S3 (s3://) ou SSM (ssm://)."""
        payload = json.dumps(asdict(self), indent=2)
        if isinstance(path, Path):
            path = str(path)
        if path.startswith("s3://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para upload S3")
            bucket, key = path[5:].split("/", 1)
            boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=payload.encode())
        elif path.startswith("ssm://"):
            if not boto3:
                raise ImportError("boto3 não está instalado para gravação SSM")
            param = path[6:]
            boto3.client("ssm").put_parameter(
                Name=param, Value=payload, Type="String", Overwrite=True
            )
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with Path(path).expanduser().open("w", encoding="utf-8") as fh:
                fh.write(payload)

    def __str__(self) -> str:
        parts = [f"role → {self.role_arn}"]
        if self.datasource_arn:
            parts.append(f"datasource → {self.datasource_arn}")
        return ", ".join(parts)

    def update(self, **kwargs: str) -> None:
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
