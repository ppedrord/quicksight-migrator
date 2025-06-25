# quicksight‑migrator

> Zero‑downtime migration of Amazon QuickSight _direct‑query_ assets between AWS accounts.

[![PyPI](https://img.shields.io/pypi/v/quicksight-migrator.svg)](https://pypi.org/project/quicksight-migrator)
[![Python](https://img.shields.io/pypi/pyversions/quicksight-migrator.svg)](https://python.org)
[![License](https://img.shields.io/github/license/yourorg/quicksight-migrator.svg)](LICENSE)

`quicksight-migrator` automates every step involved in cloning an **Aurora‑PostgreSQL** data source and any **DIRECT_QUERY** datasets that depend on it, from a _source_ account to a _destination_ account, while keeping permissions intact.

The workflow is fully idempotent (safe to re‑run) and supports complete rollback.

---

## Features

- **Stage 0 / 1 – Foundation**

  - Creates the temporary IAM role **`QS‑MigrationDest`** in the _destination_ account and registers it as a QuickSight _ADMIN_ user.
  - Patches the managed roles `aws‑quicksight‑service‑role‑v0` and `aws‑quicksight‑secretsmanager‑role‑v0` so that QuickSight can read the target database secret.
  - Ensures a QuickSight **group** (defaults to `Admins`) and adds the current caller to it.
  - (Re‑)creates an **Aurora PostgreSQL** data source pointing to the provided RDS/Aurora cluster & VPC connection.

- **Stage 2 – Dataset replication**

  - Provision the role **`QS‑MigrationOrigin`** in the _source_ account with read‑only QuickSight permissions.
  - Iterates over every **`DIRECT_QUERY`** DataSet that uses the original data source, replicating it in the _destination_ account while transparently **swapping the `DataSourceArn`** to the one created in Stage 0/1.
  - Optionally exports the raw JSON definition of each DataSet for audit or GitOps purposes.

- **Rollback helpers** for both stages (IAM, DataSource, DataSets).

- Clean, minimal **Python API** with programmatic equivalents of the CLI commands.

---

## Requirements

- **Python 3.9+**
- AWS credentials with permission to create IAM roles, VPC connections, QuickSight resources, and read the database secret.
- The destination QuickSight account must be in “Enterprise” or “Standard (reader)” edition with **Enterprise features** enabled.

See `requirements.txt` for pinned versions.

---

## Installation

```bash
pip install quicksight-migrator
```

---

## Quickstart (CLI)

```bash
# 1) Stage 0/1 – run from the *destination* profile
quicksight-migrator ensure \
    --region us-east-1 \
    --destination-account-id 123456789012 \
    --ds-id autoplan_db \
    --secret-arn arn:aws:secretsmanager:us-east-1:123456789012:secret:AuroraV2DBCredentials-xxxx \
    --vpc-connection-arn arn:aws:quicksight:us-east-1:123456789012:vpcConnection/367359c6-ede2-4122-b295-d94dd651930c \
    --export-path artefacts.json \
    --profile dest-profile

# 2) Stage 2 – replicate datasets (run from *either* profile)
quicksight-migrator replicate-datasets \
    --region us-east-1 \
    --source-account-id 111122223333 \
    --artefacts artefacts.json \
    --profile dest-profile   # optional

# 3) Optional rollback
quicksight-migrator cleanup \
    --region us-east-1 \
    --artefacts artefacts.json \
    --profile dest-profile
```

The **`artefacts.json`** file keeps track of every ARN created by the tool so that subsequent steps know what to use and rollbacks know what to delete.
You can store it on S3 (`s3://bucket/key.json`) or SSM (`ssm://parameter/name`) and the library will read/write it transparently.

---

## Python API

```python
from pathlib import Path
from quicksight_migrator import (
    create_destination_datasource,
    replicate_datasets,
    cleanup_destination_datasource,
)

# Stage 0/1
artefacts = create_destination_datasource(
    region="us-east-1",
    destination_account_id="123456789012",
    ds_id="autoplan_db",
    secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:AuroraV2DBCredentials-xxxx",
    vpc_connection_arn="arn:aws:quicksight:us-east-1:123456789012:vpcConnection/367359c6-ede2-4122-b295-d94dd651930c",
    export_path=Path("artefacts.json"),
)

# Stage 2
datasets = replicate_datasets(
    region="us-east-1",
    source_account_id="111122223333",
    artefacts_path="artefacts.json",
    save_definitions=True,           # dumps JSON specs into artefacts/datasets/
)

print(f"Replicated: {datasets}")

# Rollback
cleanup_destination_datasource(
    region="us-east-1",
    profile=None,
    artefacts_path="artefacts.json",
)
```

---

## IAM roles & permissions

| Role                                      | Account     | Purpose                                                                                              |
| ----------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------- |
| **QS‑MigrationDest**                      | destination | Assumed by the script to create QuickSight & IAM resources. Registered as a QuickSight _ADMIN_ user. |
| **QS‑MigrationOrigin**                    | source      | Read‑only QuickSight role that the destination account assumes to list/describe datasets.            |
| **aws‑quicksight‑service‑role‑v0**        | destination | Patched with an inline policy allowing access to the RDS secret.                                     |
| **aws‑quicksight‑secretsmanager‑role‑v0** | destination | Created/patched so that QuickSight can decrypt the database secret.                                  |

You may provide **`--managed-policies`** when calling `ensure` to attach additional AWS‑managed policies to `QS‑MigrationDest` (e.g. `arn:aws:iam::aws:policy/AmazonQuickSightFullAccess`).

---

## Artefacts file reference

```jsonc
{
  "destination_role_arn": "arn:aws:iam::123456789012:role/QS-MigrationDest",
  "destination_datasource_arn": "arn:aws:quicksight:us-east-1:123456789012:datasource/autoplan_db",
  "group_arn": "arn:aws:quicksight:us-east-1:123456789012:group/default/Admins",
  "datasets_arns": [
    "arn:aws:quicksight:us-east-1:123456789012:dataset/abcd1234-..."
  ],
  "datasets_defs_path": "artefacts/datasets"
}
```

---

## Logging

Set the environment variable `LOG_LEVEL` to `DEBUG` for verbose output:

```bash
export LOG_LEVEL=DEBUG
```

---

## Development

```bash
git clone https://github.com/yourorg/quicksight-migrator.git
cd quicksight-migrator
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'      # installs requirements + test extras
pytest -q
```

Pre‑commit hooks and black formatting are enforced.

---

## Troubleshooting

| Symptom                                                                | Cause                                                                               | Fix                                                                                          |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `AccessDeniedException` when the script calls `create_data_source`     | The IAM roles were not registered as QuickSight users                               | Re‑run **Stage 0/1** or open QuickSight console → _Manage users_ and add `QS‑MigrationDest`. |
| `InvalidParameterValueException: calculated columns [...] are invalid` | Some DataSets contain calculated fields incompatible with the destination DB schema | Review the JSON definition exported with `--save-defs` and adjust the target database.       |
| `NoCredentialsError: Unable to locate credentials`                     | AWS credentials/profile not picked up                                               | Set `AWS_PROFILE` or `AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY`.                            |

---

## Roadmap

- Dashboards & analyses replication
- Glue / Athena data sources
- CloudFormation wrapper for CI/CD pipelines

Feel free to open issues or pull requests!

---

## License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

_Not affiliated with Amazon Web Services. “Amazon QuickSight” is a trademark of Amazon.com, Inc. or its affiliates._
