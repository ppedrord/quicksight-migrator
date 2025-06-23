# QuickSight Migrator

[![PyPI](https://img.shields.io/pypi/v/quicksight-migrator.svg)](https://pypi.org/project/quicksight-migrator/)

Automates the setup of QuickSight roles and Data Sources across AWS accounts and helps replicate existing Direct Query datasets. The package can be used programmatically or via a small command line interface.

---

## Features

* **Stage 0/1 – IAM & Data Source**
  - Creates the temporary **QS-MigrationDest** role in the destination account.
  - Patches the default QuickSight service roles so the service can read your Secrets Manager secret.
  - Ensures the Secrets Manager execution role.
  - Creates an Aurora PostgreSQL Data Source and stores the generated ARNs.
  - Optionally ensures a QuickSight group (defaults to `Admins`).
* **Stage 2 – Data Set replication**
  - Copies all Direct Query Data Sets that rely on the source Data Source.

---

## Installation

```bash
pip install quicksight-migrator
```

The package requires Python 3.8+ and `boto3`.

---

## Quickstart

1. **Bootstrap destination account**

   ```bash
   quicksight-migrator ensure \
       --region us-east-1 \
       --destination-account-id 123456789012 \
       --ds-id aurora_ds \
       --secret-arn arn:aws:secretsmanager:us-east-1:123456789012:secret:MySecret \
       --vpc-connection-arn arn:aws:quicksight:us-east-1:123456789012:vpcConnection/abc123 \
       --export-path artefacts.json
   ```

2. **Replicate DataSets from another account**

   ```bash
   quicksight-migrator replicate-datasets \
       --region us-east-1 \
       --source-account-id 111111111111 \
       --source-role-arn arn:aws:iam::111111111111:role/QS-MigrationOrigin \
       --source-ds-arn arn:aws:quicksight:us-east-1:111111111111:datasource/xyz987 \
       --artefacts artefacts.json
   ```

3. **Cleanup**

   ```bash
   quicksight-migrator cleanup --region us-east-1 --artefacts artefacts.json
   ```

All operations are idempotent, so running them multiple times is safe.

---

## Command Line Interface

```
quicksight-migrator [command] [options]
```

| Command              | Purpose                                                          |
| -------------------- | ---------------------------------------------------------------- |
| `ensure`             | Stage 0/1 – create roles and the Aurora Data Source.             |
| `cleanup`            | Remove resources created during `ensure`.                        |
| `replicate-datasets` | Stage 2 – copy Direct Query Data Sets that use the source DS ARN. |

Run `quicksight-migrator [command] --help` for the complete list of options.

---

## Library Usage

The CLI is a thin wrapper around three Python functions:

```python
from quicksight_migrator.cli import (
    create_destination_datasource,
    cleanup_destination_datasource,
    replicate_datasets,
)
```

Each function mirrors the parameters of the respective CLI command. Using the library directly provides finer control and is ideal for CI/CD pipelines.

---

## Typical Use Cases

* **Environment bootstrap** – Prepare a new AWS account with the required roles and Data Source for QuickSight.
* **Cross-account migrations** – Replicate Direct Query Data Sets from a source environment to a destination account.
* **Rollback** – Quickly remove all migration artefacts whenever needed.

---

## Development

Clone the repository and install the dependencies from `requirements.txt`. The codebase is organised into small modules under `quicksight_migrator/` and is extensively type hinted.

---

## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.
