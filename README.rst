# quicksight-migrator

*Zero‑downtime migration of Amazon QuickSight **DIRECT\_QUERY** assets between AWS accounts.*

.. image:: [https://img.shields.io/pypi/v/quicksight-migrator.svg](https://img.shields.io/pypi/v/quicksight-migrator.svg)
\:target: [https://pypi.org/project/quicksight-migrator](https://pypi.org/project/quicksight-migrator)
.. image:: [https://img.shields.io/pypi/pyversions/quicksight-migrator.svg](https://img.shields.io/pypi/pyversions/quicksight-migrator.svg)
\:target: [https://python.org](https://python.org)
.. image:: [https://img.shields.io/github/license/yourorg/quicksight-migrator.svg](https://img.shields.io/github/license/yourorg/quicksight-migrator.svg)
\:target: LICENSE

`quicksight-migrator` automates every step required to clone an **Aurora PostgreSQL** data source—plus every *DIRECT\_QUERY* dataset that depends on it—from a *source* AWS account to a *destination* account, while preserving permissions.

The workflow is idempotent (safe to re‑run) and provides first‑class rollback helpers.

---

## Features

*Stage 0 / 1 – Foundation*

* create the temporary IAM role `QS-MigrationDest` in the **destination** account and register it as a QuickSight *ADMIN* user;
* patch managed roles `aws-quicksight-service-role-v0` and `aws-quicksight-secretsmanager-role-v0` so QuickSight can read your database secret;
* ensure a QuickSight **group** (defaults to `Admins`) exists and adds the current caller;
* (re‑)create an **Aurora PostgreSQL** data source pointing to the given cluster & VPC connection.

*Stage 2 – Dataset replication*

* create role `QS-MigrationOrigin` in the **source** account with read‑only QuickSight permissions;
* iterate over every `DIRECT_QUERY` dataset that uses the original data source, replicating it in the destination account while transparently **swapping the `DataSourceArn`**;
* optionally export the raw JSON definition of each dataset for audit or GitOps purposes.

Additional helpers allow you to roll back both stages.

---

## Requirements

* Python >= 3.9
* AWS credentials able to create IAM roles, VPC connections, QuickSight resources and read the database Secret
* Destination QuickSight account in *Enterprise* (or *Standard, reader*) edition **with Enterprise features enabled**

All dependencies are pinned in `requirements.txt`.

---

## Installation

.. code-block:: bash

pip install quicksight-migrator

---

## Quick‑start (CLI)

.. code-block:: bash

# 1) Stage 0/1 – run from the *destination* profile

quicksight-migrator ensure&#x20;
\--region us-east-1&#x20;
\--destination-account-id 123456789012&#x20;
\--ds-id autoplan\_db&#x20;
\--secret-arn arn\:aws\:secretsmanager\:us-east-1:123456789012\:secret\:AuroraV2DBCredentials-xxxx&#x20;
\--vpc-connection-arn arn\:aws\:quicksight\:us-east-1:123456789012\:vpcConnection/367359c6-ede2-4122-b295-d94dd651930c&#x20;
\--export-path artefacts.json&#x20;
\--profile dest-profile

# 2) Stage 2 – replicate datasets (can run from either profile)

quicksight-migrator replicate-datasets&#x20;
\--region us-east-1&#x20;
\--source-account-id 111122223333&#x20;
\--artefacts artefacts.json&#x20;
\--profile dest-profile

# 3) Optional rollback

quicksight-migrator cleanup&#x20;
\--region us-east-1&#x20;
\--artefacts artefacts.json&#x20;
\--profile dest-profile

`artefacts.json` stores every ARN created by the tool so later steps know what to reuse—and what to delete on rollback. You can point to `s3://bucket/key.json` or `ssm://parameter/name` and the library will handle I/O for you.

---

## Python API

.. code-block:: python

from pathlib import Path
from quicksight\_migrator import (
create\_destination\_datasource,
replicate\_datasets,
cleanup\_destination\_datasource,
)

# Stage 0/1

artefacts = create\_destination\_datasource(
region="us-east-1",
destination\_account\_id="123456789012",
ds\_id="autoplan\_db",
secret\_arn="arn\:aws\:secretsmanager\:us-east-1:123456789012\:secret\:AuroraV2DBCredentials-xxxx",
vpc\_connection\_arn="arn\:aws\:quicksight\:us-east-1:123456789012\:vpcConnection/367359c6-ede2-4122-b295-d94dd651930c",
export\_path=Path("artefacts.json"),
)

# Stage 2

datasets = replicate\_datasets(
region="us-east-1",
source\_account\_id="111122223333",
artefacts\_path="artefacts.json",
save\_definitions=True,  # dumps JSON specs into artefacts/datasets/
)

print(f"Replicated: {datasets}")

# Rollback

cleanup\_destination\_datasource(
region="us-east-1",
profile=None,
artefacts\_path="artefacts.json",
)

---

## IAM roles & permissions

+------------------------------+-------------+--------------------------------------------------------------+
\| Role                         | Account     | Purpose                                                      |
+==============================+=============+==============================================================+
\| `QS-MigrationDest`         | destination | Assumed by the script; registered as QuickSight *ADMIN*      |
+------------------------------+-------------+--------------------------------------------------------------+
\| `QS-MigrationOrigin`       | source      | Read‑only QuickSight role assumed to list/describe datasets  |
+------------------------------+-------------+--------------------------------------------------------------+
\| `aws-quicksight-…role-v0`  | destination | Patched to allow access to the RDS secret                    |
+------------------------------+-------------+--------------------------------------------------------------+
\| `aws-quicksight-…sm-role`  | destination | Grants QuickSight permission to decrypt the secret           |
+------------------------------+-------------+--------------------------------------------------------------+

Pass `--managed-policies` to `ensure` to attach extra AWS‐managed policies to `QS-MigrationDest` (e.g. `arn:aws:iam::aws:policy/AmazonQuickSightFullAccess`).

---

## Artefacts file reference

.. code-block:: json

{
"destination\_role\_arn": "arn\:aws\:iam::123456789012\:role/QS-MigrationDest",
"destination\_datasource\_arn": "arn\:aws\:quicksight\:us-east-1:123456789012\:datasource/autoplan\_db",
"group\_arn": "arn\:aws\:quicksight\:us-east-1:123456789012\:group/default/Admins",
"datasets\_arns": \[
"arn\:aws\:quicksight\:us-east-1:123456789012\:dataset/abcd1234-…"
],
"datasets\_defs\_path": "artefacts/datasets"
}

---

## Logging

.. code-block:: bash

export LOG\_LEVEL=DEBUG  # enables verbose output

---

## Development

.. code-block:: bash

git clone [https://github.com/yourorg/quicksight-migrator.git](https://github.com/yourorg/quicksight-migrator.git)
cd quicksight-migrator
python -m venv .venv
source .venv/bin/activate
pip install -e '.\[dev]'
pytest -q

`pre‑commit` hooks and **Black** formatting are enforced.

---

## Troubleshooting

+-----------------------------------------------+----------------------------------------------------------+----------------------------------------------+
\| Symptom                                       | Cause                                                    | Fix                                         |
+===============================================+==========================================================+==============================================+
\| `AccessDeniedException` on `create_data_source` | IAM role not registered as QuickSight user              | Re‑run Stage 0/1 or add user via QuickSight  |
+-----------------------------------------------+----------------------------------------------------------+----------------------------------------------+
\| `InvalidParameterValueException: … calculated | Dataset contains calculated fields incompatible with DB | Review JSON definition exported with         | | columns are invalid`                         |                                                          | `--save-defs` and adjust target DB schema  |
+-----------------------------------------------+----------------------------------------------------------+----------------------------------------------+
\| `NoCredentialsError: Unable to locate …`    | AWS credentials/profile not detected                     | Set `AWS_PROFILE` or env. variables        |
+-----------------------------------------------+----------------------------------------------------------+----------------------------------------------+

---

## Roadmap

* Dashboards & analyses replication
* Glue / Athena data sources
* CloudFormation wrapper for CI/CD pipelines

Contributions are welcome – feel free to open issues or pull requests!

---

## License

This project is licensed under the **MIT License** – see the `LICENSE` file for details.

---

*Not affiliated with Amazon Web Services. “Amazon QuickSight” is a trademark of Amazon.com, Inc. or its affiliates.*
