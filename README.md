# QuickSight Migration – Stage 0/1

> Automação de **roles IAM**, patch da service role do QuickSight e provisionamento da **DataSource Aurora PostgreSQL** na conta de destino.

---

## Estrutura do pacote

| Módulo          | Responsabilidade                                                                                                                             | Classes / funções principais                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `config.py`     | Dataclasses centrais (`Config`, `Account`) + helpers para sessões boto3/assume-role.                                                         | `Config.client()`, `Account.role_arn`                                           |
| `iam_roles.py`  | IAM helpers.<br>• `MigrationRole` — cria/atualiza a **QS‑MigrationDest**.<br>• `ServiceRolePatch` — injeta inline policy na service role QS. | `MigrationRole.ensure() / cleanup()`<br>`ServiceRolePatch.ensure() / cleanup()` |
| `datasource.py` | Interage com a API do QuickSight para criar/descrever/remover a DataSource Aurora PostgreSQL.                                                | `DataSourceManager.ensure() / cleanup()`                                        |
| `artefacts.py`  | Persistência/restore dos ARNs gerados entre os estágios.                                                                                     | `Artefacts.save()`, `Artefacts.load()`                                          |
| `cli.py`        | Orquestração de todos os managers via argparse.                                                                                              | `main()`                                                                        |
| `__main__.py`   | Permite rodar via `python -m quicksight_migrator ...`.                                                                                       | —                                                                               |

---

## Visão geral do fluxo

```mermaid
flowchart TD
    subgraph Step0
      A[MigrationRole.ensure()] -->|cria e atualiza| QSRole(QS-MigrationDest)
      B[ServiceRolePatch.ensure()] -->|inline <GetSecretValue>| QSSvcRole(aws-quicksight-service-role-v0)
    end
    Step0 --> Step1
    Step1[DataSourceManager.ensure()] -->|Cria Aurora DS| DS[QuickSight Data Source]
```

### Passos

1. **Step 0** — Preparação IAM
   a. `MigrationRole` cria/atualiza _QS‑MigrationDest_ com:

   - trust policy = QuickSight + opcional ( `--trust-principal` )
   - managed policy `AmazonQuickSightFullAccess` (ou similar)
   - **Inline policy** restrita ao seu secret de banco (least privilege).
     b. `ServiceRolePatch` injeta a mesma inline policy na _service role_ padrão (`aws-quicksight-service-role-v0`).

2. **Step 1** — DataSource do QuickSight

   - Usa o segredo passado via `--secret-arn` e parâmetros recebidos para criar a fonte Aurora PostgreSQL, caso ainda não exista.

3. **Artefacts export**

   - Salva em JSON (`--export-file`) os ARNs da role e DataSource criados, para uso em etapas seguintes.

4. **Cleanup / rollback**

   - Remove DataSource, roles e políticas inline/managed.

---

## Principais APIs públicas

### `iam_roles.MigrationRole`

| Método      | Descrição                                        |
| ----------- | ------------------------------------------------ |
| `ensure()`  | Cria/atualiza a role (idempotente), retorna ARN  |
| `cleanup()` | Remove policies (managed/inline) e exclui a role |

### `iam_roles.ServiceRolePatch`

| Método      | Descrição                              |
| ----------- | -------------------------------------- |
| `ensure()`  | Insere a inline policy na service role |
| `cleanup()` | Remove a inline policy                 |

### `datasource.DataSourceManager`

| Método      | Descrição                                            |
| ----------- | ---------------------------------------------------- |
| `ensure()`  | Busca DS pelo id; se não existir, cria e retorna ARN |
| `cleanup()` | Remove a DS, se existir                              |

### `artefacts.Artefacts`

| Método        | Descrição                          |
| ------------- | ---------------------------------- |
| `save(path)`  | Salva o JSON (indentação 2)        |
| `load(path)`  | Lê/parseia JSON, retorna instância |
| `update(**k)` | Helper: altera e salva             |

---

## Exemplos de uso

### 1 – Bootstrap (criação completa)

```bash
 python -m quicksight_migrator \
   --region us-east-1 \
   --destination 528757801159 \
   --ds-id autoplan_db \
   --secret-arn arn:aws:secretsmanager:us-east-1:528757801159:secret:AuroraV2DBCredentials-x3dXqE \
   --vpc-arn arn:aws:quicksight:us-east-1:528757801159:vpcConnection/367359c6-ede2-4122-b295-d94dd651930c \
   --profile quicksight-autoplan-hml \
   --export-file artefacts_stage1.json

```

### 2 – Cleanup / rollback (remoção de tudo criado)

```bash
python -m quicksight_migrator ... --cleanup
```

> **Dica:** Você pode rodar o `--cleanup` quantas vezes quiser, ele é idempotente e silencioso para recursos já removidos.

### 3 – Rodar já assumindo QS‑MigrationDest (exemplo CI/CD)

```bash
python -m quicksight_migrator ... --assume-role
```

> Útil para pipelines onde a role já foi provisionada e você só precisa garantir a existência do DataSource.

### 4 – Consultar artefatos em outros scripts

```python
from quicksight_migrator.artefacts import Artefacts

arts = Artefacts.load("artefacts_stage1.json")
print(arts.role_arn, arts.datasource_arn)
```

---

### Persistência de Artefatos

A opção `--export-file` (ou `--export-file`/`--import-file` para leitura) aceita **diferentes destinos**, automaticamente detectados pelo prefixo:

#### **Salvar/ler localmente (diretório local)**

```bash
python -m quicksight_migrator ... --export-file ./artefacts/artefacts_stage1.json
```

- O diretório será criado automaticamente se não existir.

#### **Salvar/ler no S3**

```bash
python -m quicksight_migrator ... --export-file s3://meu-bucket/autoplan/artefacts_stage1.json
```

- O script faz upload/download usando boto3.
- O bucket e a chave precisam existir e o perfil AWS precisa ter permissão de leitura/escrita.

#### **Salvar/ler no Parameter Store (SSM)**

```bash
python -m quicksight_migrator ... --export-file ssm:///app/artefacts/autoplan-stage1
```

- Armazena o JSON completo como parâmetro no SSM.
- Para ler:

  ```python
  Artefacts.load('ssm:///app/artefacts/autoplan-stage1')
  ```

#### **Formato autodetectado**

- Use prefixos: `s3://` para S3, `ssm://` para SSM Parameter Store, ou caminho local para arquivo.

#### **Exemplo de uso em Python**

```python
from quicksight_migrator.artefacts import Artefacts

arts = Artefacts.load('s3://meu-bucket/artefacts_stage1.json')
print(arts.role_arn, arts.datasource_arn)

arts = Artefacts.load('ssm:///app/artefacts/stage1')
```

---

## Workflows comuns

- **Primeiro uso:**
  Rode com todos os parâmetros obrigatórios (IAM + DS) e salve artefatos.
- **Reexecução/Idempotência:**
  O script não quebra se as roles/DataSource já existirem — apenas patcha o necessário.
- **Rollback:**
  Basta adicionar `--cleanup` à chamada para limpar _tudo_.
- **Uso em CI/CD:**
  Use `--assume-role` para rodar em pipelines, garantindo que o ambiente já está preparado.
