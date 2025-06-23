"""quicksight_migrator/__main__.py
====================================

Permite executar o pacote com:

```bash
python -m quicksight_migrator <args>
```

Esse wrapper delega imediatamente ao *CLI* oficial (`quicksight_migrator.cli`).
"""

from __future__ import annotations

import logging
import sys

from .cli import main as cli_main

# Configuração de logging básica — os módulos internos refinam conforme
# necessário; se o usuário quiser silenciar pode definir LOG_LEVEL antes de
# executar.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)

# Delegar para o parser/orquestração padrão.
cli_main()
