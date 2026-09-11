"""Pacote de checagens do Esteira.

Registro EAGER do catálogo. As checagens que vivem em módulos próprios
(``ai_workflow``, ``compromised_actions``, ``hardening_extra``) reusam helpers de
``detectors``; importá-las no topo de ``detectors`` criaria ciclo, então ``run_all`` as
importa localmente. Só que essas checagens se auto-registram no ``CATALOG`` no import — se
o único gatilho de import for uma varredura, ``set(CATALOG)`` fica INCOMPLETO até a
primeira ``scan()`` (validação de ``--only/--skip``, ``--list``, ``ruleset_hash`` e o laudo
de cobertura enxergariam menos regras do que existem).

Importar os módulos aqui, no ``__init__`` do pacote, popula o catálogo COMPLETO e de forma
DETERMINÍSTICA em qualquer ponto de entrada: o ``__init__`` do pacote sempre roda antes do
corpo de qualquer submódulo, então ``catalog`` e ``detectors`` inicializam por completo
antes de ``ai_workflow`` pedir seus helpers — sem depender da ordem de import do consumidor.
"""

from __future__ import annotations

from esteira.checks import (  # noqa: F401  (import só pelo efeito de auto-registro no CATALOG)
    ai_workflow,
    compromised_actions,
    hardening_extra,
)
