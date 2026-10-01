"""Deriva o Alcance de um workflow a partir dos nomes de gatilho (``on:``).

Alcance é ORTOGONAL à severidade: descreve QUEM consegue disparar o workflow, não o que ele
faz de errado. ``pull_request_target``/``issues``/``issue_comment`` aceitam evento de quem não
tem push no repositório (fork, comentário, issue) — EXTERNO, o gatilho que a suíte de
``dangerous-trigger``/``pull-request-target-checkout`` já trata como privilegiado.
``push``/``schedule`` só disparam por quem já tem escrita no repositório ou pelo relógio —
MANTENEDOR.

Um gatilho fora dessas duas listas (``workflow_dispatch``, ``pull_request`` comum,
``workflow_call``, ou a ausência de ``on:`` num arquivo que não parseou) é DESCONHECIDO: esta
função nunca alega MANTENEDOR — a rotulagem que soa segura — para um gatilho que não avaliou.
Fail-closed, cai em INDETERMINADO. Mistura de um gatilho EXTERNO com qualquer outro continua
EXTERNO: o workflow já é externamente disparável, independente do que mais o aciona.
"""

from __future__ import annotations

from enum import Enum


class Alcance(str, Enum):
    EXTERNO = "externo"
    MANTENEDOR = "mantenedor"
    INDETERMINADO = "indeterminado"


_EXTERNO = frozenset({"pull_request_target", "issues", "issue_comment"})
_MANTENEDOR = frozenset({"push", "schedule"})


def alcance_de_triggers(triggers: set[str]) -> Alcance:
    """``triggers`` é o retorno de ``loader.trigger_names`` — os nomes de ``on:`` do workflow."""
    if triggers & _EXTERNO:
        return Alcance.EXTERNO
    if triggers and triggers <= _MANTENEDOR:
        return Alcance.MANTENEDOR
    return Alcance.INDETERMINADO
