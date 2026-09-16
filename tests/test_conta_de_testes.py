"""Portão de badge (parte barata): todas as fontes anunciam a MESMA contagem de testes.

A igualdade com a coleta REAL (``pytest --collect-only``) é do ``scripts/check_test_count.py`` no
CI. Aqui garantimos, SEM subprocess (para não coletar recursivamente), que o SVG do badge e os
dois READMEs não divergem ENTRE SI — o erro humano típico (mexer num número e esquecer o outro)
fica vermelho já no ``pytest`` local, antes do CI.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_test_count.py"
_spec = importlib.util.spec_from_file_location("check_test_count", _SCRIPT)
assert _spec is not None and _spec.loader is not None
ctc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctc)


def test_badge_e_readmes_anunciam_a_mesma_contagem() -> None:
    """Badge SVG == README PT == README EN. A conta é gerada, não digitada: se as fontes divergem
    entre si, alguém mexeu num número e esqueceu do outro."""
    anunciados = ctc.numeros_anunciados()
    assert anunciados, "nenhuma contagem anunciada encontrada (badge/README)"
    valores = set(anunciados.values())
    assert len(valores) == 1, f"contagens divergentes entre fontes anunciadas: {anunciados}"
