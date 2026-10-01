"""Confiança e persona do achado: campos novos em `Finding`, default do catálogo com
override por achado — o mesmo mecanismo que `severity` já usa em `make_finding`.

Confiança e persona são eixos ORTOGONAIS entre si e em relação à severidade: uma checagem
pode ser CRITICAL e ainda ter confiança BAIXA (achado indireto, sujeito a falso-positivo),
e uma checagem de severidade baixa pode ser REGULAR (visível por padrão). Nenhuma checagem
existente foi calibrada ainda — isso é ES-05b — então hoje toda checagem do catálogo tem
que nascer ALTA/REGULAR, o comportamento visível de hoje sem esta mudança.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from esteira.checks.catalog import CATALOG, make_finding
from esteira.core.models import Confianca, Persona


def test_toda_checagem_do_catalogo_nasce_alta_regular() -> None:
    """Nenhum item foi calibrado ainda (ES-05b): mudar o default não pode mudar o comportamento
    de hoje por baixo dos pés de quem já usa a Esteira."""
    fora_do_default = {
        cid: (meta.confidence, meta.persona)
        for cid, meta in CATALOG.items()
        if (meta.confidence, meta.persona) != (Confianca.ALTA, Persona.REGULAR)
    }
    assert fora_do_default == {}


@given(check_id=st.sampled_from(sorted(CATALOG)))
def test_make_finding_sem_override_usa_o_default_do_catalogo(check_id: str) -> None:
    meta = CATALOG[check_id]
    achado = make_finding(check_id, "w.yml", 1, "detalhe")
    assert achado.confidence == meta.confidence
    assert achado.persona == meta.persona


@given(
    check_id=st.sampled_from(sorted(CATALOG)),
    confidence=st.sampled_from(list(Confianca)),
    persona=st.sampled_from(list(Persona)),
)
def test_make_finding_com_override_ignora_o_default_do_catalogo(
    check_id: str, confidence: Confianca, persona: Persona
) -> None:
    """Override por achado é por isso que os campos existem: uma instância concreta de uma
    checagem pode ser mais/menos confiável que a média dela, ou relevante para outra persona."""
    achado = make_finding(check_id, "w.yml", 1, "detalhe", confidence=confidence, persona=persona)
    assert achado.confidence == confidence
    assert achado.persona == persona


@given(a=st.sampled_from(list(Confianca)), b=st.sampled_from(list(Confianca)))
def test_rank_de_confianca_e_total_e_antissimetrico(a: Confianca, b: Confianca) -> None:
    """`rank` tem que ordenar toda a enum sem empate — senão min-confidence não filtra nada."""
    assert (a.rank == b.rank) == (a == b)


@given(a=st.sampled_from(list(Persona)), b=st.sampled_from(list(Persona)))
def test_rank_de_persona_e_total_e_antissimetrico(a: Persona, b: Persona) -> None:
    assert (a.rank == b.rank) == (a == b)


def test_persona_rank_cresce_regular_pedantic_auditor() -> None:
    """A ordem que ES-05e vai travar como monotonicidade (auditor ⊇ pedantic ⊇ regular)
    só faz sentido se o rank já nascer nessa ordem."""
    assert Persona.REGULAR.rank < Persona.PEDANTIC.rank < Persona.AUDITOR.rank


def test_confianca_rank_cresce_baixa_media_alta() -> None:
    assert Confianca.BAIXA.rank < Confianca.MEDIA.rank < Confianca.ALTA.rank
