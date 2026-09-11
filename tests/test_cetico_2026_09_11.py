"""Corpus adversarial (caçada cética multiagente de 2026-09-11) — trava de regressão de CLASSE.

Uma leva de agentes céticos atacou os quatro detectores novos (Regra de Dois de IA, ação
comprometida, cache-poisoning, ator falsificável) procurando FP/FN/red-line, e produziu
contraexemplos YAML concretos. Cada veredito foi adjudicado EMPIRICAMENTE rodando o scanner real
(não a palavra do agente). Este teste versiona esse corpus e reprova qualquer regressão: um FP que
volta, um FN que reabre, ou uma correção de classe que se perde numa refatoração.

Filosofia (igual ao `bench/`): o corpus mora no repo, roda no CI, e quando apodrece, quebra.
Casos de destaque:
- author_association OWNER/MEMBER (padrão oficial de mitigação) NÃO é acusado (era o pior FP).
- `npx @anthropic-ai/claude-code` (forma mais comum em CI) é reconhecido (era FN).
- `pull_request` de fork é MÉDIA, não ALTA (o GitHub retém token/segredos do fork).
- reviewdog casa pelo SHA malicioso definitivo, não pela tag v1 já remediada (evita FP).
- ator falsificável cobre contains/startsWith/endsWith/fromJSON/sender.login e ignora `!(...)`.
- cache: `github.ref`/`ref_name` na chave não é envenenável; `||` misto não perde alcance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from esteira.checks.engine import scan

_FIXTURE = Path(__file__).parent / "fixtures" / "cetico_ci_2026_09_11.json"
_CASOS = json.loads(_FIXTURE.read_text(encoding="utf-8"))["casos"]


@pytest.mark.parametrize("caso", _CASOS, ids=[c["id"] for c in _CASOS])
def test_corpus_cetico_ci(caso: dict, tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "w.yml").write_text(caso["yaml"], encoding="utf-8")

    resultado = scan(tmp_path)
    escopo = set(caso["escopo_ids"])
    observado = sorted({f.check_id for f in resultado.findings} & escopo)

    assert observado == caso["esperado"], (
        f"{caso['id']} [{caso['tipo']}]: esperado {caso['esperado']}, veio {observado}. "
        f"Contexto: {caso['nota']}"
    )


def test_corpus_tem_cobertura_dos_quatro_detectores() -> None:
    # O corpus precisa exercitar os quatro detectores novos (senão uma regressão passa despercebida).
    exercitados = {i for c in _CASOS for i in c["esperado"]}
    assert exercitados >= {
        "ai-agent-rule-of-two",
        "ai-agent-untrusted-input",
        "known-compromised-action",
        "cache-poisoning",
        "falsifiable-actor-condition",
    }
    # E precisa ter casos de PRECISÃO (silêncio esperado), não só de disparo.
    assert any(not c["esperado"] for c in _CASOS)
