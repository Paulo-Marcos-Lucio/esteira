"""P2-02 — a Esteira copiava até 120 caracteres CRUS da linha do workflow para `evidence`.

A regra `secret-in-run` existe justamente para achar linha com segredo. Sem camada de redação,
o relatório que denuncia o vazamento é ele próprio o vazamento — e ele vai para o JSON entregue
ao cliente e para o `snippet` do SARIF, que sobe para o GitHub Code Scanning.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.core import redaction
from esteira.report.json_report import to_json
from esteira.report.sarif import to_sarif

# Chave canônica da documentação da AWS (contém `EXAMPLE`): tem o FORMATO exato de produção,
# que é o que o padrão precisa exercitar, sem ser credencial de ninguém.
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"
_GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_STRIPE = "sk_live_" + "51H8kZqLmNoPqRsTuVwXyZ0123456789"


def _escreve(tmp_path: Path, conteudo: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "vaza.yml").write_text(textwrap.dedent(conteudo), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("credencial", [_AKIA, _GHP, _STRIPE])
def test_evidencia_nao_vaza_credencial_literal(tmp_path: Path, credencial: str) -> None:
    """O invariante da casa: o valor cru não sai — nem no JSON, nem no SARIF, nem no console."""
    repo = _escreve(
        tmp_path,
        f"""\
        on: push
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "chave={credencial} ${{{{ secrets.X }}}}"
        """,
    )
    resultado = scan(repo)
    assert resultado.findings, "o caso precisa gerar achado, senão o teste não prova nada"
    saida = to_json(resultado) + to_sarif(resultado)
    assert credencial not in saida
    assert credencial[:4] in saida, "a redação preserva o prefixo — é ele que diz QUAL credencial"


def test_credencial_alem_do_corte_de_120_nao_sai_pela_metade(tmp_path: Path) -> None:
    """A redação vem ANTES do truncamento. Na ordem inversa um segredo que começa no caractere
    110 sairia com 10 caracteres crus — vazamento parcial ainda é vazamento."""
    enchimento = "x" * 100
    repo = _escreve(
        tmp_path,
        f"""\
        on: push
        permissions: {{}}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "{enchimento} ${{{{ secrets.X }}}} {_GHP}"
        """,
    )
    documento = json.loads(to_json(scan(repo)))
    for achado in documento["findings"]:
        assert _GHP[:24] not in (achado["evidence"] or "")


def test_expressao_de_segredo_nao_e_valor_e_continua_legivel() -> None:
    """`${{ secrets.X }}` é uma REFERÊNCIA, não um valor. Redigir isso destruiria a evidência
    sem proteger nada — e é exatamente o que o auditor precisa ler no relatório."""
    linha = 'echo "token=${{ secrets.API_TOKEN }}"'
    assert redaction.redact(linha) == linha


def test_sha_de_pin_de_action_nao_e_confundido_com_segredo() -> None:
    """40 hex é o formato de um pin de action — o dado mais importante da evidência de
    `unpinned-action-*`. Uma regra genérica de entropia mastigaria justo essa evidência."""
    linha = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    assert redaction.redact(linha) == linha


@pytest.mark.parametrize(
    ("valor", "esperado"),
    [("", ""), ("curto", "c…"), ("012345678901", "0…"), ("0123456789012", "0123…9012")],
)
def test_mascara_nao_revela_as_pontas_de_valor_curto(valor: str, esperado: str) -> None:
    """Com valor curto, 8 caracteres expostos são pedaço grande demais do espaço de busca —
    e o comprimento exato também não pode vazar."""
    assert redaction.mask(valor) == esperado


def test_redacao_e_idempotente() -> None:
    """`make_finding` redige como rede de segurança e os detectores já redigem no corte:
    aplicar duas vezes não pode comer mais um pedaço da evidência."""
    uma = redaction.redact(f"chave={_AKIA}")
    assert redaction.redact(uma) == uma
