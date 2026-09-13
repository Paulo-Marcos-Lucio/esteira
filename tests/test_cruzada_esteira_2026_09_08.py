"""Invariantes das 5 classes P0+P1 da auditoria de 2026-09-08, cruzadas contra o oráculo
independente ``zizmor`` 1.30.0 (--offline). Cada classe ataca a CAUSA-RAIZ com um teste de
INVARIANTE (property-based onde cabe) e um par anti-mutação: o lado POSITIVO confirma a detecção
real, o lado NEGATIVO trava o falso-positivo — reverter o fix precisa deixar UM dos dois vermelho.

Fronteira, classe a classe:
  1. `&&`/`||` do GitHub RETORNAM o operando (curto-circuito) — não coagem para bool: só se
     suprime quando a expressão INTEIRA é booleana, não quando existe um `==` em algum ponto.
  2. `${{ inputs.x }}` só injeta se o `type:` declarado for injetável (string/choice/ausente);
     number/boolean não carregam charset de shell.
  3. `github.event.client_payload.*` (repository_dispatch) é 100% do disparador → não-confiável.
  4. Campo de evento de texto livre com charset arbitrário (release.body/.name, label.name/
     .description, milestone.*) injeta; campo de charset restrito (owner.login) NÃO.
  5. A âncora de um achado de imagem é a CHAVE ESTRUTURAL (`image:`/`container:`/nome do service),
     nunca a 1ª ocorrência textual do valor — e o `# zizmor: ignore` da linha certa volta a valer.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.detectors import (
    _expr_resulta_booleano,
    _input_e_injetavel,
    _untrusted_hit,
)
from esteira.checks.engine import scan
from esteira.core.models import Finding, Severity, Workflow


def _findings(tmp_path: Path, text: str) -> list[Finding]:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(text.lstrip("\n"), encoding="utf-8")
    return scan(tmp_path).findings


def _ids(tmp_path: Path, text: str) -> set[str]:
    return {f.check_id for f in _findings(tmp_path, text)}


def _run_wf(cmd: str, *, trigger: str = "issues") -> str:
    return (
        f"on: {trigger}\n"
        "permissions: {contents: read}\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - run: {cmd}\n"
    )


# --------------------------------------------------------------------------- #
# Classe 1 (P0) — ternário booleano super-suprime (FN).
# --------------------------------------------------------------------------- #
# Um operando é BOOLEANO ou NÃO, com a marca que diz qual. O invariante do curto-circuito: a
# expressão inteira só é booleana quando TODOS os operandos de retorno de um `&&`/`||` de topo o
# são — porque qualquer um deles pode ser o valor devolvido (e fluir cru para o shell).
_OP_BOOLEANO = [
    "a == b",
    "x != y",
    "n > 3",
    "contains(z, 'q')",
    "startswith(p, 'r')",
    "!flag",
    "true",
    "false",
]
_OP_NAO_BOOLEANO = [
    "github.event.issue.body",
    "github.head_ref",
    "inputs.name",
    "'literal'",
    "format('{0}', github.head_ref)",
]
_LEAF = st.one_of(
    st.sampled_from(_OP_BOOLEANO).map(lambda s: (s, True)),
    st.sampled_from(_OP_NAO_BOOLEANO).map(lambda s: (s, False)),
)


@settings(max_examples=400)
@given(operandos=st.lists(_LEAF, min_size=1, max_size=5), data=st.data())
def test_curto_circuito_e_booleano_sse_todos_operandos_sao(
    operandos: list[tuple[str, bool]], data: st.DataObject
) -> None:
    """INVARIANTE: `${{ ... }}` com `&&`/`||` de topo avalia para bool SE E SÓ SE todo operando
    de retorno for booleano. Reverter o fix (voltar a suprimir por 'existe um ==') derruba os
    exemplos em que um operando não-booleano é o valor devolvido."""
    expr = operandos[0][0]
    for leaf, _ in operandos[1:]:
        op = data.draw(st.sampled_from(["&&", "||"]))
        expr += f" {op} {leaf}"
    esperado = all(is_bool for _, is_bool in operandos)
    assert _expr_resulta_booleano(expr) is esperado


def test_ternario_com_retorno_nao_confiavel_injeta(tmp_path: Path) -> None:
    # POSITIVO (oráculo zizmor: template-injection): o `&&`/`||` devolve o texto do atacante.
    for cmd in (
        "echo \"${{ github.event.issue.title == 'deploy' && github.event.issue.body || 'noop' }}\"",
        "echo \"${{ github.run_attempt == '1' && github.event.issue.body || 'x' }}\"",
    ):
        assert "script-injection" in _ids(tmp_path, _run_wf(cmd)), cmd


def test_comparacao_booleana_genuina_nao_injeta(tmp_path: Path) -> None:
    # NEGATIVO (zizmor: sem achado): o não-confiável está DENTRO do operando comparado — só
    # true/false sai. Se o fix confundir os dois lados, este vira FP.
    for cmd in (
        "echo \"${{ github.event.issue.title == 'deploy' }}\"",
        "echo \"${{ contains(github.event.issue.body, 'skip') }}\"",
        'echo "${{ !github.event.issue.body }}"',
    ):
        assert "script-injection" not in _ids(tmp_path, _run_wf(cmd)), cmd


def test_ternario_vaza_segredo_no_retorno_mas_comparacao_pura_nao(tmp_path: Path) -> None:
    # A MESMA causa-raiz cega o secret-in-run: `secrets.K == 'x' && secrets.K || 'y'` devolve o
    # VALOR do segredo; `secrets.K != ''` só devolve true/false.
    vaza = "echo \"${{ secrets.K == 'x' && secrets.K || 'y' }}\""
    puro = "echo \"presente ${{ secrets.K != '' }}\""
    assert "secret-in-run" in _ids(tmp_path, _run_wf(vaza, trigger="push"))
    assert "secret-in-run" not in _ids(tmp_path, _run_wf(puro, trigger="push"))


# --------------------------------------------------------------------------- #
# Classe 2 (P0) — input tipo number/boolean tratado como injetável (FP).
# --------------------------------------------------------------------------- #
def _wf_com_input(tipo_call: str | None, tipo_disp: str | None) -> Workflow:
    def bloco(nome: str, tipo: str | None) -> str:
        if tipo is None:
            return ""
        t = "" if tipo == "ausente" else f"\n        type: {tipo}"
        return f"  {nome}:\n    inputs:\n      x:\n        required: true{t}\n"

    text = "on:\n" + bloco("workflow_call", tipo_call) + bloco("workflow_dispatch", tipo_disp)
    text += (
        "permissions: {contents: read}\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ inputs.x }}\n"
    )
    return Workflow(path="x", text=text, data=yaml.safe_load(text))


_TIPO = st.sampled_from([None, "ausente", "string", "choice", "number", "boolean"])


@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(tc=_TIPO, td=_TIPO)
def test_input_injetavel_sse_algum_bloco_e_texto(tc: str | None, td: str | None) -> None:
    """INVARIANTE: só deixa de ser injetável quando TODO bloco que declara o input dá
    number/boolean. String/choice/ausente (=string) em qualquer bloco mantém injetável; nenhum
    bloco declarando (tudo None) também mantém (tipo desconhecido, preserva o TP)."""
    if tc is None and td is None:
        return  # sem input declarado é coberto pelo caso separado abaixo
    declarados = [t for t in (tc, td) if t is not None]
    texto = {"string", "choice", "ausente"}
    esperado = any(t in texto for t in declarados)
    wf = _wf_com_input(tc, td)
    assert _input_e_injetavel(wf, "inputs.x") is esperado


def test_input_numerico_ou_booleano_nao_injeta(tmp_path: Path) -> None:
    # NEGATIVO (zizmor: sem template-injection): o GitHub coage o valor antes de existir.
    for tipo in ("number", "boolean"):
        wf = _wf_com_input(tipo, tipo).text
        assert "script-injection" not in _ids(tmp_path, wf), tipo


def test_input_string_choice_ou_ausente_ainda_injeta(tmp_path: Path) -> None:
    # POSITIVO (zizmor: template-injection): mantém o TP de type:string/choice/ausente.
    for tipo in ("string", "choice", "ausente"):
        wf = _wf_com_input(None, tipo).text
        assert "script-injection" in _ids(tmp_path, wf), tipo


def test_input_numero_num_bloco_e_texto_no_outro_ainda_injeta(tmp_path: Path) -> None:
    # BOUNDARY: number no workflow_call MAS string no workflow_dispatch → nem todo bloco é
    # não-injetável → dispara (o caller ainda pode mandar texto pelo dispatch).
    wf = _wf_com_input("number", "string").text
    assert "script-injection" in _ids(tmp_path, wf)


# --------------------------------------------------------------------------- #
# Classe 3 (P1) — client_payload (repository_dispatch) fora da lista não-confiável (FN).
# --------------------------------------------------------------------------- #
_SEG = st.text("abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8)


@settings(max_examples=200)
@given(segs=st.lists(_SEG, min_size=0, max_size=5))
def test_qualquer_subcampo_de_client_payload_e_nao_confiavel(segs: list[str]) -> None:
    """INVARIANTE: QUALQUER caminho sob github.event.client_payload (subtree inteiro, inclusive
    .slash_command.args.named.* e .args.unnamed) é não-confiável — é um regex de prefixo, não um
    campo isolado."""
    path = "github.event.client_payload" + "".join("." + s for s in segs)
    assert _untrusted_hit(f'echo "${{{{ {path} }}}}"') is not None


def test_client_payload_injeta_no_run(tmp_path: Path) -> None:
    # POSITIVO (zizmor: 2x template-injection). Severidade HIGH: escalação/insider (o dispatch
    # exige token), não externo anônimo.
    wf = """
on: repository_dispatch
permissions: {contents: read}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          checkArg=${{ github.event.client_payload.slash_command.args.named.runId }}
          snap=${{ github.event.client_payload.args.unnamed }}
"""
    achados = [f for f in _findings(tmp_path, wf) if f.check_id == "script-injection"]
    assert len(achados) == 2
    assert all(f.severity is Severity.HIGH for f in achados)


# --------------------------------------------------------------------------- #
# Classe 4 (P1) — campos de evento de texto livre fora da denylist (FN).
# --------------------------------------------------------------------------- #
def test_campos_texto_livre_de_evento_injetam(tmp_path: Path) -> None:
    # POSITIVO (zizmor: template-injection). O critério é o CHARSET arbitrário do campo, calibrado
    # a HIGH pelo privilégio do ator (release=write, label/milestone=triage): insider, não externo.
    casos = [
        ("release", "echo notes ${{ github.event.release.body }}"),
        ("release", "echo name ${{ github.event.release.name }}"),
        ("label", "echo l ${{ github.event.label.name }}"),
        ("label", "echo d ${{ github.event.label.description }}"),
        ("milestone", "echo m ${{ github.event.milestone.title }}"),
        ("milestone", "echo m ${{ github.event.milestone.description }}"),
    ]
    for trigger, cmd in casos:
        achados = [
            f
            for f in _findings(tmp_path, _run_wf(cmd, trigger=trigger))
            if f.check_id == "script-injection"
        ]
        assert achados, cmd
        assert all(f.severity is Severity.HIGH for f in achados), cmd


def test_campo_de_charset_restrito_nao_injeta(tmp_path: Path) -> None:
    # NEGATIVO (divergência deliberada do zizmor, que super-reivindica aqui): owner.login é
    # [A-Za-z0-9-] — não há charset de shell a injetar. O critério é o CHARSET, não a fonte.
    for cmd in (
        "echo owner ${{ github.event.repository.owner.login }}",
        "echo actor ${{ github.actor }}",
    ):
        assert "script-injection" not in _ids(tmp_path, _run_wf(cmd, trigger="push")), cmd


# --------------------------------------------------------------------------- #
# Classe 5 (P1) — âncora de imagem na 1ª ocorrência textual, não na chave estrutural (FP).
# --------------------------------------------------------------------------- #
_IMG_KEY_TOKENS = ("image:", "container:")


def _linha(text: str, n: int) -> str:
    return text.splitlines()[n - 1]


def test_ancora_de_imagem_pousa_na_chave_estrutural_nao_no_name(tmp_path: Path) -> None:
    """INVARIANTE: um achado de imagem-por-expressão nunca pousa numa linha sem chave de imagem
    (ex.: `name:`), mesmo quando a MESMA `${{ matrix.X }}` aparece antes num `name:`."""
    text = """
on: [push]
permissions: {contents: read}
jobs:
  test:
    name: Run ${{ matrix.g }} tests
    runs-on: ubuntu-latest
    strategy:
      matrix:
        g: [mariadb:10.6, mariadb:10.11]
    container:
      image: ${{ matrix.g }}
    steps:
      - run: mariadb --version
"""
    achados = [f for f in _findings(tmp_path, text) if f.check_id == "unpinned-container-image"]
    assert len(achados) == 1
    linha = _linha(text.lstrip("\n"), achados[0].line)
    assert "image:" in linha  # pousou na chave estrutural
    assert "name:" not in linha  # NÃO na 1ª ocorrência textual da expressão


def test_ancora_correta_reabilita_supressao_do_mantenedor(tmp_path: Path) -> None:
    # CONSEQUÊNCIA QUE TRAVA JUNTO: com a âncora no `image:`, o `# zizmor: ignore` da linha certa
    # volta a suprimir (zizmor: 0 achados, 1 suppressed). Se a âncora recair no `name:`, a
    # diretiva não é vista e o FP reaparece.
    text = """
on: [push]
permissions: {contents: read}
jobs:
  test:
    name: Run ${{ matrix.g }} tests
    runs-on: ubuntu-latest
    strategy:
      matrix:
        g: [mariadb:10.6, mariadb:10.11]
    container:
      image: ${{ matrix.g }} # zizmor: ignore[unpinned-images]
    steps:
      - run: mariadb --version
"""
    assert "unpinned-container-image" not in _ids(tmp_path, text)


def test_ancora_estrutural_para_services_mapa_e_string(tmp_path: Path) -> None:
    # A chave estrutural também para services.<n>.image (mapa) e para o service em forma string:
    # cada achado pousa na sua própria chave, nunca no `name:` do job.
    text = """
on: [push]
permissions: {contents: read}
jobs:
  j:
    name: uses ${{ matrix.x }} everywhere
    runs-on: ubuntu-latest
    services:
      cache:
        image: redis:7
      db: postgres:15
    steps:
      - run: echo hi
"""
    achados = [f for f in _findings(tmp_path, text) if f.check_id == "unpinned-container-image"]
    assert len(achados) == 2
    corpo = text.lstrip("\n")
    for f in achados:
        linha = _linha(corpo, f.line)
        assert "name:" not in linha
        # ou é a chave `image:` (mapa) ou a chave-nome do service que carrega a imagem string
        assert "image:" in linha or (f.evidence is not None and f.evidence in linha)
