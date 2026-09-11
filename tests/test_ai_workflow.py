"""Testes da CAP B — auditor de workflow-IA (Regra de Dois de agentes de IA).

Chamam ``check_ai_rule_of_two`` DIRETAMENTE: o id ainda não está no ``run_all`` (fiação do
integrador), então ``scan``/``run_all`` não produziriam o achado. Determinístico e offline.

NOTA de fiação: enquanto o integrador não adicionar os ids a ``CASOS_POSITIVOS``, a
``SEVERIDADES``, ao ``run_all``, ao README e ao corpus do bench, os meta-testes
``tests/test_catalogo.py`` (set-equality) e ``tests/test_bench.py`` (cobertura) falham por
projeto — não por defeito deste módulo.
"""

from __future__ import annotations

import yaml

from esteira.checks.ai_workflow import check_ai_rule_of_two
from esteira.checks.catalog import CATALOG
from esteira.core.models import Severity, Workflow

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _wf(text: str) -> Workflow:
    data = yaml.safe_load(text)
    return Workflow(path="w.yml", text=text, data=data if isinstance(data, dict) else None)


def _ids(text: str) -> set[str]:
    return {f.check_id for f in check_ai_rule_of_two(_wf(text))}


# --------------------------------------------------------------------------- #
# positivos
# --------------------------------------------------------------------------- #

RULE_OF_TWO = f"""\
on: issues
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
        with:
          prompt: Responda a issue
"""

UNTRUSTED_INPUT = f"""\
on: issues
permissions:
  contents: read
jobs:
  summarize:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
        with:
          prompt: Resuma a issue
"""


def test_rule_of_two_dispara_com_os_tres_fatores() -> None:
    assert _ids(RULE_OF_TWO) == {"ai-agent-rule-of-two"}


def test_untrusted_input_dispara_sem_canal_de_escrita() -> None:
    assert _ids(UNTRUSTED_INPUT) == {"ai-agent-untrusted-input"}


def test_severidades() -> None:
    rot = check_ai_rule_of_two(_wf(RULE_OF_TWO))[0]
    ui = check_ai_rule_of_two(_wf(UNTRUSTED_INPUT))[0]
    assert rot.severity is Severity.HIGH
    assert ui.severity is Severity.MEDIUM


def test_pull_request_target_com_write_e_agente() -> None:
    texto = f"""\
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
        with:
          prompt: Revise este PR
"""
    assert _ids(texto) == {"ai-agent-rule-of-two"}


def test_canal_por_segredo_no_step_do_agente() -> None:
    # Sem permissões de escrita, mas o segredo de API vai ao step do agente: canal de exfil.
    texto = f"""\
on: issues
permissions:
  contents: read
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
        with:
          anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
"""
    ids = _ids(texto)
    assert ids == {"ai-agent-rule-of-two"}


def test_canal_por_push_via_shell() -> None:
    # Permissões ausentes, sem segredo, mas um passo dá git push: canal de escrita.
    texto = f"""\
on: pull_request_target
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
      - run: git push origin HEAD
"""
    assert _ids(texto) == {"ai-agent-rule-of-two"}


def test_canal_por_action_de_escrita() -> None:
    # Sem bloco `permissions:` declarado: o token default do repo PODE conceder escrita, então a
    # action de escrita (create-pull-request) conta como canal (leg 3) — Regra de Dois completa.
    # (Com `permissions: contents: read` explícito, a action de PR não teria escopo para escrever —
    # ver test_action_de_escrita_sem_escopo_e_medio, o lado da precisão do cx02.)
    texto = f"""\
on: issue_comment
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
      - uses: peter-evans/create-pull-request@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-rule-of-two"}


def test_action_de_escrita_sem_escopo_e_medio() -> None:
    # A MESMA action de escrita, mas com `permissions: contents: read` explícito: sem escopo de
    # escrita, create-pull-request FALHARIA — o canal não está aberto, então é MÉDIA, não ALTA.
    texto = f"""\
on: issue_comment
jobs:
  bot:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
      - uses: peter-evans/create-pull-request@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-untrusted-input"}


def test_agente_por_run_cli_com_flag_de_ferramenta() -> None:
    texto = """\
on: issues
permissions:
  contents: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - run: claude -p "resolva a issue" --dangerously-skip-permissions
"""
    findings = check_ai_rule_of_two(_wf(texto))
    assert {f.check_id for f in findings} == {"ai-agent-rule-of-two"}
    assert "claude" in findings[0].detail


def test_agente_gemini_por_nome_de_action() -> None:
    texto = f"""\
on: discussion
permissions:
  contents: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-rule-of-two"}


def test_write_all_e_canal_de_escrita() -> None:
    texto = f"""\
on: workflow_run
permissions: write-all
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-rule-of-two"}


def test_dois_jobs_um_de_cada_classe() -> None:
    texto = f"""\
on: issues
permissions:
  contents: read
jobs:
  ler:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
  agir:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-untrusted-input", "ai-agent-rule-of-two"}


# --------------------------------------------------------------------------- #
# baixo-FP: falta um dos três fatores
# --------------------------------------------------------------------------- #


def test_sem_gatilho_nao_confiavel_nao_dispara() -> None:
    # push é confiável: agente + write, mas sem entrada não-confiável (leg 1 ausente).
    texto = f"""\
on: push
permissions:
  contents: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
"""
    assert _ids(texto) == set()


def test_sem_agente_de_ia_nao_dispara() -> None:
    # gatilho não-confiável + write, mas nenhum agente de IA (leg 2 ausente).
    texto = f"""\
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_SHA}
      - uses: actions/labeler@{_SHA}
"""
    assert _ids(texto) == set()


def test_job_override_de_permissao_rebaixa_para_medio() -> None:
    # Workflow concede write, mas o job do agente SUBSTITUI por read: sem canal (leg 3 ausente).
    texto = f"""\
on: issues
permissions:
  contents: write
jobs:
  bot:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
"""
    assert _ids(texto) == {"ai-agent-untrusted-input"}


def test_run_cli_sem_flag_de_ferramenta_nao_e_agente() -> None:
    # `claude` mencionado sem poder de ferramenta: não é um agente com mãos (baixo-FP).
    texto = """\
on: issues
permissions:
  contents: write
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - run: echo "peça ao claude para revisar"
"""
    assert _ids(texto) == set()


def test_github_token_nao_conta_como_segredo_exfil() -> None:
    # Só github.token no step do agente, sem write nem push: continua MÉDIO (github.token é
    # governado pelas permissões, não é material de API exfiltrável).
    texto = f"""\
on: issues
permissions:
  contents: read
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@{_SHA}
        with:
          github_token: ${{{{ github.token }}}}
"""
    assert _ids(texto) == {"ai-agent-untrusted-input"}


# --------------------------------------------------------------------------- #
# robustez / estrutura
# --------------------------------------------------------------------------- #


def test_yaml_invalido_nao_quebra() -> None:
    wf = Workflow(path="w.yml", text="on: [", data=None)
    assert check_ai_rule_of_two(wf) == []


def test_composite_action_sem_gatilho_nao_dispara() -> None:
    texto = f"""\
name: composite
runs:
  using: composite
  steps:
    - uses: anthropics/claude-code-action@{_SHA}
"""
    assert _ids(texto) == set()


def test_jobs_malformado_nao_quebra() -> None:
    assert check_ai_rule_of_two(_wf("on: issues\njobs: nao-e-mapa\n")) == []


def test_ancora_na_linha_do_agente() -> None:
    finding = check_ai_rule_of_two(_wf(RULE_OF_TWO))[0]
    linha = RULE_OF_TWO.splitlines()[finding.line - 1]
    assert "claude-code-action" in linha


def test_fix_suggestion_presente() -> None:
    rot = check_ai_rule_of_two(_wf(RULE_OF_TWO))[0]
    ui = check_ai_rule_of_two(_wf(UNTRUSTED_INPUT))[0]
    assert rot.fix_suggestion and "Regra de Dois" in rot.fix_suggestion
    assert ui.fix_suggestion and ui.fix_suggestion.strip()


def test_autoregistro_no_catalogo() -> None:
    for cid, sev in (
        ("ai-agent-rule-of-two", Severity.HIGH),
        ("ai-agent-untrusted-input", Severity.MEDIUM),
    ):
        assert cid in CATALOG
        meta = CATALOG[cid]
        assert meta.severity is sev
        assert meta.owasp is not None and meta.owasp.startswith("A05:2025")
        assert (meta.cwe or "").startswith("CWE-")
        assert meta.recommendation.strip()
