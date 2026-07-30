from __future__ import annotations

from pathlib import Path

from esteira.checks.engine import scan
from esteira.core.models import Severity


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in scan(root).findings}


def test_vuln_workflow_triggers_all_families(vuln_repo: Path) -> None:
    ids = _ids(vuln_repo)
    expected = {
        "script-injection",
        "pull-request-target-checkout",
        "unpinned-action-thirdparty",
        "unpinned-action-firstparty",
        "broad-permissions",
        "secret-in-run",
        "curl-pipe-shell",
        "self-hosted-runner",
        "dangerous-trigger",
    }
    assert expected <= ids


def test_safe_workflow_is_clean(safe_repo: Path) -> None:
    assert scan(safe_repo).findings == []


def test_script_injection_has_line_number(vuln_repo: Path) -> None:
    findings = [f for f in scan(vuln_repo).findings if f.check_id == "script-injection"]
    assert findings
    assert all(f.line > 0 for f in findings)


def test_thirdparty_is_high_firstparty_is_low(vuln_repo: Path) -> None:
    findings = scan(vuln_repo).findings
    third = next(f for f in findings if f.check_id == "unpinned-action-thirdparty")
    first = next(f for f in findings if f.check_id == "unpinned-action-firstparty")
    assert third.severity is Severity.HIGH
    assert first.severity is Severity.LOW


def test_only_and_skip_filters(vuln_repo: Path) -> None:
    only = {f.check_id for f in scan(vuln_repo, only=["curl-pipe-shell"]).findings}
    assert only == {"curl-pipe-shell"}
    skipped = {f.check_id for f in scan(vuln_repo, skip=["script-injection"]).findings}
    assert "script-injection" not in skipped


def test_missing_permissions_detected(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "np.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n", encoding="utf-8"
    )
    ids = {f.check_id for f in scan(tmp_path).findings}
    assert "missing-permissions" in ids


# --------------------------------------------------------------------------- #
# secret-to-thirdparty-action
# --------------------------------------------------------------------------- #

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _write(tmp_path: Path, body: str) -> Path:
    wf = tmp_path / ".github" / "workflows" / "w.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + body,
        encoding="utf-8",
    )
    return tmp_path


def _findings(tmp_path: Path, cid: str = "secret-to-thirdparty-action") -> list:
    return [f for f in scan(tmp_path).findings if f.check_id == cid]


def test_token_to_unpinned_thirdparty_is_flagged(tmp_path: Path) -> None:
    # Positivo: GITHUB_TOKEN entregue a uma action de terceiros fixada por tag.
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    found = _findings(root)
    assert len(found) == 1
    assert found[0].severity is Severity.HIGH
    assert "some-org/deploy-action" in found[0].detail
    # aponta para a linha do segredo, não para o 'uses:'
    assert "secrets.GITHUB_TOKEN" in (found[0].evidence or "")


def test_github_dot_token_form_is_flagged(tmp_path: Path) -> None:
    # A outra grafia do mesmo token: ${{ github.token }}.
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        with:\n"
        "          repo-token: ${{ github.token }}\n",
    )
    assert len(_findings(root)) == 1


def test_arbitrary_secret_to_unpinned_thirdparty_is_flagged(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@main\n"
        "        with:\n"
        "          api_key: ${{ secrets.DEPLOY_KEY }}\n",
    )
    assert len(_findings(root)) == 1


def test_token_to_official_action_pinned_is_clean(tmp_path: Path) -> None:
    # Negativo canônico: action OFICIAL fixada por SHA recebendo o token — uso normal.
    root = _write(
        tmp_path,
        f"      - uses: actions/github-script@{_SHA}\n"
        "        with:\n"
        "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
        "          script: core.info('ok')\n",
    )
    assert _findings(root) == []


def test_token_to_official_action_unpinned_is_clean(tmp_path: Path) -> None:
    # actions/* recebendo o token é uso esperado (github-script precisa dele); sem alarme aqui
    # — a pinagem por tag da action oficial já é coberta por 'unpinned-action-firstparty'.
    root = _write(
        tmp_path,
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
        "          script: core.info('ok')\n",
    )
    assert _findings(root) == []


def test_token_to_pinned_thirdparty_is_clean(tmp_path: Path) -> None:
    # Terceiro, mas fixado por SHA: o código está congelado/revisado — prática recomendada.
    root = _write(
        tmp_path,
        f"      - uses: peter-evans/create-pull-request@{_SHA}\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    assert _findings(root) == []


def test_thirdparty_without_secret_not_flagged_here(tmp_path: Path) -> None:
    # Sem segredo no with: não é ESTE achado (a pinagem já sai como unpinned-action-thirdparty).
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n        with:\n          environment: prod\n",
    )
    assert _findings(root) == []
    assert _findings(root, "unpinned-action-thirdparty")  # a checagem irmã ainda dispara


def test_secret_to_thirdparty_respects_inline_suppression(tmp_path: Path) -> None:
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}  # esteira: ignore\n",
    )
    assert _findings(root) == []


def test_secret_via_env_to_unpinned_thirdparty_is_flagged(tmp_path: Path) -> None:
    # FN-ESTEIRA-02: o segredo chega por env:, não with: (padrão canônico do gitleaks-action).
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        env:\n"
        "          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    found = _findings(root)
    assert len(found) == 1
    assert found[0].severity is Severity.HIGH
    assert "via env.TOKEN" in found[0].detail
    assert "secrets.GITHUB_TOKEN" in (found[0].evidence or "")


def test_secret_via_env_to_official_action_is_clean(tmp_path: Path) -> None:
    # Espelho do caso with:: action OFICIAL recebendo o token por env: é uso normal, sem alarme.
    root = _write(
        tmp_path,
        "      - uses: actions/github-script@v7\n"
        "        env:\n"
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "        with:\n"
        "          script: core.info('ok')\n",
    )
    assert _findings(root) == []


def test_secret_via_env_to_pinned_thirdparty_is_clean(tmp_path: Path) -> None:
    # Terceiro fixado por SHA recebendo o token por env: — código congelado, sem alarme.
    root = _write(
        tmp_path,
        f"      - uses: peter-evans/create-pull-request@{_SHA}\n"
        "        env:\n"
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    assert _findings(root) == []


def test_secret_in_both_with_and_env_reports_once_with_priority(tmp_path: Path) -> None:
    # Dedup: um segredo em with: E em env: gera UM achado, e o with: mantém a prioridade de texto.
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        with:\n"
        "          token: ${{ secrets.DEPLOY_KEY }}\n"
        "        env:\n"
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    found = _findings(root)
    assert len(found) == 1
    assert "via with.token" in found[0].detail


# --------------------------------------------------------------------------- #
# script-injection via inputs.* / github.event.inputs.* (FN-ESTEIRA-01)
# --------------------------------------------------------------------------- #


def _write_full(tmp_path: Path, content: str) -> Path:
    wf = tmp_path / ".github" / "workflows" / "w.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(content, encoding="utf-8")
    return tmp_path


def _injections(root: Path) -> list:
    return [f for f in scan(root).findings if f.check_id == "script-injection"]


_DISPATCH = (
    "on:\n  workflow_dispatch:\n    inputs:\n      name:\n        required: true\n"
    "permissions:\n  contents: read\n"
    "jobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n"
)
_CALL = (
    "on:\n  workflow_call:\n    inputs:\n      target:\n        type: string\n"
    "permissions:\n  contents: read\n"
    "jobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n"
)


def test_dispatch_input_injection_is_low(tmp_path: Path) -> None:
    # github.event.inputs.* interpolado no run: sob workflow_dispatch — real, mas disparar exige
    # acesso de escrita → LOW (higiene), não CRITICAL.
    root = _write_full(
        tmp_path, _DISPATCH + '      - run: echo "hi ${{ github.event.inputs.name }}"\n'
    )
    found = _injections(root)
    assert len(found) == 1
    assert found[0].severity is Severity.LOW
    assert "inputs" in found[0].detail


def test_modern_inputs_form_is_detected(tmp_path: Path) -> None:
    # A grafia unificada inputs.* também é reconhecida.
    root = _write_full(tmp_path, _DISPATCH + '      - run: echo "hi ${{ inputs.name }}"\n')
    assert len(_injections(root)) == 1


def test_workflow_call_input_injection_is_high(tmp_path: Path) -> None:
    # Reusable workflow: o input vem do CALLER (alcançável por atacante) → HIGH, não LOW.
    root = _write_full(tmp_path, _CALL + '      - run: echo "build ${{ inputs.target }}"\n')
    found = _injections(root)
    assert len(found) == 1
    assert found[0].severity is Severity.HIGH


def test_input_via_env_indirection_is_clean(tmp_path: Path) -> None:
    # A correção recomendada (env indirection + "$VAR") NÃO deve disparar — senão a ferramenta
    # puniria a própria mitigação.
    root = _write_full(
        tmp_path,
        _DISPATCH + "      - env:\n"
        "          NAME: ${{ github.event.inputs.name }}\n"
        '        run: echo "hi $NAME"\n',
    )
    assert _injections(root) == []


def test_inputs_lookalike_contexts_not_flagged(tmp_path: Path) -> None:
    # Discriminação: acesso a um CAMPO chamado 'inputs' (precedido de '.') e um identificador que
    # apenas CONTÉM 'inputs' não são o contexto inputs — sob workflow_call, se casassem, seriam
    # HIGH; asseguramos 0.
    root = _write_full(
        tmp_path,
        _CALL + "      - run: |\n"
        '          echo "${{ needs.a.outputs.inputs_json }}"\n'
        '          echo "${{ fromJSON(needs.a.outputs.cfg).inputs.name }}"\n',
    )
    assert _injections(root) == []


def test_event_body_injection_stays_critical(tmp_path: Path) -> None:
    # Guarda de regressão: a calibração de inputs NÃO pode rebaixar os eventos de texto livre.
    root = _write(tmp_path, '      - run: echo "${{ github.event.issue.title }}"\n')
    found = _injections(root)
    assert len(found) == 1
    assert found[0].severity is Severity.CRITICAL


def test_inputs_under_indeterminate_trigger_is_medium(tmp_path: Path) -> None:
    # inputs.* referenciado sem workflow_dispatch/workflow_call (config atípica): não crava
    # CRITICAL nem dispensa como LOW — sinaliza MEDIUM.
    root = _write(tmp_path, '      - run: echo "${{ inputs.name }}"\n')  # _write usa on: push
    found = _injections(root)
    assert len(found) == 1
    assert found[0].severity is Severity.MEDIUM
