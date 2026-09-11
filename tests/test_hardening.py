"""CAP C — endurecimento estático: cache-poisoning e falsifiable-actor-condition.

Cobre o disparo (par write-PR / restore-push, gate de actor por bot), os NÃO-disparos que
seguram o FP (chaves distintas, sem gatilho de PR, contextos simétricos, chave por-run, `!=`,
ator humano) e os ramos dos helpers de parsing. `test_catalogo`/`test_bench` do worktree ainda
falham por set-equality — isso é FIAÇÃO do integrador (adicionar os ids em CASOS_POSITIVOS, no
bench e no README); aqui garantimos que a lógica NOVA está verde por si.
"""

from __future__ import annotations

import yaml

from esteira.checks.catalog import CATALOG
from esteira.checks.hardening_extra import (
    CATALOG_ENTRIES,
    _actor_bot_gate,
    _cache_ref_kind,
    _is_bot_login,
    _key_run_unique,
    _keys_match,
    _norm_key,
    _reachable_events,
    _restore_keys,
    check_cache_poisoning,
    check_falsifiable_actor,
)
from esteira.core.models import Severity, Workflow

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _wf(text: str, path: str = "w.yml") -> Workflow:
    """Workflow a partir do texto, com o YAML já parseado (como o loader faria)."""
    data = yaml.safe_load(text)
    return Workflow(path=path, text=text, data=data if isinstance(data, dict) else None)


# --------------------------------------------------------------------------- #
# cache-poisoning — disparo
# --------------------------------------------------------------------------- #

_CACHE_POISON = (
    "on: [pull_request, push]\n"
    "jobs:\n"
    "  seed:\n"
    "    if: ${{ github.event_name == 'pull_request' }}\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions: {}\n"
    "    steps:\n"
    f"      - uses: actions/cache/save@{_SHA}\n"
    "        with:\n"
    "          path: dist\n"
    "          key: build-artifacts-shared\n"
    "  release:\n"
    "    if: ${{ github.event_name == 'push' }}\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions: {}\n"
    "    steps:\n"
    f"      - uses: actions/cache/restore@{_SHA}\n"
    "        with:\n"
    "          path: dist\n"
    "          key: build-artifacts-shared\n"
    "      - run: ./deploy.sh\n"
)


def test_cache_poisoning_dispara() -> None:
    wf = _wf(_CACHE_POISON)
    achados = check_cache_poisoning(wf)
    assert [f.check_id for f in achados] == ["cache-poisoning"]
    f = achados[0]
    assert f.severity is Severity.HIGH
    assert "actions/cache/save" in wf.lines[f.line - 1]  # ancora na ESCRITA não-confiável
    assert f.evidence == "build-artifacts-shared"
    assert "release" in f.detail and "seed" in f.detail  # nomeia quem lê e quem escreve
    assert f.cwe == "CWE-349"


def test_cache_both_kind_cross_job_dispara() -> None:
    """`actions/cache@` (write+restore) num job de PR e noutro de push, mesma chave."""
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  pr:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
        "  main:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
    )
    assert [f.check_id for f in check_cache_poisoning(_wf(text))] == ["cache-poisoning"]


def test_cache_restore_keys_prefixo_dispara() -> None:
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  seed:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/save@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: deps-v2-lockhash\n"
        "  use:\n"
        "    if: github.event_name != 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/restore@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: deps-v2-outra\n"
        "          restore-keys: |\n"
        "            deps-v2-\n"
    )
    assert [f.check_id for f in check_cache_poisoning(_wf(text))] == ["cache-poisoning"]


def test_cache_linha_por_fallback_quando_contagem_diverge() -> None:
    """Um `uses:` de cache num COMENTÁRIO faz a contagem divergir → âncora textual (fallback)."""
    text = (
        "on: [pull_request, push]\n"
        "# uses: actions/cache/save@v4  (menção em comentário, não é um step)\n"
        "jobs:\n"
        "  seed:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/save@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
        "  use:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/restore@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
    )
    achados = check_cache_poisoning(_wf(text))
    assert [f.check_id for f in achados] == ["cache-poisoning"]
    assert achados[0].line >= 1


# --------------------------------------------------------------------------- #
# cache-poisoning — NÃO-disparo (o lado da precisão)
# --------------------------------------------------------------------------- #


def test_cache_chaves_distintas_nao_dispara() -> None:
    text = _CACHE_POISON.replace("key: build-artifacts-shared\n", "key: cache-do-pr\n", 1)
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_sem_gatilho_de_pr_nao_dispara() -> None:
    text = _CACHE_POISON.replace("on: [pull_request, push]", "on: push")
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_contextos_simetricos_nao_disparam() -> None:
    """Dois jobs sem gate, ambos em [pr, push]: padrão split benigno, contextos idênticos."""
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/save@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/restore@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
    )
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_chave_por_run_nao_dispara() -> None:
    text = _CACHE_POISON.replace("key: build-artifacts-shared", 'key: "build-${{ github.sha }}"')
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_actions_cache_both_no_mesmo_step_nao_dispara() -> None:
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
    )
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_step_sem_with_nao_quebra() -> None:
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  seed:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/save@{_SHA}\n"  # sem 'with' → sem chave
        "  use:\n"
        "    if: github.event_name == 'push'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: actions/cache/restore@{_SHA}\n"
        "        with:\n"
        "          path: dist\n"
        "          key: shared\n"
    )
    assert check_cache_poisoning(_wf(text)) == []


def test_cache_data_none_retorna_vazio() -> None:
    assert check_cache_poisoning(Workflow(path="w.yml", text="", data=None)) == []


# --------------------------------------------------------------------------- #
# falsifiable-actor-condition
# --------------------------------------------------------------------------- #


def test_actor_gate_por_bot_dispara_no_job() -> None:
    text = (
        "on: pull_request\n"
        "jobs:\n"
        "  automerge:\n"
        "    if: ${{ github.actor == 'dependabot[bot]' }}\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      pull-requests: write\n"
        "    steps:\n"
        "      - run: gh pr merge --auto\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
    )
    wf = _wf(text)
    achados = check_falsifiable_actor(wf)
    assert [f.check_id for f in achados] == ["falsifiable-actor-condition"]
    f = achados[0]
    assert f.severity is Severity.MEDIUM
    assert f.cwe == "CWE-807"
    assert "dependabot[bot]" in wf.lines[f.line - 1]
    assert "job 'automerge'" in f.detail


def test_actor_gate_no_step_dispara() -> None:
    text = (
        "on: pull_request\n"
        "jobs:\n"
        "  ci:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: \"github.actor == 'renovate[bot]'\"\n"
        "        run: ./auto-approve.sh\n"
    )
    achados = check_falsifiable_actor(_wf(text))
    assert [f.check_id for f in achados] == ["falsifiable-actor-condition"]
    assert "step de 'ci'" in achados[0].detail


def test_actor_negacao_nao_dispara() -> None:
    text = (
        "on: pull_request\n"
        "jobs:\n"
        "  ci:\n"
        "    if: github.actor != 'dependabot[bot]'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo oi\n"
    )
    assert check_falsifiable_actor(_wf(text)) == []


def test_actor_humano_nao_dispara() -> None:
    text = (
        "on: pull_request\n"
        "jobs:\n"
        "  ci:\n"
        "    if: github.actor == 'octocat'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo oi\n"
    )
    assert check_falsifiable_actor(_wf(text)) == []


def test_actor_if_legitimo_sem_ator_nao_dispara() -> None:
    text = (
        "on: [pull_request, push]\n"
        "jobs:\n"
        "  ci:\n"
        "    if: github.ref == 'refs/heads/main'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - if: true\n"  # if não-string/booleano é ignorado
        "        run: echo oi\n"
    )
    assert check_falsifiable_actor(_wf(text)) == []


def test_actor_data_none_retorna_vazio() -> None:
    assert check_falsifiable_actor(Workflow(path="w.yml", text="", data=None)) == []


# --------------------------------------------------------------------------- #
# helpers (ramos diretos)
# --------------------------------------------------------------------------- #


def test_reachable_events_formas() -> None:
    eventos = {"push", "pull_request"}
    assert _reachable_events(eventos, ["${{ 'push' == github.event_name }}"]) == frozenset({"push"})
    assert _reachable_events(eventos, ["github.event_name != 'pull_request'"]) == frozenset(
        {"push"}
    )
    assert _reachable_events(eventos, ["'pull_request' != github.event_name"]) == frozenset(
        {"push"}
    )
    assert _reachable_events(eventos, [None, "  "]) == frozenset(eventos)
    disjuncao = "github.event_name == 'push' || github.event_name == 'pull_request'"
    assert _reachable_events(eventos, [disjuncao]) == frozenset(eventos)


def test_restore_keys_formas() -> None:
    assert _restore_keys("a-\nb-\n") == ["a-", "b-"]
    assert _restore_keys(["x-", "", " z "]) == ["x-", "z"]
    assert _restore_keys(None) == []
    assert _restore_keys(123) == []


def test_key_helpers() -> None:
    assert _norm_key("  a b ") == "ab"
    assert _keys_match("shared", "shared", [])
    assert not _keys_match("shared", "outra", [])
    assert _keys_match("deps-v2-x", None, ["deps-v2-"])
    assert not _keys_match("deps-v2-x", None, [""])
    assert _key_run_unique("build-${{ github.run_id }}")
    assert not _key_run_unique("build-${{ hashFiles('x') }}")
    assert _cache_ref_kind("actions/cache@v4") == "both"
    assert _cache_ref_kind("actions/cache/save@v4") == "write"
    assert _cache_ref_kind("actions/cache/restore@v4") == "restore"
    assert _cache_ref_kind("actions/checkout@v4") is None


def test_is_bot_login() -> None:
    assert _is_bot_login("dependabot[bot]")
    assert _is_bot_login("renovate[bot]")
    assert _is_bot_login("github-actions")
    assert _is_bot_login("qualquer-coisa[bot]")
    assert not _is_bot_login("octocat")
    assert not _is_bot_login("mantenedor-real")


def test_actor_bot_gate_formas() -> None:
    assert _actor_bot_gate("${{ github.actor == 'dependabot[bot]' }}") == "dependabot[bot]"
    assert _actor_bot_gate("github['actor'] == 'renovate[bot]'") == "renovate[bot]"
    assert _actor_bot_gate("'dependabot[bot]' == github.triggering_actor") == "dependabot[bot]"
    assert _actor_bot_gate("github.actor != 'dependabot[bot]'") is None
    assert _actor_bot_gate("github.actor == 'octocat'") is None
    assert _actor_bot_gate("github.event_name == 'push'") is None


def test_catalog_entries_registrados() -> None:
    ids = {m.id for m in CATALOG_ENTRIES}
    assert ids == {"cache-poisoning", "falsifiable-actor-condition"}
    assert CATALOG["cache-poisoning"].severity is Severity.HIGH
    assert CATALOG["falsifiable-actor-condition"].severity is Severity.MEDIUM
    for m in CATALOG_ENTRIES:
        assert m.owasp is not None and m.owasp.startswith(("A01:2025", "A03:2025"))
        assert (m.cwe or "").startswith("CWE-")
        assert m.recommendation.strip()
