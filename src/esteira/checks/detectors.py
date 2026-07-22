"""Detectores.

Quando o YAML parseia (``wf.data`` disponível) as checagens são ESTRUTURAIS: iteram
sobre os valores já parseados (jobs → steps → run/uses/with) em vez de casar regex
linha-a-linha. Isso evita confundir texto de shell com chaves YAML, cobre os plain
scalars de ``run:`` e resolve indireção por env. Só quando o arquivo não parseia é que
caímos para um melhor-esforço por linha (``_fallback_checks``).
"""

from __future__ import annotations

import re
from typing import Any

from esteira.checks.catalog import make_finding
from esteira.core.loader import trigger_names
from esteira.core.models import Finding, Severity, Workflow

# Contextos controláveis por terceiros — nunca devem ir direto para o shell.
_UNTRUSTED = (
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.full_name",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.pages",
)
# Subcampos injetáveis de commits[] — só .message/.author/.committer (não .id, que é SHA).
_UNTRUSTED_RE = (re.compile(r"github\.event\.commits.*?\.(?:message|author|committer)"),)

# Conteúdo de ${{ }}: linear, tolera placeholders {N} e chaves escapadas {{ }} do format().
_EXPR = re.compile(r"\$\{\{([^{}]*(?:(?:\{[0-9]+\}|\{\{|\}\})[^{}]*)*)\}\}")
# Uma expressão ${{ env.X }} inteira (para resolver a indireção por variável de ambiente).
_ENV_EXPR = re.compile(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")
# Acesso por colchete/aspas: normaliza github['event']['x'] → github.event.x antes de casar.
_BRACKET = re.compile(r"\[\s*['\"]([\w.-]+)['\"]\s*\]")
# SHA de 40 hex, insensível a maiúsculas.
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
# curl|wget baixando e executando no shell: só em POSIÇÃO DE COMANDO (início de linha ou
# após ; & | ( `), atravessa estágios (base64 -d, gunzip), aceita caminho absoluto e wrappers.
_LEAD_CMD = r"(?:^|[\n;&|`(])\s*"
_WRAPPERS = r"(?:(?:sudo|env|command|time|nice|nohup|xargs|timeout|stdbuf)(?:\s+\S+)*?\s+)*"
_CURL_PIPE = re.compile(
    _LEAD_CMD + _WRAPPERS + r"(?:curl|wget)\b[^\n]*\|&?\s*"
    r"" + _WRAPPERS + r"(?:/\S*/)?(?:bash|sh|zsh|dash)\b"
)
# ref/repository de checkout que aponta para o código não-confiável do PR (não a base).
_PR_REF = re.compile(
    r"refs/pull/|github\.head_ref"
    r"|github\.event\.pull_request\.(?:head|number|merge_commit_sha)\b",
    re.IGNORECASE,
)
_FORK_REPO = re.compile(r"github\.event\.pull_request\.head\.repo|github\.head_ref", re.IGNORECASE)
# Checkout do código do PR via shell sob pull_request_target (base.ref confiável NÃO casa).
_PR_CHECKOUT_RUN = re.compile(
    r"gh\s+pr\s+checkout"
    r"|git\s+fetch\b[^\n]*\bpull/\S+/(?:head|merge)"
    r"|git\s+fetch\b[^\n]*github\.event\.pull_request\.(?:head|number|merge_commit_sha)\b",
    re.IGNORECASE,
)
_MATRIX_REF = re.compile(r"matrix\.([A-Za-z_][A-Za-z0-9_-]*)")
# uses:@ref para o modo de fallback (flow-style: o ref não pode capturar } ] ,).
_USES_LINE = re.compile(r"""uses:\s*['"]?([^'"\s@]+)@([^'"\s}\],]+)""")
_FIRST_PARTY = {"actions", "github"}


def run_all(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    if wf.parse_error is not None:
        out.append(
            make_finding(
                "invalid-yaml",
                wf.path,
                1,
                "YAML não pôde ser parseado; as checagens estruturais foram puladas. "
                f"{wf.parse_error}",
                evidence=wf.parse_error,
            )
        )
    if wf.data is None:
        out += _fallback_checks(wf)
        return out
    out += check_triggers(wf)
    out += check_ppt_checkout(wf)
    out += check_permissions(wf)
    out += check_self_hosted(wf)
    out += check_script_injection(wf)
    out += check_secret_in_run(wf)
    out += check_curl_pipe(wf)
    out += check_unpinned(wf)
    return out


# --------------------------------------------------------------------------- #
# navegação estrutural
# --------------------------------------------------------------------------- #


def _jobs(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return []
    return [j for j in jobs.values() if isinstance(j, dict)]


def _steps_of(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    if isinstance(steps, dict):  # steps declarado como mapa (inválido, mas não sumir com ele)
        steps = [steps]
    if not isinstance(steps, list):
        return []
    return [s for s in steps if isinstance(s, dict)]


def _env_of(node: Any) -> dict[str, Any]:
    env = node.get("env") if isinstance(node, dict) else None
    return env if isinstance(env, dict) else {}


def _step_contexts(data: dict[str, Any] | None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(step, env_map efetivo) para cada step — de jobs OU de uma composite action (runs.steps)."""
    contexts: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if not isinstance(data, dict):
        return contexts
    workflow_env = _env_of(data)
    for job in _jobs(data):
        job_env = {**workflow_env, **_env_of(job)}
        for step in _steps_of(job):
            contexts.append((step, {**job_env, **_env_of(step)}))
    runs = data.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        for step in runs["steps"]:
            if isinstance(step, dict):
                contexts.append((step, {**workflow_env, **_env_of(step)}))
    return contexts


# --------------------------------------------------------------------------- #
# reconhecimento de contexto não-confiável
# --------------------------------------------------------------------------- #


def _normalize_brackets(text: str) -> str:
    """github['event']['issue']['title'] → github.event.issue.title (bypass canônico)."""
    return _BRACKET.sub(r".\1", text)


def _untrusted_hit(text: str) -> str | None:
    """Retorna o primeiro contexto não-confiável presente em ``text`` (ou None)."""
    normalized = _normalize_brackets(text).lower()
    for untrusted in _UNTRUSTED:
        if untrusted in normalized:
            return untrusted
    for regex in _UNTRUSTED_RE:
        match = regex.search(normalized)
        if match is not None:
            return match.group(0)
    return None


def _resolve_env_refs(
    text: str, env_map: dict[str, Any], seen: frozenset[str] = frozenset()
) -> str:
    """Substitui ${{ env.X }} pelo valor de X recursivamente (segue a cadeia, com guarda de ciclo)."""
    normalized = _normalize_brackets(text)

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        value = env_map.get(key)
        if key in seen or not isinstance(value, str):
            return match.group(0)
        return _resolve_env_refs(value, env_map, seen | {key})

    return _ENV_EXPR.sub(repl, normalized)


# --------------------------------------------------------------------------- #
# checagens estruturais
# --------------------------------------------------------------------------- #


def check_triggers(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    names = trigger_names(wf.data or {})
    for dangerous in ("pull_request_target", "workflow_run"):
        if dangerous in names:
            out.append(
                make_finding(
                    "dangerous-trigger",
                    wf.path,
                    wf.find_line(dangerous),
                    f"Gatilho privilegiado em uso: {dangerous}.",
                    evidence=dangerous,
                )
            )
    return out


def _exec_texts(step: dict[str, Any]) -> list[str]:
    """Textos EXECUTADOS de um step onde ${{ }} é interpolado: run e o script do github-script."""
    texts: list[str] = []
    run = step.get("run")
    if isinstance(run, str):
        texts.append(run)
    uses = step.get("uses")
    if isinstance(uses, str) and uses.startswith("actions/github-script"):
        with_ = step.get("with")
        script = with_.get("script") if isinstance(with_, dict) else None
        if isinstance(script, str):
            texts.append(script)
    return texts


def check_script_injection(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for step, env_map in _step_contexts(wf.data):
        for text in _exec_texts(step):
            for match in _EXPR.finditer(text):
                resolved = _resolve_env_refs(match.group(0), env_map)
                hit = _untrusted_hit(resolved)
                if hit is not None:
                    evidence = match.group(0).strip()
                    out.append(
                        make_finding(
                            "script-injection",
                            wf.path,
                            wf.find_line(evidence),
                            f"Contexto não-confiável interpolado: {hit}.",
                            evidence=evidence,
                        )
                    )
    return out


def check_secret_in_run(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for step, _env in _step_contexts(wf.data):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for line in run.splitlines():
            if _secret_echo_leak(line):
                out.append(
                    make_finding(
                        "secret-in-run",
                        wf.path,
                        wf.find_line(line.strip()[:60]) if line.strip() else 1,
                        "Um segredo é impresso em um comando (echo/printf).",
                        evidence=line.strip()[:120],
                    )
                )
    return out


def _secret_echo_leak(line: str) -> bool:
    lowered = line.lower()
    if "echo" not in lowered and "printf" not in lowered:
        return False
    if not any("secrets." in m.group(1) for m in _EXPR.finditer(line)):
        return False
    # 'echo secret | docker login --password-stdin' / 'gh auth login --with-token' NÃO vaza:
    # o segredo vai para o stdin do próximo comando, não para o log.
    return "--password-stdin" not in lowered and "--with-token" not in lowered


def check_curl_pipe(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for step, _env in _step_contexts(wf.data):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for line in run.splitlines():
            if _CURL_PIPE.search(line):
                out.append(
                    make_finding(
                        "curl-pipe-shell",
                        wf.path,
                        wf.find_line(line.strip()[:60]) if line.strip() else 1,
                        "Download da rede executado direto no shell.",
                        evidence=line.strip()[:120],
                    )
                )
    return out


def check_unpinned(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for job in _jobs(wf.data):
        job_use = _uses_finding(wf, job.get("uses"))  # reusable workflow
        if job_use is not None:
            out.append(job_use)
    for step, _env in _step_contexts(wf.data):
        step_use = _uses_finding(wf, step.get("uses"))
        if step_use is not None:
            out.append(step_use)
    return out


def _uses_finding(wf: Workflow, uses: Any, line: int | None = None) -> Finding | None:
    if not isinstance(uses, str) or "@" not in uses:
        return None  # action local (sem @) ou valor inesperado
    if uses.startswith(("./", "../", "docker://")):
        return None
    action, _, ref = uses.rpartition("@")
    if not action or not ref or _SHA.match(ref):
        return None
    owner = action.split("/", 1)[0]
    check = "unpinned-action-firstparty" if owner in _FIRST_PARTY else "unpinned-action-thirdparty"
    return make_finding(
        check,
        wf.path,
        line if line is not None else wf.find_line(uses),
        f"'{action}' fixada por '{ref}' (não é SHA).",
        evidence=f"{action}@{ref}",
    )


def _ref_is_pr_code(ref: str) -> bool:
    return bool(_PR_REF.search(_normalize_brackets(ref)))


def check_ppt_checkout(wf: Workflow) -> list[Finding]:
    if "pull_request_target" not in trigger_names(wf.data or {}):
        return []
    out: list[Finding] = []
    cursor = 1
    workflow_env = _env_of(wf.data)
    for job in _jobs(wf.data):
        job_env = {**workflow_env, **_env_of(job)}
        for step in _steps_of(job):
            env_map = {**job_env, **_env_of(step)}
            finding, cursor = _ppt_step_finding(wf, step, env_map, cursor)
            if finding is not None:
                out.append(finding)
    return out


def _ppt_step_finding(
    wf: Workflow, step: dict[str, Any], env_map: dict[str, Any], cursor: int
) -> tuple[Finding | None, int]:
    uses = step.get("uses")
    if isinstance(uses, str) and uses.startswith("actions/checkout"):
        anchor = wf.find_line(uses, start=cursor)
        cursor = anchor + 1  # avança para não colar o próximo checkout na mesma linha
        with_raw = step.get("with")
        with_: dict[str, Any] = with_raw if isinstance(with_raw, dict) else {}
        ref = _resolve_env_refs(str(with_.get("ref", "")), env_map)
        repo = _resolve_env_refs(str(with_.get("repository", "")), env_map)
        reason, needle = None, ""
        if _ref_is_pr_code(ref):
            reason, needle = f"ref={ref!r}", str(with_.get("ref", ""))
        elif repo and _FORK_REPO.search(_normalize_brackets(repo)):
            reason, needle = f"repository={repo!r}", str(with_.get("repository", ""))
        if reason is not None:
            line = wf.find_line(needle, default=anchor, start=anchor) if needle else anchor
            return (
                make_finding(
                    "pull-request-target-checkout",
                    wf.path,
                    line,
                    f"checkout do código do PR ({reason}) sob pull_request_target.",
                    evidence=needle or reason,
                ),
                cursor,
            )
        return None, cursor
    run = step.get("run")
    if isinstance(run, str):
        for line_text in run.splitlines():
            if _PR_CHECKOUT_RUN.search(line_text):
                line = (
                    wf.find_line(line_text.strip()[:60], start=cursor)
                    if line_text.strip()
                    else cursor
                )
                return (
                    make_finding(
                        "pull-request-target-checkout",
                        wf.path,
                        line,
                        "checkout do código do PR via shell (gh pr checkout / git fetch pull) "
                        "sob pull_request_target.",
                        evidence=line_text.strip()[:120],
                    ),
                    line + 1,
                )
    return None, cursor


def check_permissions(wf: Workflow) -> list[Finding]:
    data = wf.data
    if not isinstance(data, dict):
        return []
    out: list[Finding] = []
    jobs_raw = data.get("jobs")
    jobs: dict[str, Any] = jobs_raw if isinstance(jobs_raw, dict) else {}
    multi_job = len(jobs) > 1

    out += _broad_permissions(wf, data.get("permissions"), "workflow", multi_job)
    for name, job in jobs.items():
        if isinstance(job, dict) and "permissions" in job:
            out += _broad_permissions(wf, job.get("permissions"), f"job '{name}'", multi_job=True)

    # missing-permissions: só em workflows (não em arquivos de action, que têm 'runs' e não
    # têm 'permissions'), quando não há bloco no workflow E algum job herda o padrão.
    if "permissions" not in data and "runs" not in data:
        undeclared = [
            n for n, j in jobs.items() if not (isinstance(j, dict) and "permissions" in j)
        ]
        if not jobs or undeclared:
            alvo = ", ".join(str(n) for n in undeclared) if undeclared else "o workflow"
            out.append(
                make_finding(
                    "missing-permissions",
                    wf.path,
                    1,
                    f"Sem bloco 'permissions'; herda o padrão da organização em: {alvo}.",
                )
            )
    return out


def _broad_permissions(wf: Workflow, perms: Any, scope: str, multi_job: bool) -> list[Finding]:
    if perms == "write-all":
        return [
            make_finding(
                "broad-permissions",
                wf.path,
                wf.find_line("write-all"),
                f"permissions: write-all ({scope}).",
                evidence="write-all",
            )
        ]
    # Escopos de escrita específicos só são 'amplos' no nível do workflow com vários jobs
    # (todos herdam). Um write por-job (ou de workflow com um só job) é o mínimo recomendado.
    if isinstance(perms, dict) and scope == "workflow" and multi_job:
        writes = sorted((str(k) for k, v in perms.items() if v == "write"), key=str)
        if writes:
            return [
                make_finding(
                    "broad-permissions",
                    wf.path,
                    wf.find_line("permissions"),
                    f"Escopos de escrita herdados por todos os jobs: {writes}.",
                    evidence=", ".join(writes),
                    severity=Severity.MEDIUM,
                )
            ]
    return []


def check_self_hosted(wf: Workflow) -> list[Finding]:
    if wf.data is None:
        return _self_hosted_lines(wf)
    out: list[Finding] = []
    for job in _jobs(wf.data):
        labels = _runs_on_labels_resolved(job)
        if any("self-hosted" in str(label).lower() for label in labels):
            out.append(
                make_finding(
                    "self-hosted-runner",
                    wf.path,
                    wf.find_line("self-hosted"),
                    "Job roda em runner self-hosted.",
                    evidence="self-hosted",
                )
            )
    return out


def _runs_on_labels_resolved(job: dict[str, Any]) -> list[str]:
    resolved: list[str] = []
    for label in _runs_on_labels(job.get("runs-on")):
        matrix_ref = _MATRIX_REF.search(str(label))
        if matrix_ref is not None:
            resolved += _matrix_values(job, matrix_ref.group(1))
        else:
            resolved.append(str(label))
    return resolved


def _matrix_values(job: dict[str, Any], name: str) -> list[str]:
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return []
    out: list[str] = []
    axis = matrix.get(name)
    if isinstance(axis, list):
        out += [str(v) for v in axis]
    elif isinstance(axis, str):
        out.append(axis)
    include = matrix.get("include")  # entradas de include[] também definem labels
    if isinstance(include, list):
        for entry in include:
            if isinstance(entry, dict) and name in entry:
                out.append(str(entry[name]))
    return out


def _runs_on_labels(runs_on: Any) -> list[str]:
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, list):
        return [str(item) for item in runs_on]
    if isinstance(runs_on, dict):
        labels = runs_on.get("labels")
        if isinstance(labels, str):
            return [labels]
        if isinstance(labels, list):
            return [str(item) for item in labels]
    return []


# --------------------------------------------------------------------------- #
# fallback por linha (só quando o YAML não parseou)
# --------------------------------------------------------------------------- #


def _fallback_checks(wf: Workflow) -> list[Finding]:
    """Melhor-esforço textual quando ``wf.data is None`` (o arquivo não parseou)."""
    out: list[Finding] = []
    for lineno, line in enumerate(wf.lines, start=1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        for match in _EXPR.finditer(line):
            hit = _untrusted_hit(match.group(1))
            if hit is not None:
                out.append(
                    make_finding(
                        "script-injection",
                        wf.path,
                        lineno,
                        f"Contexto não-confiável interpolado: {hit}.",
                        evidence=match.group(0).strip(),
                    )
                )
                break
        uses_match = _USES_LINE.search(line)
        if uses_match is not None:
            finding = _uses_finding(wf, f"{uses_match.group(1)}@{uses_match.group(2)}", line=lineno)
            if finding is not None:
                out.append(finding)
        if _secret_echo_leak(line):
            out.append(
                make_finding(
                    "secret-in-run",
                    wf.path,
                    lineno,
                    "Um segredo é impresso em um comando (echo/printf).",
                    evidence=line.strip()[:120],
                )
            )
        if _CURL_PIPE.search(line):
            out.append(
                make_finding(
                    "curl-pipe-shell",
                    wf.path,
                    lineno,
                    "Download da rede executado direto no shell.",
                    evidence=line.strip()[:120],
                )
            )
    out += _self_hosted_lines(wf)
    return out


def _self_hosted_lines(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for lineno, line in enumerate(wf.lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") or "self-hosted" not in line.lower():
            continue
        if "runs-on:" in line or stripped.startswith("- "):
            out.append(
                make_finding(
                    "self-hosted-runner",
                    wf.path,
                    lineno,
                    "Job roda em runner self-hosted.",
                    evidence=stripped,
                )
            )
    return out
