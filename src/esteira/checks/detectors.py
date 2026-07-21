"""Detectores — parte por linha (dá número de linha), parte estrutural (YAML)."""

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
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.commits",
    "github.event.pages",
)
_EXPR = re.compile(r"\$\{\{(.*?)\}\}")
_USES = re.compile(r"""uses:\s*['"]?([^'"\s@]+)@([^'"\s]+)""")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_CURL_PIPE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b")
_FIRST_PARTY = {"actions", "github"}


def run_all(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    out += _line_checks(wf)
    out += check_triggers(wf)
    out += check_ppt_checkout(wf)
    out += check_permissions(wf)
    return out


# --------------------------------------------------------------------------- #
# por linha
# --------------------------------------------------------------------------- #


def _line_checks(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for lineno, line in enumerate(wf.lines, start=1):
        out += _script_injection(wf.path, lineno, line)
        out += _unpinned(wf.path, lineno, line)
        out += _secret_echo(wf.path, lineno, line)
        out += _curl_pipe(wf.path, lineno, line)
        out += _self_hosted(wf.path, lineno, line)
    return out


def _script_injection(path: str, lineno: int, line: str) -> list[Finding]:
    out: list[Finding] = []
    for match in _EXPR.finditer(line):
        expr = match.group(1)
        for untrusted in _UNTRUSTED:
            if untrusted in expr:
                out.append(
                    make_finding(
                        "script-injection",
                        path,
                        lineno,
                        f"Contexto não-confiável interpolado: {untrusted}.",
                        evidence=match.group(0).strip(),
                    )
                )
                break
    return out


def _unpinned(path: str, lineno: int, line: str) -> list[Finding]:
    match = _USES.search(line)
    if match is None:
        return []
    action, ref = match.group(1), match.group(2)
    if action.startswith(("./", "docker://")):
        return []
    if _SHA.match(ref):
        return []
    owner = action.split("/", 1)[0]
    check = "unpinned-action-firstparty" if owner in _FIRST_PARTY else "unpinned-action-thirdparty"
    return [
        make_finding(
            check,
            path,
            lineno,
            f"'{action}' fixada por '{ref}' (não é SHA).",
            evidence=f"{action}@{ref}",
        )
    ]


def _secret_echo(path: str, lineno: int, line: str) -> list[Finding]:
    lowered = line.lower()
    if "echo" not in lowered and "printf" not in lowered:
        return []
    if any("secrets." in match.group(1) for match in _EXPR.finditer(line)):
        return [
            make_finding(
                "secret-in-run",
                path,
                lineno,
                "Um segredo é impresso em um comando (echo/printf).",
                evidence=line.strip()[:120],
            )
        ]
    return []


def _curl_pipe(path: str, lineno: int, line: str) -> list[Finding]:
    if _CURL_PIPE.search(line):
        return [
            make_finding(
                "curl-pipe-shell",
                path,
                lineno,
                "Download da rede executado direto no shell.",
                evidence=line.strip()[:120],
            )
        ]
    return []


def _self_hosted(path: str, lineno: int, line: str) -> list[Finding]:
    if "runs-on:" in line and "self-hosted" in line:
        return [
            make_finding(
                "self-hosted-runner",
                path,
                lineno,
                "Job roda em runner self-hosted.",
                evidence=line.strip(),
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# estrutural (YAML)
# --------------------------------------------------------------------------- #


def check_triggers(wf: Workflow) -> list[Finding]:
    if wf.data is None:
        return []
    out: list[Finding] = []
    names = trigger_names(wf.data)
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


def check_ppt_checkout(wf: Workflow) -> list[Finding]:
    if wf.data is None or "pull_request_target" not in trigger_names(wf.data):
        return []
    out: list[Finding] = []
    for step in _iter_steps(wf.data):
        uses = step.get("uses", "")
        if not (isinstance(uses, str) and uses.startswith("actions/checkout")):
            continue
        with_ = step.get("with")
        ref = str(with_.get("ref", "")) if isinstance(with_, dict) else ""
        if any(marker in ref for marker in ("head", "pull_request", "github.event")):
            out.append(
                make_finding(
                    "pull-request-target-checkout",
                    wf.path,
                    wf.find_line("actions/checkout"),
                    f"checkout do código do PR (ref={ref!r}) sob pull_request_target.",
                    evidence=ref,
                )
            )
    return out


def check_permissions(wf: Workflow) -> list[Finding]:
    if wf.data is None:
        return []
    out: list[Finding] = []
    perms = wf.data.get("permissions")
    if perms == "write-all":
        out.append(
            make_finding(
                "broad-permissions",
                wf.path,
                wf.find_line("permissions"),
                "permissions: write-all no workflow.",
                evidence="write-all",
            )
        )
    elif isinstance(perms, dict):
        writes = sorted(k for k, v in perms.items() if v == "write")
        if writes:
            out.append(
                make_finding(
                    "broad-permissions",
                    wf.path,
                    wf.find_line("permissions"),
                    f"Escopos de escrita globais: {writes}.",
                    evidence=", ".join(writes),
                    severity=Severity.MEDIUM,
                )
            )
    jobs = wf.data.get("jobs")
    has_job_perms = isinstance(jobs, dict) and any(
        isinstance(j, dict) and "permissions" in j for j in jobs.values()
    )
    if perms is None and not has_job_perms:
        out.append(
            make_finding(
                "missing-permissions",
                wf.path,
                1,
                "Nenhum bloco 'permissions' declarado no workflow.",
            )
        )
    return out


def _iter_steps(data: dict[Any, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return steps
    for job in jobs.values():
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            steps.extend(s for s in job["steps"] if isinstance(s, dict))
    return steps
