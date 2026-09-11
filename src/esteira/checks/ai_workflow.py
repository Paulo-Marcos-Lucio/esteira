"""Auditor de workflow-IA: a *Regra de Dois* dos agentes de IA em CI (estático/offline).

Categoria quente de 2026 (o `Claude Code Action` recebeu um CVE de CVSS 7.8 por injeção de
prompt via contexto do evento) e ainda sem um auditor de referência em PT-BR. A checagem é
100% ESTÁTICA: lê a árvore YAML já parseada, não executa o workflow nem toca a infra do
cliente — a mesma postura read-only/LGPD do resto da suíte. "Inconclusivo não é ausência":
quando faltam sinais para cravar a Regra de Dois completa, rebaixamos para um achado MÉDIO em
vez de calar.

**Framework — a Regra de Dois.** Um agente de IA em CI vira porta de execução privilegiada
quando coexistem, NO MESMO job, os TRÊS fatores abaixo. Enquanto no máximo dois deles se
juntam, um texto hostil no evento até engana o agente, mas não alcança um canal privilegiado:

1. **Entrada não-confiável** — o gatilho traz conteúdo escrito por terceiros (título/corpo de
   issue ou PR, comentário, diff de fork). São os gatilhos ``pull_request_target``,
   ``issue_comment``, ``issues``, ``discussion``/``discussion_comment``, as variações de
   ``pull_request_review*``, ``workflow_run`` e o próprio ``pull_request`` (o agente lê o
   título/corpo/diff do fork). O agente de IA ingere esse payload no prompt POR DESIGN — é
   exatamente o vetor do CVE do Claude Code Action —, então o gatilho não-confiável já
   estabelece a superfície de injeção; interpolar ``github.event.*`` cru só a torna mais direta.
2. **Agente de IA com ferramentas** — um ``uses:`` de agente (claude-code-action, copilot,
   gemini, openai, …) ou um ``run:`` que chama uma CLI de agente (``claude``/``copilot``/
   ``gemini``/``aider``/``llm``) com poderes de ferramenta (``--allowedTools``, ``--tools``,
   ``--dangerously-skip-permissions``, ``--permission-mode``, ``--mcp``…).
3. **Canal de escrita/exfil** — o job pode MUDAR estado ou VAZAR: permissões de escrita
   (``contents``/``pull-requests``/… ``write`` ou ``write-all``), segredos disponíveis ao step
   do agente (que ele pode exfiltrar se induzido), ou um passo que dá push/comenta/abre PR.

Com os três, ``ai-agent-rule-of-two`` (ALTA, CWE-1427 injeção de prompt / CWE-77, A05:2025).
Com só (1)+(2), ``ai-agent-untrusted-input`` (MÉDIA): a exposição existe, mas o canal
privilegiado ainda não foi confirmado no mesmo job.

Posicionamento honesto: não competimos em motor ativo nem em contagem de regras; o valor aqui
é o baixo-FP com número, a leitura estática (sem rodar nada na infra do cliente) e a doutrina
em PT-BR de uma categoria que ainda não tem dono no Brasil.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from esteira.checks.catalog import CATALOG, CheckMeta, make_finding
from esteira.checks.detectors import _EXPR, _action_ref, _env_of, _steps_of
from esteira.core.loader import trigger_names
from esteira.core.models import Finding, Severity, Workflow

# --------------------------------------------------------------------------- #
# catálogo (auto-registrado no fim do módulo)
# --------------------------------------------------------------------------- #

CATALOG_ENTRIES: list[CheckMeta] = [
    CheckMeta(
        "ai-agent-rule-of-two",
        "Agente de IA em CI reúne os três fatores da Regra de Dois",
        Severity.HIGH,
        "Aplique a Regra de Dois: nunca reúna, no MESMO job, entrada não-confiável + agente de "
        "IA + canal de escrita/segredos — no máximo dois dos três. Separe a LEITURA (agente sem "
        "privilégio, no gatilho não-confiável) da AÇÃO (job privilegiado disparado só por gatilho "
        "confiável, ex.: workflow_run após revisão humana) e trate o conteúdo do evento como "
        "DADO — passe-o por variável de ambiente/arquivo, jamais colado no prompt como instrução.",
        "A05:2025 Injection",
        "CWE-1427",
    ),
    CheckMeta(
        "ai-agent-untrusted-input",
        "Agente de IA exposto a entrada não-confiável (sem canal de escrita confirmado)",
        Severity.MEDIUM,
        "Trate o conteúdo do evento (título/corpo/comentário/diff de terceiros) como dado, não "
        "como instrução: injeção de prompt (CWE-1427) pode desviar a saída do agente. Não dê a "
        "este job permissões de escrita nem segredos e não adicione passos que commitem/comentem "
        "— senão ele completa a Regra de Dois (achado 'ai-agent-rule-of-two', ALTA).",
        "A05:2025 Injection",
        "CWE-1427",
    ),
]

# --------------------------------------------------------------------------- #
# (1) entrada não-confiável — gatilhos que carregam texto de terceiros
# --------------------------------------------------------------------------- #

# Gatilhos cujo payload é escrito por quem está FORA do círculo de confiança do repositório e
# que o agente de IA lê no prompt. `pull_request` entra porque o agente-revisor ingere o
# título/corpo/diff do fork; os demais são os do framework + as variações de review.
_UNTRUSTED_AI_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "pull_request",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "workflow_run",
    }
)


def _untrusted_ai_triggers(wf: Workflow) -> set[str]:
    """Gatilhos não-confiáveis presentes no workflow (reusa o resolvedor de `on:` do loader,
    que também trata o caso do YAML 1.1 em que `on` vira a chave booleana `True`)."""
    return trigger_names(wf.data or {}) & _UNTRUSTED_AI_TRIGGERS


# Gatilho em que o GitHub RETÉM o token de escrita e os segredos do conteúdo não-confiável (fork):
# `pull_request` de fork roda com GITHUB_TOKEN read-only e sem segredos, então o texto hostil do
# fork NÃO alcança um canal privilegiado — a Regra de Dois não fecha (cap em MÉDIA). Já
# `pull_request_target`/`issue_comment`/… rodam no contexto da base, com token e segredos plenos.
_FORK_ISOLATED_TRIGGERS = frozenset({"pull_request"})

# Associação de autor CONFIÁVEL: definida pelo GitHub (não spoofável), quebra a leg 1 (entrada
# não-confiável) — só um mantenedor dispara. CONTRIBUTOR/FIRST_TIME_CONTRIBUTOR/NONE NÃO contam.
_ASSOC_EQ = re.compile(
    r"github\.event(?:\.\w+)*\.author_association\s*==\s*['\"](?:OWNER|MEMBER|COLLABORATOR)['\"]",
    re.IGNORECASE,
)
# Allowlist de associações confiáveis: contains(fromJSON('["OWNER","MEMBER"]'), author_association).
_ASSOC_FROMJSON = re.compile(
    r"contains\(\s*fromjson\([^)]*\)\s*,\s*github\.event(?:\.\w+)*\.author_association\s*\)",
    re.IGNORECASE,
)


def _has_trust_gate(if_value: Any) -> bool:
    """O `if:` restringe a execução a um autor CONFIÁVEL (author_association OWNER/MEMBER/
    COLLABORATOR), neutralizando a leg 1? É o padrão de mitigação recomendado oficialmente para
    bots de IA. Só neutraliza se TODO caminho de execução exigir confiança: uma disjunção `||`
    com um termo não-confiável (ex.: `|| github.event_name == 'schedule'`) NÃO neutraliza.

    Só author_association conta — `github.actor == 'fulano'` é falsificável (é o domínio do
    detector 'falsifiable-actor-condition'), não uma guarda de confiança."""
    if not isinstance(if_value, str) or "author_association" not in if_value.lower():
        return False
    from esteira.checks.detectors import _normalize_brackets

    norm = _normalize_brackets(if_value)
    parts = norm.split("||")
    return all(bool(_ASSOC_EQ.search(p) or _ASSOC_FROMJSON.search(p)) for p in parts)


# --------------------------------------------------------------------------- #
# (2) agente de IA com ferramentas
# --------------------------------------------------------------------------- #

# Nome (owner/action, sem @ref) de um `uses:` que é um agente de IA. Curado de propósito para
# manter o FP baixo: só marcas de LLM-agente conhecidas, não qualquer coisa com "ai" no nome.
# `openai`/`anthropic`/`claude`/`copilot`/`gemini`/`chatgpt` casam por substring (distintivos);
# `aider`/`llm` exigem fronteira de segmento para não casar "raider"/"small".
_AI_ACTION_RE = re.compile(
    r"claude|copilot|gemini|openai|anthropic|chatgpt"
    r"|(?:^|[/-])aider(?:$|[/-])"
    r"|(?:^|[/-])llm(?:$|[/-])",
    re.IGNORECASE,
)
# CLI de agente invocada num `run:`, em posição de comando (início, após separador ou wrapper).
_AI_CLI = re.compile(
    r"(?:^|[\s;&|`(])(claude|copilot|gemini|aider|codex|llm|chatgpt)\b",
    re.IGNORECASE,
)
# Pacote de agente executado por `npx`/`pipx`/`uvx` (o nome vem depois de '/', então escapa da
# posição-de-comando de _AI_CLI). É a forma MAIS comum de rodar o Claude Code em CI. Reconhecemos
# pelo NOME DO PACOTE, curado para manter o FP baixo.
_AI_PKG = re.compile(
    r"@anthropic-ai/claude-code"
    r"|@openai/codex(?:-cli)?"
    r"|@google/gemini-cli"
    r"|@githubnext/copilot(?:-cli)?"
    r"|\baider-chat\b",
    re.IGNORECASE,
)
# Flags que concedem PODER DE FERRAMENTA à CLI do agente (executar bash, ler/escrever, MCP): é o
# que separa "rodei um agente" de "dei um agente com mãos". Exigir uma delas evita casar um
# `echo "peça ao claude"` benigno.
_AI_CAPABILITY_FLAG = re.compile(
    r"--allow\w*"
    r"|--allowed[- ]?tools"
    r"|--dangerously-skip-permissions"
    r"|--permission-mode\b"
    r"|--mcp(?:-config)?\b"
    r"|--tools?\b"
    r"|--yolo\b",
    re.IGNORECASE,
)


def _is_ai_action(name: str) -> bool:
    """O nome de action (owner/action) é de um agente de IA conhecido?"""
    return bool(_AI_ACTION_RE.search(name.lower()))


def _agent_of_step(step: dict[str, Any]) -> tuple[str, str] | None:
    """(evidência, nome-de-exibição) do agente de IA de um step, ou None.

    Reconhece dois sinks: um ``uses:`` de action de agente, ou um ``run:`` que invoca uma CLI de
    agente COM flag de ferramenta. A evidência é o texto para ancorar/redigir; o nome de exibição
    é o que entra na cópia do achado (a action ou a CLI).
    """
    uses = step.get("uses")
    if isinstance(uses, str):
        parsed = _action_ref(uses)
        name = parsed[0] if parsed is not None else uses.split("@", 1)[0]
        if name and _is_ai_action(name):
            return uses, name
    run = step.get("run")
    if isinstance(run, str) and _AI_CAPABILITY_FLAG.search(run):
        # Basta a flag de ferramenta em qualquer ponto do `run:` e a CLI numa das linhas: a
        # linha que casa é a evidência ancorável (um `run:` multi-linha vira uma linha por vez).
        for line in run.splitlines():
            match = _AI_CLI.search(line)
            if match is not None:
                return line.strip(), match.group(1).lower()
            pkg = _AI_PKG.search(line)
            if pkg is not None:
                return line.strip(), pkg.group(0).lower()
    return None


# --------------------------------------------------------------------------- #
# (3) canal de escrita/exfil no mesmo job
# --------------------------------------------------------------------------- #

# Segredo real (`secrets.X`) numa expressão — NÃO o `github.token`, que é o token padrão já
# governado pelas permissões (leg 3a). Um segredo de API colado no step do agente é material
# exfiltrável se o agente for induzido por injeção de prompt.
_SECRET_ONLY = re.compile(r"\bsecrets\.[A-Za-z_]\w*")
# Push/comentário/abertura de PR/release via shell — o job muda estado do repositório.
_PUSH_COMMENT_RUN = re.compile(
    r"\bgit\s+push\b"
    r"|\bgh\s+pr\s+(?:comment|review|merge|edit|create|close)\b"
    r"|\bgh\s+issue\s+(?:comment|edit|create|close)\b"
    r"|\bgh\s+release\s+(?:create|edit|upload)\b"
    r"|\bgh\s+api\b[^\n]*-X\s*(?:POST|PATCH|PUT|DELETE)\b",
    re.IGNORECASE,
)
# Actions cujo propósito é escrever no repositório (commit/PR/comentário/release).
_WRITE_ACTION_RE = re.compile(
    r"peter-evans/create-pull-request"
    r"|peter-evans/create-or-update-comment"
    r"|peter-evans/commit-comment"
    r"|stefanzweifel/git-auto-commit-action"
    r"|ad-m/github-push-action"
    r"|endbug/add-and-commit"
    r"|thollander/actions-comment-pull-request"
    r"|mshick/add-pr-comment"
    r"|softprops/action-gh-release"
    r"|actions/create-release"
    r"|ncipollo/release-action",
    re.IGNORECASE,
)


def _write_scopes(perms: Any) -> str:
    """Escopos de ESCRITA concedidos por um bloco `permissions:` (ou '' se nenhum).

    ``write-all`` (string) concede tudo; um mapa concede o que estiver marcado ``write``.
    ``read-all``/``{}``/``none``/ausente não concedem escrita.
    """
    if perms == "write-all":
        return "write-all"
    if isinstance(perms, dict):
        writes = sorted(str(k) for k, v in perms.items() if str(v).strip().lower() == "write")
        return ", ".join(writes)
    return ""


def _effective_permissions(data: dict[str, Any], job: dict[str, Any]) -> Any:
    """Permissões EFETIVAS do job. Um bloco `permissions:` no job SUBSTITUI o do workflow (não
    mescla); sem ele, valem as do workflow."""
    if "permissions" in job:
        return job["permissions"]
    return data.get("permissions")


def _has_real_secret(text: str) -> bool:
    """A string interpola algum `secrets.X` (dentro de `${{ }}`)?"""
    return any(_SECRET_ONLY.search(m.group(1)) for m in _EXPR.finditer(text))


def _agent_step_has_secret(data: dict[str, Any], job: dict[str, Any], step: dict[str, Any]) -> bool:
    """O step do agente recebe um segredo — pelo `env:` efetivo (workflow→job→step) ou pelo
    `with:`. Ambos chegam ao processo do agente (`process.env`/inputs)."""
    env_map = {**_env_of(data), **_env_of(job), **_env_of(step)}
    values = [v for v in env_map.values() if isinstance(v, str)]
    with_ = step.get("with")
    if isinstance(with_, dict):
        values += [v for v in with_.values() if isinstance(v, str)]
    return any(_has_real_secret(v) for v in values)


def _job_pushes_or_comments(job: dict[str, Any]) -> str | None:
    """Descrição do primeiro passo do job que dá push/comenta/abre PR (ou None)."""
    for step in _steps_of(job):
        uses = step.get("uses")
        if isinstance(uses, str) and _WRITE_ACTION_RE.search(uses):
            return f"action de escrita ({uses.split('@', 1)[0]})"
        run = step.get("run")
        if isinstance(run, str) and _PUSH_COMMENT_RUN.search(run):
            return "push/comentário ao repositório via shell"
    return None


# Canal de EXFIL que NÃO depende de escopo de escrita do token: um artefato carrega para fora o
# que o agente foi induzido a ler (segredo/código). `upload-artifact` sobe pela API de Actions,
# independentemente de `contents: read`.
_EXFIL_ACTION_RE = re.compile(r"actions/upload-artifact", re.IGNORECASE)


def _job_exfil_channel(job: dict[str, Any]) -> str | None:
    """Canal de exfiltração por artefato no job (leg 3), ou None."""
    for step in _steps_of(job):
        uses = step.get("uses")
        if isinstance(uses, str) and _EXFIL_ACTION_RE.search(uses):
            return f"canal de exfiltração via upload de artefato ({uses.split('@', 1)[0]})"
    return None


def _job_write_channel(
    data: dict[str, Any], job: dict[str, Any], agent_step: dict[str, Any]
) -> str | None:
    """Canal de escrita/exfil do job (leg 3), ou None se nenhum for confirmado. Ordem determinística:
    permissões de escrita → segredos no step do agente → exfil por artefato → push/comentário."""
    perms = _effective_permissions(data, job)
    escopos = _write_scopes(perms)
    if escopos:
        return f"permissões de escrita ({escopos})"
    if _agent_step_has_secret(data, job, agent_step):
        return "segredos disponíveis ao step do agente (exfiltráveis por injeção de prompt)"
    exfil = _job_exfil_channel(job)
    if exfil is not None:
        return exfil
    # push/comentário via shell/action DEPENDE de escopo de escrita do token: só conta se as
    # permissões NÃO foram declaradas (o default do repo pode conceder escrita). Um bloco
    # `permissions:` declarado SEM escrita (ex.: `{}`/`read`) fecha o escopo — o passo falharia,
    # então não é canal aberto (evita FP em quem zerou o token de propósito).
    canal_exec = _job_pushes_or_comments(job)
    if canal_exec is not None and perms is None:
        return canal_exec
    return None


# --------------------------------------------------------------------------- #
# checagem
# --------------------------------------------------------------------------- #


def _named_jobs(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """(nome, job) de cada job que é um mapa — preservando a ordem do documento."""
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if isinstance(job, dict):
                yield str(name), job


def _first_agent(job: dict[str, Any]) -> tuple[dict[str, Any], str, str] | None:
    """(step, evidência, nome) do primeiro step do job que é um agente de IA, ou None."""
    for step in _steps_of(job):
        agent = _agent_of_step(step)
        if agent is not None:
            return step, agent[0], agent[1]
    return None


def check_ai_rule_of_two(wf: Workflow) -> list[Finding]:
    """Regra de Dois dos agentes de IA. Emite ``ai-agent-rule-of-two`` (ALTA) quando os três
    fatores coexistem no mesmo job, ou ``ai-agent-untrusted-input`` (MÉDIA) quando há entrada
    não-confiável + agente mas o canal de escrita/exfil não foi confirmado.

    Só workflows (precisa de gatilho); uma composite action, sem `on:`, nunca dispara.
    """
    data = wf.data
    if not isinstance(data, dict):
        return []
    gatilhos = _untrusted_ai_triggers(wf)
    if not gatilhos:
        return []  # sem entrada não-confiável não há Regra de Dois de IA (leg 1 ausente)
    gatilho = sorted(gatilhos)[0]
    # Só `pull_request` de fork como entrada não-confiável: o token de escrita e os segredos são
    # retidos do fork, então mesmo com canal declarado a Regra de Dois não fecha (cap em MÉDIA).
    fork_only = gatilhos <= _FORK_ISOLATED_TRIGGERS
    out: list[Finding] = []
    cursor = 1
    for name, job in _named_jobs(data):
        if _has_trust_gate(job.get("if")):
            continue  # leg 1 neutralizada: só autor confiável (author_association) dispara o job
        agente = _first_agent(job)
        if agente is None:
            juses = job.get("uses")
            if isinstance(juses, str) and _is_ai_action(juses.split("@", 1)[0]):
                inherit = (
                    " e 'secrets: inherit' entrega o cofre inteiro ao reusable"
                    if job.get("secrets") == "inherit"
                    else ""
                )
                at = wf.find_line(juses[:60], default=cursor, start=cursor)
                cursor = at + 1
                out.append(
                    make_finding(
                        "ai-agent-untrusted-input",
                        wf.path,
                        at,
                        f"Job '{name}' chama um reusable workflow de agente de IA "
                        f"({juses.split('@', 1)[0]}) sob entrada não-confiável (gatilho "
                        f"'{gatilho}'){inherit}: superfície de injeção de prompt (CWE-1427). O "
                        "interior do reusable é opaco à análise estática — inconclusivo não é "
                        "ausência: se ele tiver canal de escrita/segredos, é a Regra de Dois "
                        "completa. Isole a AÇÃO privilegiada num workflow disparado por "
                        "'workflow_run' após revisão humana.",
                        evidence=juses,
                        fix_suggestion=_fix_untrusted_input(),
                    )
                )
            continue  # sem agente de IA em step neste job (leg 2 ausente)
        step, evidencia, nome_agente = agente
        if _has_trust_gate(step.get("if")):
            continue  # o step do agente só roda para autor confiável — leg 1 neutralizada
        at = wf.find_line(evidencia[:60], default=cursor, start=cursor)
        cursor = at + 1
        canal = _job_write_channel(data, job, step)
        if canal is not None and not fork_only:
            out.append(
                make_finding(
                    "ai-agent-rule-of-two",
                    wf.path,
                    at,
                    f"Regra de Dois completa no job '{name}': (1) entrada não-confiável (gatilho "
                    f"'{gatilho}'), (2) agente de IA com ferramentas ({nome_agente}) e (3) "
                    f"{canal}. Um texto hostil no evento pode instruir o agente por injeção de "
                    "prompt (CWE-1427) a usar o canal privilegiado — commitar, comentar, abrir PR "
                    "ou vazar segredo. Quebre ao menos um dos três fatores.",
                    evidence=evidencia,
                    fix_suggestion=_fix_rule_of_two(gatilho),
                )
            )
        elif canal is not None and fork_only:
            out.append(
                make_finding(
                    "ai-agent-untrusted-input",
                    wf.path,
                    at,
                    f"Agente de IA ({nome_agente}) exposto a entrada não-confiável no job "
                    f"'{name}' (gatilho '{gatilho}'): superfície de injeção de prompt (CWE-1427). "
                    f"Há um canal no job ({canal}), MAS sob '{gatilho}' de fork o GitHub retém o "
                    "token de escrita e os segredos do conteúdo não-confiável — o texto hostil do "
                    "fork não alcança o canal (a Regra de Dois não fecha aqui). Atenção: se este "
                    "job passar a 'pull_request_target'/'issue_comment' ou rodar de branch do "
                    "próprio repo, fecha ('ai-agent-rule-of-two').",
                    evidence=evidencia,
                    fix_suggestion=_fix_untrusted_input(),
                )
            )
        else:
            out.append(
                make_finding(
                    "ai-agent-untrusted-input",
                    wf.path,
                    at,
                    f"Agente de IA ({nome_agente}) exposto a entrada não-confiável no job "
                    f"'{name}' (gatilho '{gatilho}'): superfície de injeção de prompt (CWE-1427). "
                    "Não confirmamos aqui um canal de escrita/exfil no mesmo job — inconclusivo "
                    "não é ausência: se este job ganhar permissão de escrita, segredos ou um passo "
                    "que comente/commite, vira a Regra de Dois completa ('ai-agent-rule-of-two').",
                    evidence=evidencia,
                    fix_suggestion=_fix_untrusted_input(),
                )
            )
    return out


def _fix_rule_of_two(gatilho: str) -> str:
    """Correção sugerida: quebrar um dos três fatores (a ferramenta NÃO reescreve o YAML)."""
    return (
        "Correção sugerida (quebre um dos três fatores da Regra de Dois):\n"
        f"  1. Gatilho: não rode o agente direto em '{gatilho}'. Faça a AÇÃO privilegiada num "
        "workflow separado, disparado por 'workflow_run' após revisão humana.\n"
        "  2. Agente: remova as permissões de escrita e os segredos do job do agente "
        "('permissions: {}' e sem 'secrets.*' no step).\n"
        "  3. Entrada: passe o contexto do evento como DADO, não como prompt — via 'env:' e "
        "referência entre aspas, nunca interpolado como instrução."
    )


def _fix_untrusted_input() -> str:
    """Correção sugerida para o caso (1)+(2) sem canal confirmado."""
    return (
        "Correção sugerida: trate o conteúdo do evento como dado. Passe-o por 'env:' e leia-o "
        "no agente como entrada a ser resumida/classificada, não como instrução a executar; e "
        "mantenha o job sem permissões de escrita e sem segredos para não completar a Regra de "
        "Dois."
    )


# Auto-registro no catálogo compartilhado (o integrador liga `check_ai_rule_of_two` ao run_all).
for _m in CATALOG_ENTRIES:
    CATALOG.setdefault(_m.id, _m)
