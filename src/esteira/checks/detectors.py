"""Detectores.

Quando o YAML parseia (``wf.data`` disponível) as checagens são ESTRUTURAIS: iteram
sobre os valores já parseados (jobs → steps → run/uses/with) em vez de casar regex
linha-a-linha. Isso evita confundir texto de shell com chaves YAML, cobre os plain
scalars de ``run:`` e resolve indireção por env. Só quando o arquivo não parseia é que
caímos para um melhor-esforço por linha (``_fallback_checks``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
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
    # Texto livre, 100% controlado pelo autor do fork (lista oficial do GitHub).
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
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
# Subcampos injetáveis de commits[] — só .message/.author/.committer (não .id, que é SHA) — e os
# INPUTS do workflow. `inputs.*` (workflow_call/workflow_dispatch) e a grafia legada
# `github.event.inputs.*` são controláveis por quem alimenta o input; a severidade é calibrada
# depois pelo gatilho (ver `_injection_severity`). O lookbehind `(?<![\w.])` evita casar DENTRO de
# outro contexto — `needs.x.outputs.inputs_json` e `myinputs.y` NÃO são inputs.
_UNTRUSTED_RE = (
    re.compile(r"github\.event\.commits.*?\.(?:message|author|committer)"),
    re.compile(r"(?:github\.event\.inputs|(?<![\w.])inputs)\.[\w-]+"),
)

# Conteúdo de ${{ }}. As alternativas são disjuntas pelo 1º caractere (', ", {, }, resto),
# então a repetição é determinística — não há backtracking a explorar.
#  - `'…'` / `"…"`: literal de string, onde {{ }} do format() e chaves de JSON são conteúdo;
#  - `\}(?!\})`: uma chave solta fecha nada — só `}}` termina a expressão. É isto que impede
#    a expressão de ENGOLIR o `}}` de fechamento e se estender até a última do arquivo
#    (com a forma antiga, três `${{ … }}` num mesmo `run:` viravam UM match só, e dois
#    achados de injeção sumiam);
#  - `$` fora de string encerra a tentativa: um `${{` sem fechamento falha na hora, em vez de
#    varrer o resto do texto. Sem isso o custo é quadrático — medido: 200 KB de `${{ ` sem
#    fechamento levavam 130 s; agora, 0,005 s.
_EXPR = re.compile(r"\$\{\{((?:'[^']*'|\"[^\"]*\"|\{\{|\{[0-9]+\}|\}(?!\})|[^'\"{}$])*)\}\}")
# Uma expressão ${{ env.X }} inteira (para resolver a indireção por variável de ambiente).
_ENV_EXPR = re.compile(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")
# Acesso por colchete/aspas: normaliza github['event']['x'] → github.event.x antes de casar.
_BRACKET = re.compile(r"\[\s*['\"]([\w.-]+)['\"]\s*\]")
# SHA de 40 hex, insensível a maiúsculas.
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
# curl|wget baixando e executando no shell: só em POSIÇÃO DE COMANDO (início de linha ou
# após ; & | ( `), atravessa estágios (base64 -d, gunzip), aceita caminho absoluto e wrappers.
_LEAD_CMD = r"(?:^|[\n;&|`(])\s*"
# As DUAS repetições são limitadas de propósito. A forma ilimitada
# `(?:WRAPPER(?:\s+\S+)*?\s+)*` é ambígua — a mesma palavra pode ser consumida pelo `*?`
# interno OU iniciar uma iteração do `*` externo — e explode em backtracking exponencial:
# medido, `'sudo env time nice ' * 6` (129 caracteres) levava 7,1 s, contra 0,000016 s aqui.
# Um `run:` hostil de ~160 caracteres num PR travava o job de auditoria por horas.
# O limite cobre o uso real (até 3 wrappers encadeados, cada um com até 3 argumentos
# próprios); quem encadear mais que isso deixa de ser detectado — troca deliberada.
_WRAPPERS = r"(?:(?:sudo|env|command|time|nice|nohup|xargs|timeout|stdbuf)(?:\s+\S+){0,3}?\s+){0,3}"
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
# Prefixo `- run:` de uma linha crua, removido no fallback para o comando voltar à posição 0.
_RUN_KEY = re.compile(r"^\s*-?\s*run:\s*")
_FIRST_PARTY = {"actions", "github"}
# Referência a um segredo dentro de uma expressão: qualquer secrets.X ou o github.token.
_SECRET_REF = re.compile(r"\bsecrets\.[A-Za-z_]\w*|\bgithub\.token\b", re.IGNORECASE)
# Identificador final de um contexto (github.event.issue.title → title) p/ nomear a env var.
_LAST_IDENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")


def run_all(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    if wf.parse_error is not None:
        out.append(
            make_finding(
                "invalid-yaml",
                wf.path,
                1,
                "Análise estrutural pulada — o YAML não pôde ser usado como workflow. "
                f"{wf.parse_error}",
                evidence=wf.parse_error,
            )
        )
    if wf.data is None:
        out += _fallback_checks(wf)
        return [f for f in out if not _is_suppressed(wf, f)]
    out += check_malformed_jobs(wf)
    out += check_triggers(wf)
    out += check_ppt_checkout(wf)
    out += check_permissions(wf)
    out += check_self_hosted(wf)
    out += check_script_injection(wf)
    out += check_secret_in_run(wf)
    out += check_curl_pipe(wf)
    out += check_unpinned(wf)
    out += check_secret_to_thirdparty(wf)
    out += check_secrets_inherit(wf)
    out += check_unpinned_images(wf)
    out += check_checkout_credentials(wf)
    return [f for f in out if not _is_suppressed(wf, f)]


def _is_suppressed(wf: Workflow, finding: Finding) -> bool:
    """Respeita supressão inline '# zizmor: ignore' / '# esteira: ignore' na linha do achado."""
    lines = wf.lines
    index = finding.line - 1
    if not 0 <= index < len(lines):
        return False
    lowered = lines[index].lower()
    if "esteira: ignore" in lowered:
        return True
    # zizmor: ignore[regra] — respeita a supressão (a nossa checagem pode ter outro nome, mas o
    # mantenedor já declarou aquele ponto como revisado/seguro).
    return "zizmor: ignore" in lowered


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


def check_malformed_jobs(wf: Workflow) -> list[Finding]:
    """`jobs:` presente mas NÃO é um mapa de jobs (é lista/escalar) — cegueira estrutural.

    O topo do arquivo parseou como mapa (então não caiu no fallback), mas ``jobs`` veio como
    lista ou escalar. Todo o resto das checagens itera ``jobs`` como um dicionário e devolve
    vazio em silêncio para essa forma — um workflow que esconde um runner self-hosted ou uma
    injeção dentro de um ``jobs:`` malformado passaria no gate como limpo (no máximo um
    ``missing-permissions`` LOW, que não reprova o CI no ``--fail-on high`` padrão). Reaproveita
    a rota ``invalid-yaml`` (HIGH, fail-closed): sinaliza que a análise por job foi pulada e
    reprova o CI, em vez de ficar verde por engano. ``jobs`` ausente/nulo (arquivo de action
    com ``runs:``) e ``jobs: {}`` continuam legítimos e não disparam nada.
    """
    data = wf.data
    if not isinstance(data, dict):
        return []
    jobs = data.get("jobs")
    if jobs is None or isinstance(jobs, dict):
        return []
    return [
        make_finding(
            "invalid-yaml",
            wf.path,
            wf.find_line("jobs"),
            f"o campo 'jobs' é {type(jobs).__name__}, não um mapeamento de jobs; "
            "as checagens por job/step foram puladas para este arquivo.",
            evidence="jobs",
        )
    ]


def check_triggers(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    names = trigger_names(wf.data or {})
    for dangerous in ("pull_request_target", "workflow_run", "issue_comment"):
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


def _exec_texts(step: dict[str, Any]) -> list[tuple[str, str]]:
    """(sink, texto) executados onde ${{ }} é interpolado.

    ``sink`` é ``"run"`` (shell) ou ``"github-script"`` (JS) — a correção sugerida difere:
    ``"$VAR"`` no shell, ``process.env.VAR`` no JS.
    """
    texts: list[tuple[str, str]] = []
    run = step.get("run")
    if isinstance(run, str):
        texts.append(("run", run))
    uses = step.get("uses")
    if isinstance(uses, str) and uses.startswith("actions/github-script"):
        with_ = step.get("with")
        script = with_.get("script") if isinstance(with_, dict) else None
        if isinstance(script, str):
            texts.append(("github-script", script))
    return texts


def _env_var_name(hit: str) -> str:
    """Nome de env var a sugerir a partir do contexto (github.event.issue.title → TITLE)."""
    match = _LAST_IDENT.search(hit)
    return match.group(1).upper() if match is not None else "UNTRUSTED_INPUT"


# Gatilhos em que o INPUT é alcançável por quem NÃO tem acesso de escrita: um reusable workflow
# (workflow_call) recebe o input do caller (que pode ser menos confiável), e eventos privilegiados
# carregam contexto de fora. Nesses casos a injeção via inputs.* é séria.
_INPUT_REACHABLE_TRIGGERS = frozenset(
    {"workflow_call", "pull_request_target", "workflow_run", "repository_dispatch"}
)


def _is_inputs_context(hit: str) -> bool:
    """O contexto casado é um INPUT do workflow (inputs.* / github.event.inputs.*)?"""
    return "inputs" in hit


def _injection_severity(wf: Workflow, hit: str) -> Severity | None:
    """Severidade calibrada por gatilho (``None`` ⇒ padrão CRITICAL do catálogo).

    Sinal SUAVE, não filtro: nunca suprime o achado — só ajusta o quão alto ele grita, porque a
    MESMA expressão vale coisas diferentes conforme QUEM alimenta o input.

    - Evento de texto livre (issue/PR/comentário/commit): permanece CRITICAL — controlado por
      qualquer um que abra um PR/issue (retorna ``None`` p/ herdar o catálogo).
    - Input com gatilho alcançável por atacante (workflow_call e cia.): HIGH.
    - Input só sob workflow_dispatch: LOW — disparar já exige acesso de escrita ao repo, então é
      higiene, não porta de entrada externa (mas NÃO é zero: o próprio operador pode se enganar,
      e o hábito de interpolar input cru no shell é o que queremos corrigir).
    - Gatilho indeterminado: MEDIUM — sinaliza sem cravar CRITICAL.
    """
    if not _is_inputs_context(hit):
        return None
    names = trigger_names(wf.data or {})
    if names & _INPUT_REACHABLE_TRIGGERS:
        return Severity.HIGH
    if "workflow_dispatch" in names:
        return Severity.LOW
    return Severity.MEDIUM


def _injection_fix(expr: str, hit: str, *, in_js: bool) -> str:
    """Sugestão CONCRETA de correção por env indirection para um script-injection.

    Move a expressão não-confiável para um bloco ``env:`` (onde ela vira DADO, não texto
    reinterpretado pelo shell/JS) e referencia a variável — ``"$VAR"`` no ``run:``,
    ``process.env.VAR`` no ``github-script``. É enriquecimento do achado (a ferramenta NÃO
    reescreve o YAML): só sugere o padrão, sem afirmar que aplicá-lo torna o workflow seguro.
    """
    var = _env_var_name(hit)
    if in_js:
        return (
            "Correção sugerida (env indirection): passe a expressão via 'env:' e leia com "
            f"process.env no script — não interpole {expr} direto no JS. Ex.:\n"
            f"    env:\n      {var}: {expr}\n    with:\n      script: |\n"
            f"        const value = process.env.{var}"
        )
    return (
        "Correção sugerida (env indirection): mova a expressão para um bloco 'env:' do step e "
        f"referencie a variável entre aspas no run:. Ex.:\n    env:\n      {var}: {expr}\n"
        f'    run: |\n      echo "${var}"   # em vez de {expr}'
    )


def _containing_line(text: str, match: re.Match[str]) -> str:
    """A linha de ``text`` que contém ``match`` (o comando, não só a expressão)."""
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    return text[start : end if end != -1 else len(text)].strip()


def _anchor_line(wf: Workflow, command: str, fallback: str, cursor: int) -> int:
    """Linha do arquivo para um achado dentro de um texto executável.

    Ancora pelo COMANDO inteiro (``echo "${{ … }}"``), não só pela expressão: senão a mesma
    expressão usada corretamente num bloco ``env:`` anterior "rouba" a localização e o achado
    aponta para a própria mitigação. Se o comando não existe como linha do arquivo — plain
    scalar multi-linha, que o YAML dobra numa linha só —, cai para a expressão. O ``cursor``
    impede que N achados distintos colapsem todos na primeira ocorrência.
    """
    at = wf.find_line(command[:60], default=0, start=cursor)
    if at == 0:
        at = wf.find_line(fallback, default=cursor, start=cursor)
    return at


def check_script_injection(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    for step, env_map in _step_contexts(wf.data):
        for sink, text in _exec_texts(step):
            for match in _EXPR.finditer(text):
                resolved = _resolve_env_refs(match.group(0), env_map)
                hit = _untrusted_hit(resolved)
                if hit is None:
                    continue
                evidence = match.group(0).strip()
                at = _anchor_line(wf, _containing_line(text, match), evidence, cursor)
                cursor = at + 1
                out.append(
                    make_finding(
                        "script-injection",
                        wf.path,
                        at,
                        f"Contexto não-confiável interpolado: {hit}.",
                        evidence=evidence,
                        severity=_injection_severity(wf, hit),
                        fix_suggestion=_injection_fix(evidence, hit, in_js=sink == "github-script"),
                    )
                )
    return out


def _exec_lines(wf: Workflow) -> Iterator[tuple[str, str]]:
    """(sink, linha) de cada linha executável do workflow, na ordem do arquivo.

    Fronteira única de "onde há execução": reusa ``_exec_texts`` (``run:`` e o ``script:``
    do ``actions/github-script``), de modo que uma checagem nova não precise reimplementar
    a navegação por steps — e um sink novo passe a valer para todas de uma vez.
    """
    for step, _env in _step_contexts(wf.data):
        for sink, text in _exec_texts(step):
            for line in text.splitlines():
                yield sink, line


def check_secret_in_run(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    for sink, line in _exec_lines(wf):
        if not _secret_echo_leak(line, sink):
            continue
        stripped = line.strip()
        at = wf.find_line(stripped[:60], start=cursor) if stripped else cursor
        cursor = at + 1  # âncora: N vazamentos idênticos ⇒ N linhas distintas
        out.append(
            make_finding(
                "secret-in-run",
                wf.path,
                at,
                "Um segredo é impresso num comando que escreve no log do job.",
                evidence=stripped[:120],
            )
        )
    return out


# Redirecionamento de saída para ARQUIVO (`> path`, `>> "$GITHUB_ENV"`), distinto de
# duplicação de descritor (`2>&1`, `>&2`) e de redirecionamento de stderr (`2>/dev/null`,
# que NÃO impede o segredo de sair no stdout):
#  - `(?<![0-9&])` rejeita `2>`/`1>`/`>&`, ou seja, exige redirecionar o stdout;
#  - `[^\s&|;]` exige um alvo de arquivo real logo depois.
_REDIRECT_TO_FILE = re.compile(r"(?<![0-9&])>>?\s*[^\s&|;]")
# String literal do shell — apagada antes de procurar o redirecionamento, senão um `>`
# DENTRO do texto ecoado (`echo "==> publicando ${{ secrets.X }}"`) se disfarça de gravação
# em arquivo e engole o achado.
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
# Comandos que imprimem no log do job, por sink. No `run:` é o shell; no `github-script`
# a saída de console/@actions/core também vai para o log da Action.
_PRINT_COMMANDS: dict[str, tuple[str, ...]] = {
    "run": ("echo", "printf"),
    "github-script": ("console.log", "console.error", "console.warn", "core.info", "core.warning"),
}


def _secret_echo_leak(line: str, sink: str = "run") -> bool:
    lowered = line.lower()
    if not any(cmd in lowered for cmd in _PRINT_COMMANDS.get(sink, ())):
        return False
    if not any("secrets." in m.group(1) for m in _EXPR.finditer(line)):
        return False
    if sink != "run":
        return True  # no JS não há redirecionamento de shell: o valor vai para o log
    # Casos em que o segredo NÃO chega ao log da Action:
    #  - vai para o stdin do próximo comando (`--password-stdin` / `--with-token`);
    #  - o STDOUT é redirecionado para um ARQUIVO (`printf '%s' "${{secrets.KEY}}" > id_deploy`,
    #    `echo "${{secrets.X}}" >> "$GITHUB_ENV"`) — padrão canônico e seguro de instalar/
    #    exportar um segredo. O que vaza é o `echo`/`printf` SEM redirecionamento (stdout → log).
    if "--password-stdin" in lowered or "--with-token" in lowered:
        return False
    return not _REDIRECT_TO_FILE.search(_QUOTED.sub("''", line))


def check_curl_pipe(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    for sink, line in _exec_lines(wf):
        # Só o sink de shell: `curl | bash` não existe dentro do JS do github-script.
        if sink != "run" or not _CURL_PIPE.search(line):
            continue
        stripped = line.strip()
        at = wf.find_line(stripped[:60], start=cursor) if stripped else cursor
        cursor = at + 1
        out.append(
            make_finding(
                "curl-pipe-shell",
                wf.path,
                at,
                "Download da rede executado direto no shell.",
                evidence=stripped[:120],
            )
        )
    return out


def check_unpinned(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1  # avança pela ordem do arquivo p/ 'uses:' idênticos não colarem na 1ª linha
    for job in _jobs(wf.data):
        finding, cursor = _uses_finding(wf, job.get("uses"), cursor=cursor)  # reusable workflow
        if finding is not None:
            out.append(finding)
        for step in _steps_of(job):
            finding, cursor = _uses_finding(wf, step.get("uses"), cursor=cursor)
            if finding is not None:
                out.append(finding)
    data = wf.data
    runs = data.get("runs") if isinstance(data, dict) else None
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):  # composite action
        for step in runs["steps"]:
            if isinstance(step, dict):
                finding, cursor = _uses_finding(wf, step.get("uses"), cursor=cursor)
                if finding is not None:
                    out.append(finding)
    return out


def _action_ref(uses: Any) -> tuple[str, str] | None:
    """(action, ref) de um 'uses' de action REMOTA; None se local/docker/sem '@ref'.

    Classificador compartilhado de pinagem/owner: quem chama decide o que fazer com o par
    (ex.: `_SHA.match(ref)` para pinagem, `owner in _FIRST_PARTY` para 1ª parte).
    """
    if not isinstance(uses, str) or "@" not in uses:
        return None  # action local (sem @) ou valor inesperado
    if uses.startswith(("./", "../", "docker://")):
        return None
    action, _, ref = uses.rpartition("@")
    if not action or not ref:
        return None
    return action, ref


def _uses_finding(
    wf: Workflow, uses: Any, *, cursor: int = 1, line: int | None = None
) -> tuple[Finding | None, int]:
    parsed = _action_ref(uses)
    if parsed is None:
        return None, cursor
    action, ref = parsed
    if _SHA.match(ref):
        return None, cursor
    at = line if line is not None else wf.find_line(str(uses), start=cursor)
    if "/.github/workflows/" in action:
        # Reusable workflow: pinar por SHA é ideal, mas @branch dentro da org é comum/aceito.
        check = "unpinned-reusable-workflow"
        detail = f"reusable workflow '{action}' fixado por '{ref}' (não é SHA)."
    else:
        owner = action.split("/", 1)[0]
        first = owner in _FIRST_PARTY
        check = "unpinned-action-firstparty" if first else "unpinned-action-thirdparty"
        detail = f"'{action}' fixada por '{ref}' (não é SHA)."
    finding = make_finding(check, wf.path, at, detail, evidence=f"{action}@{ref}")
    return finding, at + 1


def _with_secret_ref(value: Any) -> str | None:
    """Retorna a expressão ${{ secrets.X }} / ${{ github.token }} de um valor de with:/env: (ou None).

    Só olha DENTRO de ${{ }} (reusa ``_EXPR``) — assim um literal 'secrets.foo' em texto solto
    não vira falso-positivo, só uma interpolação real de segredo.
    """
    if not isinstance(value, str):
        return None
    for match in _EXPR.finditer(value):
        if _SECRET_REF.search(match.group(1)):
            return match.group(0).strip()
    return None


def _first_secret_binding(mapping: dict[str, Any]) -> tuple[str, str] | None:
    """Primeiro par (chave, expressão-de-segredo) de um mapa with:/env: (ou None se nenhum)."""
    for key, value in mapping.items():
        secret = _with_secret_ref(value)
        if secret is not None:
            return str(key), secret
    return None


def check_secret_to_thirdparty(wf: Workflow) -> list[Finding]:
    """Segredo/GITHUB_TOKEN passado via with: a uma action de TERCEIROS não fixada por SHA.

    Reusa o classificador de owner/pinagem (`_action_ref` + `_FIRST_PARTY` + `_SHA`): action
    oficial (actions/*, github/*) recebendo o token é uso normal (github-script, checkout), e
    uma de terceiros fixada por SHA teve o código congelado/revisado — nenhuma alarma. O risco
    real é a de terceiros por tag/branch: a tag pode ser movida para código que exfiltra o
    segredo. Complementa 'unpinned-action-thirdparty' (que ignora se há segredo em jogo).

    O segredo chega à action por DOIS caminhos: ``with:`` (parâmetro da action) e o ``env:``
    EFETIVO do step (workflow + job + step) — que a action lê em ``process.env``. O padrão
    canônico do ``gitleaks-action`` entrega o ``GITHUB_TOKEN`` por ``env:``, não ``with:``; olhar
    só o ``with:`` deixava esse caso passar. Varre os dois, com ``with:`` primeiro para preservar
    a âncora/redação quando o segredo está lá.
    """
    out: list[Finding] = []
    cursor = 1
    for step, env_map in _step_contexts(wf.data):
        parsed = _action_ref(step.get("uses"))
        if parsed is None:
            continue
        action, ref = parsed
        if "/.github/workflows/" in action:
            continue  # reusable workflow recebe 'secrets:', não 'with:' — coberto à parte
        owner = action.split("/", 1)[0]
        if owner in _FIRST_PARTY or _SHA.match(ref):
            continue  # oficial, ou terceiro já fixado por SHA: passar o token é aceitável
        for source, mapping in (("with", step.get("with")), ("env", env_map)):
            if not isinstance(mapping, dict):
                continue
            binding = _first_secret_binding(mapping)
            if binding is None:
                continue
            key, secret = binding
            anchor = wf.find_line(f"{action}@{ref}", start=cursor)
            cursor = anchor + 1
            line = wf.find_line(secret, default=anchor, start=anchor)
            out.append(
                make_finding(
                    "secret-to-thirdparty-action",
                    wf.path,
                    line,
                    f"segredo ({secret}) passado via {source}.{key} para a action de terceiros "
                    f"'{action}' fixada por '{ref}' (não é SHA).",
                    evidence=secret,
                )
            )
            break  # um achado por step basta (with: tem prioridade sobre env:)
    return out


def check_secrets_inherit(wf: Workflow) -> list[Finding]:
    """Job que chama um reusable workflow com 'secrets: inherit' entrega todo o cofre."""
    data = wf.data
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return []
    out: list[Finding] = []
    cursor = 1
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str) and job.get("secrets") == "inherit":
            line = wf.find_line("inherit", start=cursor)
            cursor = line + 1
            out.append(
                make_finding(
                    "secrets-inherit",
                    wf.path,
                    line,
                    f"job '{name}' chama um reusable workflow com 'secrets: inherit' "
                    "(passa todo o cofre de segredos).",
                    evidence="secrets: inherit",
                )
            )
    return out


def check_unpinned_images(wf: Workflow) -> list[Finding]:
    """Imagens de contêiner (container:/services:/docker://) fixadas por tag, não por digest."""
    out: list[Finding] = []
    cursor = 1
    for job in _jobs(wf.data):
        for image in _job_images(job):
            if "@sha256:" in image:
                continue
            line = wf.find_line(image, start=cursor)
            cursor = line + 1
            out.append(
                make_finding(
                    "unpinned-container-image",
                    wf.path,
                    line,
                    f"imagem '{image}' fixada por tag (não por digest).",
                    evidence=image,
                )
            )
    for step, _env in _step_contexts(wf.data):
        uses = step.get("uses")
        if isinstance(uses, str) and uses.startswith("docker://") and "@sha256:" not in uses:
            line = wf.find_line(uses, start=cursor)
            cursor = line + 1
            out.append(
                make_finding(
                    "unpinned-container-image",
                    wf.path,
                    line,
                    f"imagem '{uses}' (docker://) fixada por tag (não por digest).",
                    evidence=uses,
                )
            )
    return out


# Valores de `upload-artifact.path` que publicam a raiz do workspace — e portanto o `.git`
# com a credencial que o checkout deixou lá.
_WORKSPACE_PATHS = frozenset(
    {".", "./", "${{ github.workspace }}", "${{github.workspace}}", "$GITHUB_WORKSPACE"}
)


def _publishes_workspace(with_: dict[str, Any]) -> bool:
    path = with_.get("path")
    if path is None:
        return True  # sem 'path' explícito, o padrão histórico é o diretório de trabalho
    entries = [line.strip() for line in str(path).splitlines() if line.strip()]
    return any(entry in _WORKSPACE_PATHS for entry in entries)


def check_checkout_credentials(wf: Workflow) -> list[Finding]:
    """Credencial deixada pelo checkout em `.git/config` e publicada via upload-artifact.

    Classe 'artipacked': `actions/checkout` grava o token em `.git/config`
    (`persist-credentials` é true por padrão); se um step POSTERIOR do mesmo job publica a
    raiz do workspace, o `.git` — e o token — vão dentro do artefato. Exige os dois lados
    (checkout sem a mitigação **e** upload abrangente depois dele) de propósito: sozinho, o
    checkout padrão é o de 99% dos workflows e alarmar nele seria só ruído.
    """
    out: list[Finding] = []
    cursor = 1
    for job in _jobs(wf.data):
        exposed_at: int | None = None
        for step in _steps_of(job):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            with_raw = step.get("with")
            with_: dict[str, Any] = with_raw if isinstance(with_raw, dict) else {}
            if uses.startswith("actions/checkout"):
                if with_.get("persist-credentials") is not False:
                    exposed_at = wf.find_line(uses, start=cursor)
                    cursor = exposed_at + 1
            elif (
                uses.startswith("actions/upload-artifact")
                and exposed_at is not None
                and _publishes_workspace(with_)
            ):
                out.append(
                    make_finding(
                        "checkout-credentials-in-artifact",
                        wf.path,
                        exposed_at,
                        "checkout sem 'persist-credentials: false' e, depois dele, um "
                        f"'{uses}' que publica a raiz do workspace (path="
                        f"{with_.get('path', '<ausente>')!r}): o .git/config com a credencial "
                        "vai dentro do artefato.",
                        evidence=uses,
                    )
                )
                exposed_at = None  # um achado por par checkout → upload
    return out


def _job_images(job: dict[str, Any]) -> list[str]:
    images: list[str] = []
    container = job.get("container")
    if isinstance(container, str):
        images.append(container)
    elif isinstance(container, dict) and isinstance(container.get("image"), str):
        images.append(container["image"])
    services = job.get("services")
    if isinstance(services, dict):
        for svc in services.values():
            if isinstance(svc, str):
                images.append(svc)
            elif isinstance(svc, dict) and isinstance(svc.get("image"), str):
                images.append(svc["image"])
    return images


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
            # Credita mitigações do mantenedor: persist-credentials:false + sparse-checkout de
            # caminho não-executável reduzem (não zeram) o risco → HIGH em vez de CRITICAL.
            mitigated = with_.get("persist-credentials") is False and "sparse-checkout" in with_
            detail = f"checkout do código do PR ({reason}) sob pull_request_target."
            severity = None
            if mitigated:
                severity = Severity.HIGH
                detail += (
                    " Mitigado (persist-credentials:false + sparse-checkout), mas ainda revise se o "
                    "código do PR chega a ser executado (ex.: build que roda conf.py/scripts)."
                )
            return (
                make_finding(
                    "pull-request-target-checkout",
                    wf.path,
                    line,
                    detail,
                    evidence=needle or reason,
                    severity=severity,
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

    cursor = 1
    found, cursor = _broad_permissions(wf, data.get("permissions"), "workflow", multi_job, cursor)
    out += found
    for name, job in jobs.items():
        if isinstance(job, dict) and "permissions" in job:
            found, cursor = _broad_permissions(
                wf, job.get("permissions"), f"job '{name}'", True, cursor
            )
            out += found

    # missing-permissions: só em workflows (não em arquivos de action, que têm 'runs' e não
    # têm 'permissions'), quando não há bloco no workflow E algum job herda o padrão.
    if "permissions" not in data and "runs" not in data:
        undeclared = [
            n for n, j in jobs.items() if not (isinstance(j, dict) and "permissions" in j)
        ]
        if not jobs or undeclared:
            alvo = ", ".join(str(n) for n in undeclared) if undeclared else "o workflow"
            # Reusable workflow (on: workflow_call) herda do CALLER, não do padrão da org.
            herda = (
                "herda as permissões do workflow que o chama (caller)"
                if "workflow_call" in trigger_names(data)
                else "herda o padrão da organização"
            )
            out.append(
                make_finding(
                    "missing-permissions",
                    wf.path,
                    1,
                    f"Sem bloco 'permissions'; {herda} em: {alvo}.",
                )
            )
    return out


def _broad_permissions(
    wf: Workflow, perms: Any, scope: str, multi_job: bool, cursor: int = 1
) -> tuple[list[Finding], int]:
    """Achados de permissão ampla + o cursor avançado.

    O cursor é o que faz cada bloco `permissions:` apontar para a SUA linha. Sem ele, os
    blocos de nível de job colavam todos na primeira linha do arquivo com `write-all` — e,
    como a supressão inline é decidida pela linha do achado, um único `# esteira: ignore`
    no bloco do workflow apagava também os achados dos jobs, que ninguém suprimiu.
    """
    if perms == "write-all":
        at = wf.find_line("write-all", start=cursor)
        return [
            make_finding(
                "broad-permissions",
                wf.path,
                at,
                f"permissions: write-all ({scope}).",
                evidence="write-all",
            )
        ], at + 1
    # Escopos de escrita específicos só são 'amplos' no nível do workflow com vários jobs
    # (todos herdam). Um write por-job (ou de workflow com um só job) é o mínimo recomendado.
    if isinstance(perms, dict) and scope == "workflow" and multi_job:
        writes = sorted((str(k) for k, v in perms.items() if v == "write"), key=str)
        if writes:
            at = wf.find_line("permissions", start=cursor)
            return [
                make_finding(
                    "broad-permissions",
                    wf.path,
                    at,
                    f"Escopos de escrita herdados por todos os jobs: {writes}.",
                    evidence=", ".join(writes),
                    severity=Severity.MEDIUM,
                )
            ], at + 1
    return [], cursor


def check_self_hosted(wf: Workflow) -> list[Finding]:
    # Só é chamada com o YAML parseado: quando ``wf.data is None``, ``run_all`` já retornou
    # pelo caminho de fallback (que chama ``_self_hosted_lines`` diretamente).
    out: list[Finding] = []
    cursor = 1
    for job in _jobs(wf.data):
        labels = _runs_on_labels_resolved(job)
        runs_on = job.get("runs-on")
        by_label = any("self-hosted" in str(label).lower() for label in labels)
        if by_label:
            at = wf.find_line("self-hosted", start=cursor)
            cursor = at + 1
            out.append(
                make_finding(
                    "self-hosted-runner",
                    wf.path,
                    at,
                    "Job roda em runner self-hosted.",
                    evidence="self-hosted",
                )
            )
        elif isinstance(runs_on, dict) and "group" in runs_on:
            group = str(runs_on["group"])
            at = wf.find_line("group", start=cursor)
            cursor = at + 1
            out.append(
                make_finding(
                    "self-hosted-runner",
                    wf.path,
                    at,
                    f"Job usa runner group '{group}' (grupos organizam runners self-hosted).",
                    evidence=f"group: {group}",
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
                evidence = match.group(0).strip()
                out.append(
                    make_finding(
                        "script-injection",
                        wf.path,
                        lineno,
                        f"Contexto não-confiável interpolado: {hit}.",
                        evidence=evidence,
                        # Fallback é por linha (só quando o YAML não parseia): sem árvore de
                        # steps para distinguir o sink, sugere-se o padrão de shell (run:).
                        fix_suggestion=_injection_fix(evidence, hit, in_js=False),
                    )
                )
                break
        uses_match = _USES_LINE.search(line)
        if uses_match is not None:
            finding, _ = _uses_finding(
                wf, f"{uses_match.group(1)}@{uses_match.group(2)}", line=lineno
            )
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
        # `_CURL_PIPE` exige POSIÇÃO DE COMANDO. No caminho estrutural o valor do `run:` já
        # chega isolado; aqui a linha é crua, e o prefixo `- run: ` empurraria o `curl` para
        # fora dessa posição — falso-negativo só por estarmos no fallback.
        if _CURL_PIPE.search(_RUN_KEY.sub("", line)):
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
