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
from esteira.core.redaction import evidence as evidencia

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
    # workflow_run carrega o PR associado; `pull_requests[i].head.ref`/`.head.label` é o nome da
    # branch do fork (texto livre do atacante), mesma classe de `github.head_ref`.
    re.compile(r"github\.event\.workflow_run\.pull_requests\[[0-9]+\]\.head\.(?:ref|label)"),
)
# `toJSON(...)` de um OBJETO do evento serializa os campos de texto livre que ele contém (título,
# corpo, mensagem de commit) — que, dentro de aspas no shell, quebram a string com um `'`/`"`. O
# objeto inteiro (github / github.event) e os subobjetos abaixo são não-confiáveis; um escalar
# seguro como `toJSON(github.event.pull_request.number)` NÃO casa, de propósito.
_TOJSON_UNTRUSTED = re.compile(
    r"tojson\(\s*github(?:\.event(?:\.(?:issue|pull_request|comment|review|review_comment"
    r"|discussion|head_commit|commits|workflow_run|pages|sender))?)?\s*\)"
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
# Interpretadores que executam o que recebem da rede: shells POSIX e também os runtimes
# script (python/node/ruby/perl) usados por instaladores reais (Poetry, nvm). `python3` antes
# de `python` porque `python\b` não casaria o `3`.
_INTERP = r"(?:bash|zsh|dash|sh|python3|python|nodejs|node|ruby|perl)"
_CURL = r"(?:curl|wget)"
# 1) Forma clássica com pipe: `curl … | bash` (ou | python3 -, | ruby, …), em posição de comando.
_CURL_PIPE = re.compile(
    _LEAD_CMD + _WRAPPERS + _CURL + r"\b[^\n]*\|&?\s*" + _WRAPPERS + r"(?:/\S*/)?" + _INTERP + r"\b"
)
# 2) Substituição de processo: `bash <(curl …)` — idioma do codecov, sem pipe mas mesmo efeito.
_CURL_PROCSUBST = re.compile(_INTERP + r"\b[^\n]*<\(\s*" + _WRAPPERS + _CURL + r"\b")
# 3) Substituição de comando: `sh -c "$(curl …)"` / `bash -c \`curl …\`` (Homebrew/oh-my-zsh).
_CURL_CMDSUBST = re.compile(_INTERP + r"\b[^\n]*\s-c\b[^\n]*(?:\$\(|`)[^\n]*" + _CURL + r"\b")
# 4) Equivalente PowerShell: `iwr … | iex` / `Invoke-WebRequest … | Invoke-Expression` (Chocolatey).
_IWR_IEX = re.compile(
    r"(?:iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)\b[^\n]*\|[^\n]*"
    r"\b(?:iex|invoke-expression)\b",
    re.IGNORECASE,
)
# Avaliadores POSIX que NÃO recebem código por stdin como um shell (`curl | bash`), mas rodam
# código da rede por outras formas — ficam fora de `_INTERP` de propósito e ganham padrões próprios.
# `source`/`.` executam um ARQUIVO/descritor; `eval` avalia uma STRING. Todos = CWE-494.
_SOURCE = r"(?:source|\.)"
# 5) `eval "$(curl …)"` / eval com backticks `eval \`wget …\``: a string avaliada vem da rede. O
# `[^`)\n]*` impede o match de atravessar o `)`/backtick de fechamento e casar um curl não-relacionado.
_EVAL_CURL = re.compile(_LEAD_CMD + r"eval\b[^\n]*?(?:\$\(|`)\s*[^`)\n]*?" + _CURL + r"\b")
# 6) Substituição de processo para o avaliador de source: `. <(curl …)` / `source <(wget …)`.
_SOURCE_PROCSUBST = re.compile(_LEAD_CMD + _SOURCE + r"\s+<\(\s*" + _WRAPPERS + _CURL + r"\b")
# 7) Forma pipada para o avaliador de source: `curl … | . /dev/stdin` / `wget … | source …`.
_CURL_PIPE_SOURCE = re.compile(
    _LEAD_CMD + _WRAPPERS + _CURL + r"\b[^\n]*\|&?\s*" + _WRAPPERS + _SOURCE + r"(?=\s|$)"
)


def _curl_pipe_hit(text: str) -> bool:
    """Download da rede executado direto por um interpretador, em qualquer das variantes reais:
    pipe (`curl|bash`), substituição de processo (`bash <(curl)`), de comando (`sh -c "$(curl)"`),
    o par PowerShell `iwr|iex`, ou os avaliadores POSIX `eval "$(curl)"` / `. <(curl)` / `curl | .`.
    Todas equivalem a rodar código não verificado da rede (CWE-494)."""
    return bool(
        _CURL_PIPE.search(text)
        or _CURL_PROCSUBST.search(text)
        or _CURL_CMDSUBST.search(text)
        or _IWR_IEX.search(text)
        or _EVAL_CURL.search(text)
        or _SOURCE_PROCSUBST.search(text)
        or _CURL_PIPE_SOURCE.search(text)
    )


# ref/repository de checkout que aponta para o código não-confiável do PR (não a base). Cobre
# o pull_request_target (head/number/merge_commit_sha) E o workflow_run, que tem os MESMOS
# privilégios e carrega o head do fork por outro caminho (head_sha/head_branch/pull_requests).
_PR_REF = re.compile(
    r"refs/pull/|github\.head_ref"
    r"|github\.event\.pull_request\.(?:head|number|merge_commit_sha)\b"
    r"|github\.event\.workflow_run\.(?:head_sha|head_branch)\b"
    r"|github\.event\.workflow_run\.pull_requests\b",
    re.IGNORECASE,
)
_FORK_REPO = re.compile(
    r"github\.event\.pull_request\.head\.repo"
    r"|github\.event\.workflow_run\.head_repository"
    r"|github\.head_ref",
    re.IGNORECASE,
)
# Checkout do código do PR via shell sob gatilho privilegiado (base.ref confiável NÃO casa).
# `git clone` do fork entra pela resolução de variável de ambiente (ver `_ppt_step_finding`),
# porque o repo/ref costumam chegar por `$REF`/`$REPO` vindos de um bloco `env:`.
_PR_CHECKOUT_RUN = re.compile(
    r"gh\s+pr\s+checkout"
    r"|git\s+fetch\b[^\n]*\bpull/\S+/(?:head|merge)"
    r"|git\s+fetch\b[^\n]*github\.event\.pull_request\.(?:head|number|merge_commit_sha)\b",
    re.IGNORECASE,
)
# `git clone`/`git fetch`/`git checkout` de um repositório/ref — o alvo (confiável ou fork) é
# decidido à parte, casando `_PR_REF`/`_FORK_REPO` na linha já com as variáveis de env expandidas.
_GIT_FETCH_CODE = re.compile(r"git\s+(?:clone|fetch|checkout|pull)\b", re.IGNORECASE)
# Referência a variável de shell (`$REF`, `${REPO}`) — para expandir a partir do `env:` do step.
_SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
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
# `esteira: ignore[regra-a, regra-b]` — captura a lista de regras da nossa própria diretiva de
# supressão escopada. A linha já vem em minúsculas quando é consultada.
_ESTEIRA_IGNORE_SCOPE = re.compile(r"esteira:\s*ignore\s*\[([^\]]*)\]")


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
    out += check_insecure_commands(wf)
    out += check_curl_pipe(wf)
    out += check_unpinned(wf)
    out += check_secret_to_thirdparty(wf)
    out += check_secrets_inherit(wf)
    out += check_unpinned_images(wf)
    out += check_checkout_credentials(wf)
    return [f for f in out if not _is_suppressed(wf, f)]


def _is_suppressed(wf: Workflow, finding: Finding) -> bool:
    """Respeita supressão inline '# zizmor: ignore' / '# esteira: ignore' na linha do achado.

    Três formas, em ordem de precedência:

    - `# esteira: ignore[regra-a, regra-b]` é ESCOPADA: só cala os achados cujo `check_id`
      está na lista. Sem isso, uma diretiva escrita para uma regra silenciaria em silêncio um
      achado sem relação na mesma linha (fail-open) — o pior comportamento para um mecanismo de
      supressão, porque esconde o defeito exatamente onde alguém já estava olhando.
    - `# esteira: ignore` (sem colchete) marca a linha inteira como revisada e cala qualquer
      achado nela — é a forma ampla, explícita, para quem revisou o ponto todo.
    - `# zizmor: ignore[...]` é honrada como "linha revisada pelo mantenedor". O espaço de nomes
      de regras do zizmor não é o nosso, então não há mapeamento confiável entre `[regra]` deles
      e o nosso `check_id`; tratamos a marca como declaração de revisão da linha. (Interop
      deliberada; o escopo por regra vale só para a nossa própria diretiva.)
    """
    lines = wf.lines
    index = finding.line - 1
    if not 0 <= index < len(lines):
        return False
    lowered = lines[index].lower()
    escopo = _ESTEIRA_IGNORE_SCOPE.search(lowered)
    if escopo is not None:
        regras = {r.strip() for r in escopo.group(1).split(",") if r.strip()}
        return finding.check_id.lower() in regras
    if "esteira: ignore" in lowered:
        return True
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


_ENV_FALSY = frozenset({"", "false", "0", "no", "off"})


def check_insecure_commands(wf: Workflow) -> list[Finding]:
    """`ACTIONS_ALLOW_UNSECURE_COMMANDS` reativa os comandos de workflow legados (`set-env`,
    `add-path` via stdout) — o vetor de CVE-2020-15228. Com ela ligada, qualquer saída que o
    atacante controle pode injetar variável de ambiente ou entrada de PATH e escalar para RCE.

    Anomaly-only: só dispara quando a variável está presente e com valor não-falso, no `env`
    do workflow, de um job ou de um step. Um workflow saudável nunca a define.
    """
    data = wf.data
    escopos: list[dict[str, Any]] = [_env_of(data)]
    for job in _jobs(data):
        escopos.append(_env_of(job))
        for step in _steps_of(job):
            escopos.append(_env_of(step))
    presente = any(
        str(chave).strip().upper() == "ACTIONS_ALLOW_UNSECURE_COMMANDS"
        and str(valor).strip().lower() not in _ENV_FALSY
        for env in escopos
        for chave, valor in env.items()
    )
    # Forma histórica (2020) de reativar os comandos legados sem tocar em `env:`: exportar a var
    # em runtime pelo arquivo $GITHUB_ENV (`echo "ACTIONS_ALLOW_UNSECURE_COMMANDS=true" >> $GITHUB_ENV`).
    # Ler só os mapas `env:` deixava esse vetor passar — a var acaba igualmente no ambiente do job.
    if not presente:
        presente = any(
            which == "ENV"
            and name == "actions_allow_unsecure_commands"
            and str(value).strip().lower() not in _ENV_FALSY
            for step, _env in _step_contexts(data)
            if isinstance(step.get("run"), str)
            for line in step["run"].splitlines()
            for which, name, value in _github_file_assignments(line)
        )
    if not presente:
        return []
    at = wf.find_line("ACTIONS_ALLOW_UNSECURE_COMMANDS")
    return [
        make_finding(
            "insecure-commands",
            wf.path,
            at,
            "O workflow define ACTIONS_ALLOW_UNSECURE_COMMANDS, que reativa os comandos "
            "inseguros 'set-env'/'add-path' (CVE-2020-15228) e abre injeção de ambiente/PATH.",
            evidence="ACTIONS_ALLOW_UNSECURE_COMMANDS",
        )
    ]


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


# Funcoes/operadores cujo RESULTADO e booleano (true/false), nao o texto de entrada. Um
# contexto nao-confiavel dentro deles nao e injetavel (o output e um bool), e um segredo dentro
# deles nao vaza o VALOR (vaza so "true"/"false"). Classes FP 18 (script-injection) e 30
# (secret-in-run): `${{ contains(github.event.title, 'x') }}` e `${{ secrets.K != '' }}`.
_BOOL_FUNCS = (
    "contains(",
    "startswith(",
    "endswith(",
    "always(",
    "success(",
    "failure(",
    "cancelled(",
)
_COMPARACAO = re.compile(r"==|!=|<=|>=|(?<![<>=!])[<>](?![=])")


def _expr_resulta_booleano(inner: str) -> bool:
    """O conteudo de um `${{ ... }}` avalia para um BOOLEANO (comparacao ou funcao booleana
    envolvendo tudo)? Entao nao carrega o texto/segredo de entrada para a saida."""
    s = inner.strip().lower()
    if _COMPARACAO.search(s):
        return True
    return s.endswith(")") and any(s.startswith(fn) for fn in _BOOL_FUNCS)


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
    tojson = _TOJSON_UNTRUSTED.search(normalized)
    if tojson is not None:
        return tojson.group(0)
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


# Inputs de action de terceiros cujo valor é executado como SHELL (remoto ou local): o texto
# interpolado ali é reinterpretado por um shell, exatamente como um `run:`. `appleboy/ssh-action`
# usa `script`, `azure/cli` usa `inlineScript`, várias usam `command`/`cmd`/`run`. Só vale para
# action de TERCEIROS (a de 1ª parte com `script` é o github-script, tratado à parte).
_SHELL_INPUTS = frozenset(
    {"script", "inlinescript", "inline_script", "command", "commands", "cmd", "run"}
)


def _exec_texts(step: dict[str, Any]) -> list[tuple[str, str]]:
    """(sink, texto) executados onde ${{ }} é interpolado.

    ``sink`` é ``"run"`` (shell), ``"github-script"`` (JS) ou ``"action-shell"`` (input de shell
    de action de terceiros) — a correção sugerida difere: ``"$VAR"`` no shell/action-shell,
    ``process.env.VAR`` no JS. Só ``run``/``github-script`` são varridos por segredo/curl; o
    ``action-shell`` alimenta apenas a injeção (não sabemos o dialeto exato do shell remoto).
    """
    texts: list[tuple[str, str]] = []
    run = step.get("run")
    if isinstance(run, str):
        texts.append(("run", run))
    uses = step.get("uses")
    if not isinstance(uses, str):
        return texts
    if uses.startswith("actions/github-script"):
        with_ = step.get("with")
        script = with_.get("script") if isinstance(with_, dict) else None
        if isinstance(script, str):
            texts.append(("github-script", script))
        return texts
    parsed = _action_ref(uses)
    if (
        parsed is not None
        and "/.github/workflows/" not in parsed[0]
        and parsed[0].split("/", 1)[0] not in _FIRST_PARTY
    ):
        with_ = step.get("with")
        if isinstance(with_, dict):
            for key, value in with_.items():
                if isinstance(value, str) and str(key).strip().lower() in _SHELL_INPUTS:
                    texts.append(("action-shell", value))
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


# --------------------------------------------------------------------------- #
# taint: contexto não-confiável que chega ao sink por um DESVIO (output de step/job, env
# dinâmica via $GITHUB_ENV, valor de matriz). A fronteira é a MESMA de sempre — só o texto cru
# do atacante injeta; um valor SANITIZADO por caminho ($(… | tr -c 'a-z' …)) NÃO propaga taint,
# que é o que separa p11/p12 (cru) do benigno c21 (filtrado) no corpus.
# --------------------------------------------------------------------------- #

# Escrita `name=value` para o arquivo $GITHUB_ENV / $GITHUB_OUTPUT.
_GHFILE = re.compile(r"\$\{?GITHUB_(ENV|OUTPUT)\}?")
# Substituição de comando `$( … )` / `` ` … ` `` (nível único). NÃO é sanitizador por si só: só
# neutraliza o taint quando o pipeline dentro dela contém um filtro allowlist REAL (`_SANITIZER`).
# Identidade (`$(echo "$T")`) e truncamento (`| head`/`| cut`/`| awk '{print $1}'`) preservam o
# texto do atacante — o valor continua cru.
_CMD_SUBST = re.compile(r"\$\([^()]*\)|`[^`]*`")
# Filtros que trocam o texto não-confiável por uma saída de charset/estrutura controlada — aí sim o
# valor deixa de ser cru: `tr -c`/`tr -d` (complemento/deleção de charset), `sed 's/[^…]//'`
# (apaga fora de um conjunto), `printf %q` (quoting), `jq -r` (extrai campo estruturado), `base64`
# (encode), `sha*sum`/`shasum` (digest), `grep -o…`/`-E…-o` (só o trecho casado por regex fixa).
_SANITIZER = re.compile(
    r"\btr\s+-\S*[cd]"
    r"|\bsed\b[^|`)]*s/\[\^"
    r"|\bprintf\b[^|`)]*%q"
    r"|\bjq\b[^|`)]*(?:^|\s)-r\b"
    r"|\bbase64\b"
    r"|\bsha(?:1|224|256|384|512)?sum\b|\bshasum\b"
    r"|\bgrep\b[^|`)]*-\S*o",
    re.IGNORECASE,
)
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)=(.*)$", re.DOTALL)
_ECHO_PREFIX = re.compile(r"^\s*(?:echo|printf)\b\s*(?:-[eEnr]+\s+)?(?:'%s(?:\\n)?'\s+)?", re.I)


def _tainted_env_vars(env_map: dict[str, Any]) -> set[str]:
    """Nomes de variáveis do `env:` efetivo cujo valor carrega contexto não-confiável (`$T` onde
    `T: ${{ github.event.* }}`)."""
    return {
        str(name).lower()
        for name, value in env_map.items()
        if isinstance(value, str) and _untrusted_hit(_resolve_env_refs(value, env_map))
    }


def _value_carries_taint(value: str, tainted_vars: set[str], env_map: dict[str, Any]) -> bool:
    # Apaga uma substituição de comando SÓ quando ela sanitiza de verdade (filtro allowlist). Sem
    # filtro, o `$( … )` é identidade/truncamento: preservamos o conteúdo para o taint ser visto lá
    # dentro (`$(echo "$T")` continua carregando `$T`; `${{ github.event.* }}` cru continua cru).
    v = _CMD_SUBST.sub(lambda m: "" if _SANITIZER.search(m.group(0)) else m.group(0), value)
    if _untrusted_hit(_resolve_env_refs(v, env_map)):
        return True
    return any(
        re.search(r"\$\{?" + re.escape(var) + r"(?![A-Za-z0-9_])", v, re.IGNORECASE)
        for var in tainted_vars
    )


def _github_file_assignments(line: str) -> list[tuple[str, str, str]]:
    """(alvo, nome, valor) para cada `echo "nome=valor" >> $GITHUB_ENV|OUTPUT` da linha."""
    m = _GHFILE.search(line)
    if m is None:
        return []
    before = line[: m.start()]
    redirs = list(re.finditer(r">>?", before))
    content = before[: redirs[-1].start()] if redirs else before
    content = _ECHO_PREFIX.sub("", content).strip()
    if len(content) >= 2 and content[0] in "\"'" and content[-1] == content[0]:
        content = content[1:-1]
    assign = _ASSIGN.match(content)
    if assign is None:
        return []
    return [(m.group(1), assign.group(1).lower(), assign.group(2))]


def _step_output_taint(job: dict[str, Any], workflow_env: dict[str, Any]) -> dict[str, set[str]]:
    """{id_do_step: {nomes de output com taint}} — output cru derivado de contexto não-confiável."""
    job_env = {**workflow_env, **_env_of(job)}
    result: dict[str, set[str]] = {}
    for step in _steps_of(job):
        sid = step.get("id")
        run = step.get("run")
        if not isinstance(sid, str) or not isinstance(run, str):
            continue
        env_map = {**job_env, **_env_of(step)}
        tainted_vars = _tainted_env_vars(env_map)
        names = {
            name
            for line in run.splitlines()
            for which, name, value in _github_file_assignments(line)
            if which == "OUTPUT" and _value_carries_taint(value, tainted_vars, env_map)
        }
        if names:
            result[sid.lower()] = names
    return result


def _job_output_taint(
    job: dict[str, Any], step_out: dict[str, set[str]], workflow_env: dict[str, Any]
) -> set[str]:
    outputs = job.get("outputs")
    if not isinstance(outputs, dict):
        return set()
    job_env = {**workflow_env, **_env_of(job)}
    tainted: set[str] = set()
    for oname, value in outputs.items():
        if not isinstance(value, str):
            continue
        norm = _normalize_brackets(value).lower()
        if _untrusted_hit(_resolve_env_refs(value, job_env)):
            tainted.add(str(oname).lower())
            continue
        for sid, onames in step_out.items():
            if any(f"steps.{sid}.outputs.{on}" in norm for on in onames):
                tainted.add(str(oname).lower())
    return tainted


def _update_runtime_env_taint(
    step: dict[str, Any], env_map: dict[str, Any], runtime_tainted: set[str]
) -> None:
    """Acumula os nomes exportados para $GITHUB_ENV com valor cru não-confiável — visíveis como
    `${{ env.NOME }}` nos steps SEGUINTES do job (a env dinâmica que `_resolve_env_refs` não vê)."""
    run = step.get("run")
    if not isinstance(run, str):
        return
    tainted_vars = _tainted_env_vars(env_map)
    for line in run.splitlines():
        for which, name, value in _github_file_assignments(line):
            if which == "ENV" and _value_carries_taint(value, tainted_vars, env_map):
                runtime_tainted.add(name)


def _taint_hit(inner: str, taint_ctx: Any, env_map: dict[str, Any]) -> str | None:
    """Contexto não-confiável alcançado por desvio (output/env-dinâmica/matriz) na expressão."""
    if taint_ctx is None:
        return None
    job, step_out, job_out_taint, runtime_tainted = taint_ctx
    norm = _normalize_brackets(inner).lower()
    m = re.search(r"steps\.([\w-]+)\.outputs\.([\w-]+)", norm)
    if m is not None and m.group(2) in step_out.get(m.group(1), set()):
        return m.group(0)
    m = re.search(r"needs\.([\w-]+)\.outputs\.([\w-]+)", norm)
    if m is not None and m.group(2) in job_out_taint.get(m.group(1), set()):
        return m.group(0)
    m = re.search(r"(?<![\w.])env\.([\w-]+)", norm)
    if m is not None and m.group(1) in runtime_tainted:
        return m.group(0)
    m = re.search(r"(?<![\w.])matrix\.([\w-]+)", norm)
    if m is not None and any(_untrusted_hit(v) for v in _matrix_values(job, m.group(1))):
        return m.group(0)
    return None


def _scan_step_injection(
    wf: Workflow,
    out: list[Finding],
    step: dict[str, Any],
    env_map: dict[str, Any],
    cursor: int,
    taint_ctx: Any,
) -> int:
    for sink, text in _exec_texts(step):
        for match in _EXPR.finditer(text):
            resolved = _resolve_env_refs(match.group(0), env_map)
            hit = _untrusted_hit(resolved) or _taint_hit(match.group(1), taint_ctx, env_map)
            if hit is None:
                continue
            if _expr_resulta_booleano(match.group(1)):
                continue  # ${{ contains(...) }} / comparacao: resultado booleano, nao injetavel
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
    return cursor


def check_script_injection(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    data = wf.data
    workflow_env = _env_of(data)
    jobs_map = data.get("jobs") if isinstance(data, dict) else None
    jobs_map = jobs_map if isinstance(jobs_map, dict) else {}
    valid_jobs = {str(n).lower(): j for n, j in jobs_map.items() if isinstance(j, dict)}
    step_out_by_job = {n: _step_output_taint(j, workflow_env) for n, j in valid_jobs.items()}
    job_out_taint = {
        n: _job_output_taint(j, step_out_by_job[n], workflow_env) for n, j in valid_jobs.items()
    }
    for name, job in valid_jobs.items():
        job_env = {**workflow_env, **_env_of(job)}
        runtime_tainted: set[str] = set()
        taint_ctx = (job, step_out_by_job[name], job_out_taint, runtime_tainted)
        for step in _steps_of(job):
            env_map = {**job_env, **_env_of(step)}
            cursor = _scan_step_injection(wf, out, step, env_map, cursor, taint_ctx)
            _update_runtime_env_taint(step, env_map, runtime_tainted)
    # Composite action (runs.steps): sem contexto de job/needs/matriz — só o taint direto.
    runs = data.get("runs") if isinstance(data, dict) else None
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        for step in runs["steps"]:
            if isinstance(step, dict):
                env_map = {**workflow_env, **_env_of(step)}
                cursor = _scan_step_injection(wf, out, step, env_map, cursor, None)
    return out


def _exec_lines(wf: Workflow) -> Iterator[tuple[str, str, str]]:
    """(sink, shell, linha) de cada linha executável do workflow, na ordem do arquivo.

    Fronteira única de "onde há execução": reusa ``_exec_texts`` (``run:`` e o ``script:``
    do ``actions/github-script``), de modo que uma checagem nova não precise reimplementar
    a navegação por steps — e um sink novo passe a valer para todas de uma vez. O ``shell`` é o
    do step (bash|pwsh|python), que decide qual comando imprime no stdout.
    """
    for step, _env in _step_contexts(wf.data):
        shell = _step_shell(step)
        for sink, text in _exec_texts(step):
            for line in text.splitlines():
                yield sink, shell, line


def check_secret_in_run(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    for sink, shell, line in _exec_lines(wf):
        vazamento = _secret_echo_leak(line, sink, shell)
        if vazamento is None:
            continue
        stripped = line.strip()
        at = wf.find_line(stripped[:60], start=cursor) if stripped else cursor
        cursor = at + 1  # âncora: N vazamentos idênticos ⇒ N linhas distintas
        out.append(_secret_finding(wf.path, at, vazamento, stripped))
    out += _secret_heredoc_leaks(wf, cursor)
    out += _secret_file_then_artifact(wf, cursor)
    return out


# O texto tem de descrever o risco QUE EXISTE em cada caso. Dizer "vai para o log" sobre um
# `echo … >> $GITHUB_ENV` está errado em dois níveis — o `>>` grava em ARQUIVO e o GitHub
# mascara segredo no log — e um cliente que confere a afirmação, vê que não se sustenta e
# descarta o achado leva junto o risco real, que ali é a propagação para os steps seguintes.
_DETALHE_VAZAMENTO: dict[str, str] = {
    "log": "Um segredo é impresso no stdout do step e vai para o log do job.",
    "github-env": (
        "Segredo exportado para $GITHUB_ENV: ele passa a existir no ambiente de TODOS os "
        "steps seguintes do job, inclusive actions de terceiros — que recebem o process.env "
        "inteiro, sem precisar declarar nada."
    ),
    "artifact": (
        "Um segredo é gravado em arquivo e, depois, um step publica esse arquivo como artefato "
        "(upload-artifact): o valor fica baixável por qualquer um com acesso aos artefatos do "
        "repositório. Gravar em disco não protege se o disco é publicado."
    ),
}
# Exportar para o ambiente não expõe o valor fora do job: é escopo largo demais, não vazamento
# público. Rebaixar para Média é o que mantém o achado crível — e o `--fail-on high` do
# cliente continua reprovando pelo caso que de fato manda o segredo para fora.
_SEVERIDADE_VAZAMENTO: dict[str, Severity] = {"github-env": Severity.MEDIUM}


def _secret_finding(path: str, at: int, vazamento: str, linha: str) -> Finding:
    return make_finding(
        "secret-in-run",
        path,
        at,
        _DETALHE_VAZAMENTO[vazamento],
        evidence=evidencia(linha),
        severity=_SEVERIDADE_VAZAMENTO.get(vazamento),
    )


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
# Fronteira entre COMANDOS de uma mesma linha de shell. `||` antes de `|` (a alternância do
# `re` é preguiçosa e casaria o pipe sozinho, partindo o `||` em dois). `&` isolado ficou de
# fora de propósito: aparece em `2>&1`/`>&2`, onde não separa comando nenhum.
_SEPARADOR_DE_COMANDO = re.compile(r"\|\||&&|[;|]")
# `$GITHUB_ENV` em qualquer das grafias que o shell aceita como alvo do redirecionamento.
_GITHUB_ENV = re.compile(r"\$\{?GITHUB_ENV\}?")
# Alvos de redirecionamento que são dispositivos de terminal/console: escrever neles é ir ao LOG
# do job — NÃO gravar um "arquivo seguro". Cobre /dev/stderr|stdout, /dev/fd/{1,2} e
# /proc/{self,PID}/fd/{1,2}. As duplicações de descritor `>&1`/`>&2` já caem no ramo de log porque
# `_REDIRECT_TO_FILE` não casa `>&` (o `&` seguinte é rejeitado pelo `[^\s&|;]`).
_LOG_DEVICE = re.compile(r"^(?:/dev/(?:stderr|stdout|fd/[12])|/proc/(?:self|[0-9]+)/fd/[12])$")
# Re-emissores puros: copiam o stdin de volta ao stdout. `tee` SEMPRE (e ainda grava no arquivo);
# `cat`/`tac`/`nl`/`rev` quando NÃO redirecionam a saída a um arquivo. Um `| jq`/`| base64 -d`/
# `| gpg` transforma ou CONSOME o segredo — não o reimprime cru (é o que preserva a classe FP 17).
_REEMIT_CMD = re.compile(r"^\s*(?:sudo\s+|command\s+)*(cat|tac|nl|rev|tee)\b", re.IGNORECASE)
# Comandos que imprimem no stdout — o segredo vai para o log do job. O `run:` depende do SHELL do
# step: `echo`/`printf` no bash, `Write-Host`/`Write-Output` no pwsh, `print(...)` no python. Um
# `echo` do bash não imprime nada num step `shell: python`, e um `print` do python não é comando
# de bash — por isso o conjunto é por shell, com fronteira de palavra (`\bprint\b` não casa
# `fingerprint`). O `github-script` roda JS, onde console/@actions/core também vão ao log.
_RUN_PRINT_RE: dict[str, re.Pattern[str]] = {
    "bash": re.compile(r"\b(?:echo|printf)\b", re.IGNORECASE),
    "pwsh": re.compile(
        r"\b(?:echo|write-host|write-output|write-error|write-warning|out-host)\b", re.IGNORECASE
    ),
    "python": re.compile(r"\bprint\b", re.IGNORECASE),
}
_JS_PRINT_RE = re.compile(r"console\.(?:log|error|warn)|core\.(?:info|warning)", re.IGNORECASE)


def _step_shell(step: dict[str, Any]) -> str:
    """Normaliza `shell:` do step para a família cujo comando de impressão vale: bash|pwsh|python."""
    sh = step.get("shell")
    if isinstance(sh, str):
        s = sh.strip().lower()
        if s.startswith("python"):
            return "python"
        if s in ("pwsh", "powershell"):
            return "pwsh"
    return "bash"  # bash/sh/cmd e o padrão do runner: echo/printf


def _neutraliza_aspas(line: str) -> str:
    """Mesma linha com o CONTEÚDO das aspas trocado por ``x``, PRESERVANDO os índices.

    Separador de comando e seta de redirecionamento dentro de string literal não separam nem
    redirecionam nada (``echo "a|b ==> c"``). Trocar por texto de mesmo comprimento — em vez de
    apagar — deixa as posições do original e da versão neutra alinhadas, que é o que permite
    procurar a estrutura aqui e ler a evidência lá.
    """
    return _QUOTED.sub(lambda m: m.group(0)[0] + "x" * (len(m.group(0)) - 2) + m.group(0)[0], line)


def _segmento(neutro: str, pos: int) -> tuple[int, int]:
    """(início, fim) do comando que contém ``pos``, delimitado por ``;`` ``|`` ``||`` ``&&``."""
    inicio, fim = 0, len(neutro)
    for sep in _SEPARADOR_DE_COMANDO.finditer(neutro):
        if sep.end() <= pos:
            inicio = sep.end()
        elif sep.start() >= pos:
            fim = sep.start()
            break
    return inicio, fim


def _pipeline_reemite_ao_log(neutro: str, pipe_pos: int) -> bool:
    """A cauda do pipeline a partir de ``pipe_pos`` (um ``|``) reimprime o stdin no stdout/log?

    Verdadeiro se ALGUM estágio: chama ``tee`` (copia p/ o stdout, com ou sem arquivo); é um
    re-emissor puro (``cat``/``tac``/``nl``/``rev``) SEM redirecionar a arquivo; ou redireciona a
    um dispositivo de log (``> /dev/stderr``). Falso para ``| jq``/``| base64 -d > f``/``| gpg``
    (FP 17): transformam ou consomem o segredo em vez de o reemitir cru.
    """
    tail = neutro[pipe_pos:]
    term = re.search(r";|&&|\|\|", tail)  # a cauda vai até o próximo terminador de comando
    if term is not None:
        tail = tail[: term.start()]
    for stage in tail.split("|"):
        if not stage.strip():
            continue
        alvo = _REDIRECT_TARGET.search(stage)
        if alvo is not None and _LOG_DEVICE.match(alvo.group(1).strip("\"'")):
            return True
        m = _REEMIT_CMD.match(stage)
        if m is None:
            continue
        if m.group(1).lower() == "tee":
            return True  # tee sempre copia para o stdout, mesmo com arquivo
        if _REDIRECT_TO_FILE.search(stage) is None:
            return True  # cat/tac/nl/rev SEM arquivo de destino imprime no stdout/log
    return False


def _heredoc_vai_ao_log(neutro: str) -> bool:
    """O corpo de um heredoc cujo cabeçalho (neutralizado) é ``neutro`` chega ao stdout/log?

    Sim quando: não há redirecionamento e não há pipe; há redirect a um dispositivo de log
    (``cat <<EOF > /dev/stderr``); ou a cauda do pipeline reemite (``cat <<EOF | tee …``). Não
    quando o cabeçalho manda o corpo a um arquivo comum (``> resumo.md``, ``>> $GITHUB_STEP_SUMMARY``)
    ou o pipa a um consumidor que não reemite.
    """
    redir = _REDIRECT_TO_FILE.search(neutro)
    if redir is not None:
        alvo = _REDIRECT_TARGET.search(neutro[redir.start() :])
        return alvo is not None and _LOG_DEVICE.match(alvo.group(1).strip("\"'")) is not None
    pipe = re.search(r"\|(?!\|)", neutro)
    if pipe is not None:
        return _pipeline_reemite_ao_log(neutro, pipe.start())
    return True


def _secret_echo_leak(line: str, sink: str = "run", shell: str = "bash") -> str | None:
    """Classifica o vazamento da linha: ``"log"``, ``"github-env"`` ou ``None``.

    A checagem exige que o comando de impressão e o segredo estejam no MESMO comando. Sem
    isso, "existe echo na linha" + "existe ${{ secrets }} na linha" bastava — e o idioma mais
    banal de pipeline de matriz virava falso-positivo:

        [ -n "${{ secrets.OPENAI_API_KEY }}" ] || { echo "::warning::não configurado"; exit 0; }

    Medido no fork `iac-scanner`: 2 de 2 achados de `secret-in-run` eram desta forma, com o
    `echo` imprimindo o NOME da variável e nunca o valor. Enquanto isso, a linha seguinte —
    `echo "K=${{ secrets.X }}" >> $GITHUB_ENV`, que é onde há risco — ficava calada.
    """
    lowered = line.lower()
    if sink == "github-script":
        # No JS não há redirecionamento de shell: o valor vai direto para o log da Action.
        if not _JS_PRINT_RE.search(lowered):
            return None
        return "log" if any("secrets." in m.group(1) for m in _EXPR.finditer(line)) else None
    if sink != "run":
        return None  # sink sem semântica de impressão de stdout (ex.: action-shell)
    print_re = _RUN_PRINT_RE.get(shell, _RUN_PRINT_RE["bash"])
    if not print_re.search(lowered):
        return None
    # Segredo entregue pelo STDIN do próximo comando não passa pelo stdout em momento nenhum.
    if "--password-stdin" in lowered or "--with-token" in lowered:
        return None
    neutro = _neutraliza_aspas(line)
    for expr in _EXPR.finditer(line):
        if "secrets." not in expr.group(1):
            continue
        if _expr_resulta_booleano(expr.group(1)):
            continue  # `secrets.K != ''` imprime true/false, nao o segredo (FP 30)
        inicio, fim = _segmento(neutro, expr.start())
        if not print_re.search(lowered[inicio : expr.start()]):
            continue  # o `echo` desta linha está em OUTRO comando: não é ele que imprime
        if "::add-mask::" in lowered[inicio:fim]:
            continue  # `echo "::add-mask::${{ secrets.X }}"` MASCARA o segredo (FP 16), nao vaza
        redirecionamento = _REDIRECT_TO_FILE.search(neutro, expr.end(), fim)
        if redirecionamento is None:
            # stdout do echo PIPADO. Só é seguro se o consumidor NÃO reemite o stdin ao log
            # (`base64 -d > f`, `gpg`, `jq` — FP 17). Se a cauda reemite (`| tee`, `| cat`, ou um
            # redirect a dispositivo de log), o segredo vai para o log tal qual um echo cru.
            if fim < len(neutro) and neutro[fim] == "|" and neutro[fim : fim + 2] != "||":
                if _pipeline_reemite_ao_log(neutro, fim):
                    return "log"
                continue
            return "log"
        if _GITHUB_ENV.search(line[redirecionamento.start() : fim]):
            return "github-env"
        # Redirect a dispositivo de terminal/console (`> /dev/stderr`, `> /proc/self/fd/1`) é LOG,
        # não arquivo seguro. Arquivo comum (`printf … > id_deploy`) é o idioma canônico de instalar
        # o segredo em disco (FP 28): segue para a próxima expressão (pode haver outro segredo).
        alvo = _REDIRECT_TARGET.search(line[redirecionamento.start() : fim])
        if alvo is not None and _LOG_DEVICE.match(alvo.group(1).strip("\"'")):
            return "log"
    return None


_HEREDOC_START = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def _line_has_secret(line: str) -> bool:
    return any(
        "secrets." in e.group(1) and not _expr_resulta_booleano(e.group(1))
        for e in _EXPR.finditer(line)
    )


def _secret_heredoc_leaks(wf: Workflow, cursor: int) -> list[Finding]:
    """Segredo no CORPO de um heredoc que sai pelo stdout (`cat <<EOF … EOF`, sem redirecionar).

    O caminho linha-a-linha não pega isto: o `cat`/`<<EOF` está numa linha e o segredo em OUTRA
    (o corpo). `cat` de heredoc SEM `> arquivo` nem pipe imprime o corpo no log do job — o mesmo
    vazamento de um `echo`. Se o cabeçalho manda o corpo a um arquivo comum (`cat <<EOF >> "$GITHUB_
    STEP_SUMMARY"`) ou o pipa a um consumidor que não reemite, o corpo não vai ao log (classe FP 11);
    mas `| tee`, `| cat` ou `> /dev/stderr` reemitem ao log e continuam sendo vazamento (`_heredoc_
    vai_ao_log`)."""
    out: list[Finding] = []
    for step, _env in _step_contexts(wf.data):
        if _step_shell(step) != "bash":
            continue  # heredoc é idioma POSIX/bash
        run = step.get("run")
        if not isinstance(run, str):
            continue
        lines = run.splitlines()
        i = 0
        while i < len(lines):
            header = _HEREDOC_START.search(lines[i])
            if header is None:
                i += 1
                continue
            delim = header.group(2)
            neutro = _neutraliza_aspas(lines[i])
            to_stdout = _heredoc_vai_ao_log(neutro)
            j = i + 1
            while j < len(lines) and lines[j].strip() != delim:
                if to_stdout and _line_has_secret(lines[j]):
                    at = wf.find_line(lines[j].strip()[:60], start=cursor)
                    cursor = at + 1
                    out.append(_secret_finding(wf.path, at, "log", lines[j].strip()))
                    to_stdout = False  # um achado por heredoc basta
                j += 1
            i = j + 1
    return out


# Alvo de redirecionamento (`> arquivo`) que NÃO é um arquivo especial do runner.
_REDIRECT_TARGET = re.compile(r">>?\s*([^\s&|;<>]+)")


def _secret_file_target(line: str) -> str | None:
    """Caminho de arquivo para onde a linha grava um segredo (ou None). Exclui os arquivos
    especiais do runner ($GITHUB_ENV/$GITHUB_OUTPUT/$GITHUB_*), que têm semântica própria."""
    if not _line_has_secret(line):
        return None
    neutro = _neutraliza_aspas(line)
    redir = _REDIRECT_TO_FILE.search(neutro)
    if redir is None:
        return None
    alvo = _REDIRECT_TARGET.search(line[redir.start() :])
    if alvo is None:
        return None
    target = alvo.group(1).strip("\"'")
    if "GITHUB_" in target.upper():
        return None
    return target


def _artifact_covers(with_: dict[str, Any], secret_path: str) -> bool:
    """O upload-artifact publica o arquivo de segredo? (raiz do workspace, ou o caminho exato)."""
    if _publishes_workspace(with_):
        return not secret_path.startswith(("/", "~"))  # arquivo relativo dentro do workspace
    entries = [
        line.strip().strip("\"'")
        for line in str(with_.get("path", "")).splitlines()
        if line.strip()
    ]
    return secret_path in entries


def _secret_file_then_artifact(wf: Workflow, cursor: int) -> list[Finding]:
    """Segredo gravado em arquivo e, depois, publicado como artefato — exfiltração equivalente ao
    log. Gravar em disco é 'seguro' isolado (classe FP 28, sem upload), mas o `upload-artifact`
    do MESMO arquivo (ou da raiz do workspace) entrega o segredo a quem baixar o artefato."""
    out: list[Finding] = []
    for job in _jobs(wf.data):
        secret_files: dict[str, int] = {}
        for step in _steps_of(job):
            run = step.get("run")
            if isinstance(run, str):
                for line in run.splitlines():
                    target = _secret_file_target(line)
                    if target is not None and target not in secret_files:
                        secret_files[target] = wf.find_line(line.strip()[:60], start=cursor)
            uses = step.get("uses")
            if (
                isinstance(uses, str)
                and uses.startswith("actions/upload-artifact")
                and secret_files
            ):
                with_raw = step.get("with")
                with_ = with_raw if isinstance(with_raw, dict) else {}
                for path, at in list(secret_files.items()):
                    if _artifact_covers(with_, path):
                        out.append(_secret_finding(wf.path, at, "artifact", path))
                secret_files = {}  # consumidos por este upload
    return out


def check_curl_pipe(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    cursor = 1
    for sink, _shell, line in _exec_lines(wf):
        # Só o sink de shell: `curl | bash` não existe dentro do JS do github-script.
        if sink != "run" or not _curl_pipe_hit(line):
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
                evidence=evidencia(stripped),
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
    out += _reusable_secret_to_thirdparty(wf, cursor)
    return out


def _reusable_secret_to_thirdparty(wf: Workflow, cursor: int) -> list[Finding]:
    """Reusable workflow de OUTRA org, por @branch/@tag, recebendo segredo explícito via `secrets:`.

    O `check_secret_to_thirdparty` pula o reusable ('coberto à parte'), mas o único que cobre o
    reusable inteiro é `secrets-inherit` — e ELE só vê a palavra `inherit`. Um `secrets:` com mapa
    explícito (`DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}`) para `outra-org/…@main` entrega o
    segredo a código de terceiros que uma branch móvel pode trocar: a MESMA classe de
    secret-to-thirdparty, por outro canal. Primeira parte / fixado por SHA não alarmam (revisado)."""
    data = wf.data
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return []
    out: list[Finding] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        parsed = _action_ref(job.get("uses"))
        if parsed is None or "/.github/workflows/" not in parsed[0]:
            continue
        action, ref = parsed
        if action.split("/", 1)[0] in _FIRST_PARTY or _SHA.match(ref):
            continue
        secrets = job.get("secrets")
        if not isinstance(secrets, dict):
            continue  # 'inherit' (string) fica com check_secrets_inherit
        binding = _first_secret_binding(secrets)
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
                f"segredo ({secret}) passado via secrets.{key} para o reusable workflow de "
                f"terceiros '{action}' fixado por '{ref}' (não é SHA).",
                evidence=secret,
            )
        )
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


_MATRIX_ONLY = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")


def _resolve_matrix_image(job: dict[str, Any], image: str) -> list[str] | None:
    """Se ``image`` é exatamente ``${{ matrix.X }}``, os valores estáticos daquele eixo da
    matriz (axis + include). ``None`` quando não é uma referência de matriz resolvível — aí o
    chamador mantém o comportamento padrão (imagem tratada como tag)."""
    m = _MATRIX_ONLY.fullmatch(image.strip())
    if m is None:
        return None
    return _matrix_values(job, m.group(1)) or None


def check_unpinned_images(wf: Workflow) -> list[Finding]:
    """Imagens de contêiner (container:/services:/docker://) fixadas por tag, não por digest."""
    out: list[Finding] = []
    cursor = 1
    for job in _jobs(wf.data):
        for image in _job_images(job):
            if "@sha256:" in image:
                continue
            resolved = _resolve_matrix_image(job, image)
            # Imagem vinda de `${{ matrix.X }}` cujos valores são TODOS fixados por digest: a
            # imagem efetiva já está pinada em cada célula da matriz — resolver estaticamente
            # evita acusar a expressão como se fosse uma tag móvel (classe FP 35).
            if resolved is not None and all("@sha256:" in v for v in resolved):
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


def _persist_credentials_disabled(value: Any) -> bool:
    """`persist-credentials` desligado? O runner entrega todo `with:` como STRING; o
    `actions/checkout` lê o input com `core.getBooleanInput`, que aceita `false`/`False`/`FALSE`
    (e por extensão as grafias falsy usuais) tanto quanto o booleano YAML `false`. Tratar só o
    booleano `False` como desligado (e a string `'false'` como ligado) inverte a semântica real
    e acusa um checkout que de fato NÃO persiste a credencial (classe FP 19)."""
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _ENV_FALSY
    return False


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
                if not _persist_credentials_disabled(with_.get("persist-credentials")):
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


# Gatilhos que rodam no contexto do repositório-base — com segredos e token de escrita — mas
# podem receber o head do fork. Fazer checkout/clonar/buscar esse head sob QUALQUER um deles é
# executar código não-confiável com privilégio; a gaiola do `pull_request_target` valia igual
# para o `workflow_run` (mesmos privilégios) e para o `issue_comment` (ChatOps que dá checkout).
_PRIVILEGED_CHECKOUT_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")


def check_ppt_checkout(wf: Workflow) -> list[Finding]:
    names = trigger_names(wf.data or {})
    presentes = [t for t in _PRIVILEGED_CHECKOUT_TRIGGERS if t in names]
    if not presentes:
        return []
    gatilho = presentes[0]
    out: list[Finding] = []
    cursor = 1
    workflow_env = _env_of(wf.data)
    for job in _jobs(wf.data):
        job_env = {**workflow_env, **_env_of(job)}
        for step in _steps_of(job):
            env_map = {**job_env, **_env_of(step)}
            finding, cursor = _ppt_step_finding(wf, step, env_map, cursor, gatilho)
            if finding is not None:
                out.append(finding)
    return out


def _expand_shell_vars(text: str, env_map: dict[str, Any]) -> str:
    """Substitui `$VAR`/`${VAR}` pelo valor de env do step (uma passada, sem recursão de shell).

    O checkout do fork por `git clone`/`git fetch` costuma parametrizar o repo/ref por variáveis
    de ambiente (`REF: ${{ github.event.pull_request.head.ref }}` → `git clone … "$REF"`). Trazer
    o valor de volta para a linha deixa `_PR_REF`/`_FORK_REPO` reconhecerem o alvo não-confiável —
    sem isso, o `$REF` opaco esconde o clone do fork."""

    def repl(match: re.Match[str]) -> str:
        value = env_map.get(match.group(1))
        return str(value) if isinstance(value, str) else match.group(0)

    return _SHELL_VAR.sub(repl, text)


def _ppt_step_finding(
    wf: Workflow, step: dict[str, Any], env_map: dict[str, Any], cursor: int, gatilho: str
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
            mitigated = (
                _persist_credentials_disabled(with_.get("persist-credentials"))
                and "sparse-checkout" in with_
            )
            detail = f"checkout do código do PR ({reason}) sob {gatilho}."
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
            expandido = _normalize_brackets(_expand_shell_vars(line_text, env_map))
            # `gh pr checkout` / `git fetch pull/*` casam direto; `git clone`/`git fetch`/`git
            # checkout` de um alvo que — após expandir as variáveis de env — aponta para o
            # head/repo do fork é o mesmo risco por outra sintaxe (classe: buscar código do PR).
            fetches_pr_code = _PR_CHECKOUT_RUN.search(expandido) or (
                _GIT_FETCH_CODE.search(expandido)
                and (_PR_REF.search(expandido) or _FORK_REPO.search(expandido))
            )
            if fetches_pr_code:
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
                        "checkout do código do PR via shell (gh pr checkout / git fetch pull / "
                        f"git clone do fork) sob {gatilho}.",
                        evidence=evidencia(line_text),
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
    # 08: o write de nivel de workflow so e "amplo" se ALGUM job herda. Se todo job declara
    # seu proprio bloco permissions:, nenhum herda os escopos do workflow -> nao e achado.
    algum_job_herda = (not jobs) or any(
        not (isinstance(j, dict) and "permissions" in j) for j in jobs.values()
    )
    found, cursor = _broad_permissions(
        wf, data.get("permissions"), "workflow", multi_job, cursor, herdado=algum_job_herda
    )
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
    wf: Workflow, perms: Any, scope: str, multi_job: bool, cursor: int = 1, *, herdado: bool = True
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
    if isinstance(perms, dict) and scope == "workflow" and multi_job and herdado:
        writes = sorted((str(k) for k, v in perms.items() if v == "write"), key=str)
        if writes:
            linha_do_bloco = wf.find_line("permissions", start=cursor)
            # 34: ancorar na linha do ESCOPO de escrita (onde o mantenedor escreve o
            # `# zizmor: ignore`, como em campo), nao na linha do `permissions:` — senao a
            # supressao inline do usuario e ignorada. Cai de volta na linha do bloco se nao achar.
            at = wf.find_line(f"{writes[0]}", start=linha_do_bloco)
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
        elif (
            isinstance(runs_on, dict)
            and "group" in runs_on
            and not _grupo_parece_github_hosted(str(runs_on["group"]))
        ):
            # `runs-on: group: X` nao implica self-hosted: os larger runners GITHUB-HOSTED
            # tambem usam grupos (ex.: `ubuntu-runners`). So sinalizamos quando o nome do grupo
            # NAO carrega um token de SO GitHub-hosted — um grupo de hardware/on-prem
            # (`amd-mi300-1gpu`, `on-prem`) segue apontado; `ubuntu-runners` nao (FP 20).
            group = str(runs_on["group"])
            at = wf.find_line("group", start=cursor)
            cursor = at + 1
            out.append(
                make_finding(
                    "self-hosted-runner",
                    wf.path,
                    at,
                    f"Job usa runner group '{group}' (grupos costumam organizar runners self-hosted; "
                    "confirme se nao e um grupo de larger runners GitHub-hosted).",
                    evidence=f"group: {group}",
                )
            )
    return out


_GH_HOSTED_GROUP_HINTS = ("ubuntu", "windows", "macos", "linux")


def _grupo_parece_github_hosted(group: str) -> bool:
    """Nome de runner group com token de SO GitHub-hosted (larger runner), nao self-hosted."""
    g = group.lower()
    return any(h in g for h in _GH_HOSTED_GROUP_HINTS)


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
        vazamento = _secret_echo_leak(line)
        if vazamento is not None:
            # Mesmo texto do caminho estrutural: o cliente não pode receber duas descrições
            # diferentes do mesmo risco só porque o YAML dele não parseou.
            out.append(_secret_finding(wf.path, lineno, vazamento, line))
        # `_CURL_PIPE` exige POSIÇÃO DE COMANDO. No caminho estrutural o valor do `run:` já
        # chega isolado; aqui a linha é crua, e o prefixo `- run: ` empurraria o `curl` para
        # fora dessa posição — falso-negativo só por estarmos no fallback.
        if _curl_pipe_hit(_RUN_KEY.sub("", line)):
            out.append(
                make_finding(
                    "curl-pipe-shell",
                    wf.path,
                    lineno,
                    "Download da rede executado direto no shell.",
                    evidence=evidencia(line),
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
