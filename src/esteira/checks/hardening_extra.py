"""CAP C — endurecimento estático adicional (offline).

Dois detectores que trabalham só sobre a árvore YAML já carregada (nunca tocam a rede), na
mesma doutrina do resto da suíte — detecção estática, "inconclusivo não é ausência":

* ``cache-poisoning`` — par escrita↔restauração da MESMA chave de cache entre jobs/steps. Uma
  chave escrita num contexto MENOS confiável (um run de ``pull_request``) e restaurada num
  contexto confiável (``push``/deploy) deixa um run pouco privilegiado envenenar o artefato que
  o build/deploy consome. O sinal é a ASSIMETRIA de confiança entre quem escreve e quem lê a
  mesma chave — não um fluxo de dados —, por isso este detector raciocina sobre gatilhos + `if:`
  e não sobre o grafo de taint (que mede outra coisa: texto do atacante chegando a um sink).

* ``falsifiable-actor-condition`` — ``if:`` que decide privilégio por ``github.actor ==
  'dependabot[bot]'`` (ou outro bot). O ``actor`` é o quem-disparou-o-run, não uma autenticação
  robusta do autor do PR (muda em re-runs e em ``workflow_run``): apoiar auto-merge/deploy nele
  é confiar num input falsificável como se fosse controle de acesso.

Posicionamento honesto (2026): não competimos em motor ATIVO nem em contagem de regras. O ganho
aqui é confirmação READ-ONLY/offline, baixo-FP com discriminadores explícitos (chave estável vs.
chave por-run; assimetria de contexto; ``==`` que CONCEDE confiança ao bot, não o ``!=`` que o
exclui) e remediação em PT-BR.

Este módulo é DISJUNTO do resto: expõe ``CATALOG_ENTRIES`` e se auto-registra no ``CATALOG`` no
fim do arquivo; expõe ``check_cache_poisoning`` / ``check_falsifiable_actor`` para o integrador
plugar em ``run_all``. Os imports de helpers de ``detectors`` são LAZY (dentro das funções) de
propósito: ``detectors`` importará este módulo para chamar as checagens, então um import de topo
para ``detectors`` fecharia um ciclo — no momento em que ``run_all`` chama estas funções,
``detectors`` já está totalmente carregado.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from esteira.checks.catalog import CATALOG, CheckMeta, make_finding
from esteira.core.loader import trigger_names
from esteira.core.models import Finding, Severity, Workflow

CATALOG_ENTRIES: list[CheckMeta] = [
    CheckMeta(
        "cache-poisoning",
        "Cache envenenável: chave escrita em contexto não-confiável e restaurada em confiável",
        Severity.HIGH,
        "Separe o escopo do cache por confiança: inclua na 'key' um componente que só o contexto "
        "confiável produz (ex.: '${{ github.ref_name }}' de um branch protegido) OU não restaure "
        "num job privilegiado uma chave que um run de PR possa escrever. O GitHub isola caches de "
        "PRs de fork, então o vetor de maior confiança é 'pull_request_target'/'workflow_run' e "
        "PRs de branch do mesmo repositório; 'restore-keys' agravam por casarem por prefixo. "
        "Detecção estática/offline.",
        "A03:2025 Software Supply Chain Failures",
        "CWE-349",
    ),
    CheckMeta(
        "falsifiable-actor-condition",
        "Porta de segurança apoiada em github.actor (falsificável)",
        Severity.MEDIUM,
        "Não decida privilégio (auto-merge/auto-approve/deploy) por 'if: github.actor == ...': o "
        "'actor' é o ator que disparou o run, não uma autenticação robusta do autor — muda em "
        "re-runs e em 'workflow_run'. Use os controles nativos do GitHub (proteção de branch, "
        "required reviews, environments com revisores) e, para triar PR de bot, verifique "
        "'github.event.pull_request.user.login'. Detecção estática/offline.",
        "A01:2025 Broken Access Control",
        "CWE-807",
    ),
]


# --------------------------------------------------------------------------- #
# navegação estrutural (mesma forma que _jobs/_steps_of de detectors, porém preservando o NOME
# do job, que os achados citam — e sem depender de símbolos privados de detectors no import)
# --------------------------------------------------------------------------- #


def _iter_jobs(data: dict[str, Any] | None) -> Iterator[tuple[str, dict[str, Any]]]:
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, dict):
        return
    for name, job in jobs.items():
        if isinstance(job, dict):
            yield str(name), job


def _iter_steps(job: dict[str, Any]) -> Iterator[dict[str, Any]]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for step in steps:
        if isinstance(step, dict):
            yield step


# --------------------------------------------------------------------------- #
# (1) cache-poisoning
# --------------------------------------------------------------------------- #

# Referências das actions de cache oficiais e o papel de cada uma. `actions/cache` faz as duas
# coisas (restaura no início, salva no fim); `save`/`restore` são os subcomandos separados.
_CACHE_REFS: dict[str, str] = {
    "actions/cache": "both",
    "actions/cache/save": "write",
    "actions/cache/restore": "restore",
    # Drop-in de terceiros com a MESMA interface (`key`/`restore-keys`) e a mesma classe de
    # risco de envenenamento. Curado para manter o FP baixo (só compatíveis 1:1 com o oficial).
    "buildjet/cache": "both",
    "buildjet/cache/save": "write",
    "buildjet/cache/restore": "restore",
}

# Eventos em que um run é MENOS confiável: o conteúdo pode vir de um PR. (No `pull_request` de
# fork o GitHub isola o cache; a recomendação nomeia os vetores de maior confiança.)
_UNTRUSTED_EVENTS = frozenset({"pull_request", "pull_request_target"})

# Tokens que tornam a 'key' ÚNICA por run/commit: se a chave os contém, o run que escreve e o
# que restaura calculam chaves DIFERENTES, então não há colisão para envenenar — não é achado.
# `hashFiles(...)` NÃO entra aqui de propósito: é baseado em conteúdo e colide entre contextos.
_RUN_UNIQUE_TOKENS: tuple[str, ...] = (
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.run_attempt",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.number",
    "github.event.number",
    "github.head_ref",
    # Discriminadores de CONTEXTO (não de run): diferem entre o run não-confiável (PR:
    # 'refs/pull/N/merge') e o confiável (push: 'refs/heads/main'), então a chave não colide
    # entre os dois — não há o que envenenar. `github.ref` é prefixo de `github.ref_name`, mas
    # ambos ficam listados por clareza. É exatamente o que a nossa própria remediação recomenda.
    "github.ref_name",
    "github.ref",
)

_EVENT_EQ = re.compile(r"github\.event_name\s*==\s*['\"]([a-z_]+)['\"]", re.IGNORECASE)
_EVENT_EQ_REV = re.compile(r"['\"]([a-z_]+)['\"]\s*==\s*github\.event_name", re.IGNORECASE)
_EVENT_NE = re.compile(r"github\.event_name\s*!=\s*['\"]([a-z_]+)['\"]", re.IGNORECASE)
_EVENT_NE_REV = re.compile(r"['\"]([a-z_]+)['\"]\s*!=\s*github\.event_name", re.IGNORECASE)
_USES_LINE = re.compile(r"uses:\s*(\S+)")


@dataclass
class _CacheOp:
    """Uma operação de cache localizada: papel, chave, prefixos, eventos alcançáveis e linha."""

    kind: str  # "write" | "restore" | "both"
    key: str | None
    restore_keys: list[str]
    reachable: frozenset[str]
    uses: str
    job_name: str
    line: int


def _cache_ref_kind(uses: str) -> str | None:
    ref = uses.split("@", 1)[0].strip().rstrip("/").lower()
    return _CACHE_REFS.get(ref)


def _restore_keys(value: Any) -> list[str]:
    if isinstance(value, str):
        return [ln.strip() for ln in value.splitlines() if ln.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _reachable_events(events: set[str], gates: list[Any]) -> frozenset[str]:
    """Eventos sob os quais uma op pode rodar: os gatilhos do workflow restringidos pelos `if:`.

    `github.event_name == 'x'` (em qualquer ordem, inclusive num `||` que forma uma lista de
    permitidos) intersecta com {x…}; `!= 'x'` remove x. Gates de `ref`/branch são ignorados de
    propósito — não mudam a CLASSE de confiança do evento e ignorá-los é o lado conservador."""
    from esteira.checks.detectors import _normalize_brackets

    reachable = set(events)
    for gate in gates:
        if not isinstance(gate, str) or not gate.strip():
            continue
        norm = _normalize_brackets(gate).lower()
        # `||` com um termo NÃO-evento (ex.: `event_name=='push' || actor=='renovate[bot]'`): o
        # gate pode ser satisfeito pela via não-evento sob QUALQUER evento, então a restrição por
        # `event_name`==/!= não é garantida — não a aplicamos (lado conservador: mantém a
        # alcançabilidade ampla e evita FN de contexto). Uma disjunção SÓ de eventos continua
        # tratada como allowlist (união dos `==`), como antes.
        parts = norm.split("||")
        if len(parts) > 1 and any("github.event_name" not in p for p in parts):
            continue
        required = set(_EVENT_EQ.findall(norm)) | set(_EVENT_EQ_REV.findall(norm))
        if required:
            reachable &= required
        for ev in _EVENT_NE.findall(norm) + _EVENT_NE_REV.findall(norm):
            reachable.discard(ev)
    return frozenset(reachable)


def _cache_use_lines(wf: Workflow) -> list[int]:
    """Linhas (1-based) das `uses:` de action de cache, em ordem de documento."""
    nums: list[int] = []
    for i, line in enumerate(wf.lines, start=1):
        m = _USES_LINE.search(line)
        if m is not None and _cache_ref_kind(m.group(1).strip("'\"")) is not None:
            nums.append(i)
    return nums


def _assign_lines(wf: Workflow, ops: list[_CacheOp]) -> None:
    """Casa cada op (ordem de documento) com a linha `uses:` correspondente (mesma ordem).

    Quando as contagens divergem — um `uses:` de cache num comentário, um job não-mapa —, cai
    para uma âncora textual com cursor monotônico, para dois achados não colapsarem na mesma linha.
    """
    nums = _cache_use_lines(wf)
    if len(nums) == len(ops):
        for op, n in zip(ops, nums, strict=True):
            op.line = n
        return
    cursor = 1
    for op in ops:
        at = wf.find_line(op.uses, default=cursor, start=cursor)
        op.line = at
        cursor = at + 1


def _collect_cache_ops(wf: Workflow) -> list[_CacheOp]:
    data = wf.data
    events = trigger_names(data) if isinstance(data, dict) else set()
    ops: list[_CacheOp] = []
    for jname, job in _iter_jobs(data):
        job_if = job.get("if")
        for step in _iter_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            kind = _cache_ref_kind(uses)
            if kind is None:
                continue
            with_ = step.get("with")
            key: str | None = None
            restore_keys: list[str] = []
            if isinstance(with_, dict):
                raw_key = with_.get("key")
                if isinstance(raw_key, str):
                    key = raw_key
                restore_keys = _restore_keys(with_.get("restore-keys"))
            reachable = _reachable_events(events, [job_if, step.get("if")])
            ops.append(_CacheOp(kind, key, restore_keys, reachable, uses, jname, 0))
    _assign_lines(wf, ops)
    return ops


def _norm_key(key: str) -> str:
    """Chave normalizada para comparação: espaços removidos (variam só dentro de ${{ … }})."""
    return re.sub(r"\s+", "", key)


def _key_run_unique(key: str) -> bool:
    from esteira.checks.detectors import _normalize_brackets

    norm = _normalize_brackets(key).lower()
    return any(tok in norm for tok in _RUN_UNIQUE_TOKENS)


def _keys_match(write_key: str, restore_key: str | None, restore_prefixes: list[str]) -> bool:
    nw = _norm_key(write_key)
    if restore_key is not None and _norm_key(restore_key) == nw:
        return True
    return any(nw.startswith(_norm_key(p)) for p in restore_prefixes if _norm_key(p))


def _cache_finding(wf: Workflow, write: _CacheOp, restore: _CacheOp, key: str) -> Finding:
    untrusted = "/".join(sorted(write.reachable & _UNTRUSTED_EVENTS))
    trusted = "/".join(sorted(restore.reachable - _UNTRUSTED_EVENTS))
    detail = (
        f"Chave de cache '{key.strip()}' escrita em contexto não-confiável (job "
        f"'{write.job_name}', evento {untrusted}) e restaurada em contexto confiável (job "
        f"'{restore.job_name}', evento {trusted}, linha {restore.line}): um run menos "
        "privilegiado pode envenenar o artefato que o build/deploy consome."
    )
    fix = (
        f"Inclua na 'key' um componente exclusivo do contexto confiável (ex.: "
        f"'${{{{ github.ref_name }}}}' de um branch protegido) ou remova a restauração dessa "
        f"chave do job '{restore.job_name}'."
    )
    return make_finding(
        "cache-poisoning",
        wf.path,
        write.line,
        detail,
        evidence=key.strip(),
        fix_suggestion=fix,
    )


def check_cache_poisoning(wf: Workflow) -> list[Finding]:
    """Achado quando a MESMA chave de cache é escrita num contexto não-confiável e restaurada
    num confiável, com contextos ASSIMÉTRICOS (evidência de separação deliberada por gatilho/`if`)
    e chave que colide entre os dois contextos (estável, não por-run)."""
    if not isinstance(wf.data, dict):
        return []
    ops = _collect_cache_ops(wf)
    out: list[Finding] = []
    seen: set[tuple[int, int, str]] = set()
    for write in ops:
        if write.kind not in ("write", "both") or write.key is None:
            continue
        if not (write.reachable & _UNTRUSTED_EVENTS):
            continue
        if _key_run_unique(write.key):
            continue
        for restore in ops:
            if restore is write or restore.kind not in ("restore", "both"):
                continue
            if not (restore.reachable - _UNTRUSTED_EVENTS):
                continue
            # Contextos idênticos = padrão simétrico benigno (restore+save no mesmo escopo de
            # gatilho); só a ASSIMETRIA indica escrita-num-contexto / leitura-noutro.
            if write.reachable == restore.reachable:
                continue
            if not _keys_match(write.key, restore.key, restore.restore_keys):
                continue
            pair = (write.line, restore.line, _norm_key(write.key))
            if pair in seen:
                continue
            seen.add(pair)
            out.append(_cache_finding(wf, write, restore, write.key))
    return out


# --------------------------------------------------------------------------- #
# (2) falsifiable-actor-condition
# --------------------------------------------------------------------------- #

# Logins de bot que aparecem como porta de `if:`. `[bot]` é o marcador canônico de conta de bot.
_KNOWN_BOTS = frozenset(
    {
        "dependabot",
        "dependabot[bot]",
        "dependabot-preview[bot]",
        "renovate",
        "renovate[bot]",
        "github-actions",
        "github-actions[bot]",
    }
)

# Campos que carregam a IDENTIDADE do ator e NÃO autenticam o autor de forma robusta (o login
# muda em re-runs / 'workflow_run' e é falsificável como controle). Inclui `sender.login` do
# payload; NÃO inclui `pull_request.user.login` (o autor real do PR — a alternativa ROBUSTA que
# a própria remediação recomenda), para não gerar FP no campo certo.
_ACTOR_FIELD = r"(?:github\.(?:triggering_)?actor|github\.event\.sender\.login)"

_ACTOR_LEFT = re.compile(
    rf"{_ACTOR_FIELD}\s*(?P<op>==|!=)\s*(?P<q>['\"])(?P<val>[^'\"]*)(?P=q)",
    re.IGNORECASE,
)
_ACTOR_RIGHT = re.compile(
    rf"(?P<q>['\"])(?P<val>[^'\"]*)(?P=q)\s*(?P<op>==|!=)\s*{_ACTOR_FIELD}",
    re.IGNORECASE,
)
# Forma de FUNÇÃO: contains/startsWith/endsWith(<ator>, '<bot>') concede a um login de bot
# falsificável o mesmo privilégio que `==`.
_ACTOR_FUNC = re.compile(
    rf"(?:contains|startswith|endswith)\(\s*{_ACTOR_FIELD}\s*,\s*(?P<q>['\"])(?P<val>[^'\"]*)(?P=q)\s*\)",
    re.IGNORECASE,
)
# Allowlist de atores: contains(fromJSON('[...]'), <ator>) decide privilégio por uma lista de
# logins (todos falsificáveis).
_ACTOR_FROMJSON = re.compile(
    rf"contains\(\s*fromjson\([^)]*\)\s*,\s*{_ACTOR_FIELD}\s*\)",
    re.IGNORECASE,
)


def _is_bot_login(value: str) -> bool:
    # Casamento EXATO (login em `_KNOWN_BOTS`) ou sufixo canônico `[bot]`. Sem `substring`
    # solta: `"dependabot" in v` acusava um humano chamado 'my-dependabot-helper' como bot
    # falsificável (FP). O login real do bot é sempre 'dependabot[bot]'/'renovate[bot]' — que
    # casam por sufixo — ou o bare 'dependabot'/'renovate' que já está em `_KNOWN_BOTS`.
    v = value.strip().strip("'\"").lower()
    return v.endswith("[bot]") or v in _KNOWN_BOTS


def _negated_before(text: str, start: int) -> bool:
    """A expressão que começa em `start` está sob negação `!`?

    Cobre `!contains(actor, 'x')` (o `!` colado no token) e `!(github.actor == 'x')` (o `!`
    antes do parêntese que ENVOLVE a expressão) — ambos EXCLUEM o ator (direção segura). O `!=`
    não passa por aqui (é tratado pelo grupo `op`).
    """
    pre = text[:start].rstrip()
    if pre.endswith("!"):
        return True
    if pre.endswith("("):
        return pre[:-1].rstrip().endswith("!")
    return False


def _actor_bot_gate(if_text: str) -> str | None:
    """Se o `if:` CONCEDE confiança a uma identidade de ator falsificável, devolve o login/rótulo.

    Concede via ``==`` e via `contains/startsWith/endsWith(<ator>, '<bot>')` e a allowlist
    `contains(fromJSON([...]), <ator>)`. NÃO conta o ``!=`` nem uma negação envolvente `!(...)`
    (EXCLUEM o ator — direção segura/comum, FP baixo). `github.event.sender.login` conta como
    ator; `github.event.pull_request.user.login` (autor real do PR) NÃO. Aceita ordem invertida
    e a forma `github['actor']`.
    """
    from esteira.checks.detectors import _normalize_brackets

    norm = _normalize_brackets(if_text)
    # (a) igualdade direta com um login de bot
    for rx in (_ACTOR_LEFT, _ACTOR_RIGHT):
        for m in rx.finditer(norm):
            if (
                m.group("op") == "=="
                and _is_bot_login(m.group("val"))
                and not _negated_before(norm, m.start())
            ):
                return m.group("val")
    # (b) contains/startsWith/endsWith(<ator>, '<bot>')
    for m in _ACTOR_FUNC.finditer(norm):
        if _is_bot_login(m.group("val")) and not _negated_before(norm, m.start()):
            return m.group("val")
    # (c) allowlist de atores via fromJSON
    for m in _ACTOR_FROMJSON.finditer(norm):
        if not _negated_before(norm, m.start()):
            return "allowlist de atores (fromJSON)"
    return None


def _emit_actor(wf: Workflow, out: list[Finding], if_value: Any, scope: str, cursor: int) -> int:
    if not isinstance(if_value, str):
        return cursor
    bot = _actor_bot_gate(if_value)
    if bot is None:
        return cursor
    at = wf.find_line(bot, default=cursor, start=cursor)
    out.append(
        make_finding(
            "falsifiable-actor-condition",
            wf.path,
            at,
            f"Condição de {scope} concede privilégio a uma identidade de ator falsificável "
            f"('{bot}') — o ator não autentica de forma robusta o autor (muda em "
            "re-runs/'workflow_run' e o login é falsificável), então não serve de controle de "
            "segurança.",
            evidence=if_value.strip(),
            fix_suggestion=(
                "Troque a decisão de privilégio por controle nativo (proteção de branch / "
                "environment com revisor) e, para triar PR de bot, use "
                "'github.event.pull_request.user.login'."
            ),
        )
    )
    return at + 1


def check_falsifiable_actor(wf: Workflow) -> list[Finding]:
    """Achado para `if:` de job ou step que usa `github.actor == '<bot>'` como porta de segurança."""
    if not isinstance(wf.data, dict):
        return []
    out: list[Finding] = []
    cursor = 1
    for jname, job in _iter_jobs(wf.data):
        cursor = _emit_actor(wf, out, job.get("if"), f"job '{jname}'", cursor)
        for step in _iter_steps(job):
            cursor = _emit_actor(wf, out, step.get("if"), f"step de '{jname}'", cursor)
    return out


# Auto-registro no catálogo: uma checagem nova nasce declarada (título/severidade/OWASP/CWE)
# sem editar catalog.py. `setdefault` não sobrescreve um id já existente.
for _m in CATALOG_ENTRIES:
    CATALOG.setdefault(_m.id, _m)
