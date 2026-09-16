"""Invariantes de CLASSE (property-based) dos três detectores estáticos novos (salto 17→22).

`ai_workflow`, `hardening_extra` e `compromised_actions` somam ~1.100 linhas e, até aqui, só
tinham testes POR EXEMPLO — cada um checando o token que alguém digitou. Esta rede gera milhares
de entradas de cada família e afirma a propriedade de FP/FN que não pode falhar nunca:

* **compromised-action:** offline, um `uses:` só é achado SE e SÓ SE a raiz `owner/action` está no
  snapshot E o `@ref` (case-insensitive, subpath normalizado) é um dos refs comprometidos. Nem um
  ref seguro da mesma action, nem uma action fora da lista, geram achado (o eixo de baixo-FP).
* **ai-agent (Regra de Dois):** sem gatilho não-confiável (leg 1) não há achado, haja o que houver
  de agente/canal; sob `pull_request` de fork o achado nunca sobe para ALTA (o token é retido);
  um `if:` de autor confiável (author_association) neutraliza o job; toda severidade emitida é
  ALTA ou MÉDIA, nunca outra.
* **cache-poisoning / falsifiable-actor:** chave por-run (`github.sha`…) nunca é achado, mesmo com
  contextos assimétricos; contextos simétricos nunca são achado; `!=`/negação de ator nunca é
  achado (só o `==`/contains que CONCEDE a um bot falsificável).

Ataca a classe, não o exemplo: afrouxar um discriminador de FP/FN fica vermelho aqui antes do merge.
"""

from __future__ import annotations

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.ai_workflow import (
    _FORK_ISOLATED_TRIGGERS,
    _UNTRUSTED_AI_TRIGGERS,
    check_ai_rule_of_two,
)
from esteira.checks.compromised_actions import KNOWN_COMPROMISED, check_compromised_actions
from esteira.checks.hardening_extra import check_cache_poisoning, check_falsifiable_actor
from esteira.core.models import Severity, Workflow

_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"  # ref seguro, não-incidente
_HEX = "0123456789abcdef"


def _wf(text: str) -> Workflow:
    data = yaml.safe_load(text)
    return Workflow(path="w.yml", text=text, data=data if isinstance(data, dict) else None)


# --------------------------------------------------------------------------- #
# compromised-action — a classe é: achado ⇔ (raiz no snapshot ∧ ref comprometido)
# --------------------------------------------------------------------------- #

_PARES_COMPROMETIDOS = [(raiz, ref) for raiz, adv in KNOWN_COMPROMISED.items() for ref in adv.refs]
_REFS_COMPROMETIDOS = {ref.lower() for _r, adv in KNOWN_COMPROMISED.items() for ref in adv.refs}
_RAIZES = sorted(KNOWN_COMPROMISED)


def _uses(action_ref: str) -> Workflow:
    return _wf(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: {action_ref}\n"
    )


@given(
    par=st.sampled_from(_PARES_COMPROMETIDOS),
    subpath=st.booleans(),
    caixa_alta=st.booleans(),
)
def test_ref_comprometido_sempre_dispara_critico(
    par: tuple[str, str], subpath: bool, caixa_alta: bool
) -> None:
    """FN-classe: raiz do snapshot + ref comprometido → SEMPRE um achado CRÍTICO, com subpath
    normalizado e ref case-insensitive."""
    raiz, ref = par
    alvo = f"{raiz}/subdir" if subpath else raiz
    ref_uso = ref.upper() if caixa_alta else ref
    achados = check_compromised_actions(_uses(f"{alvo}@{ref_uso}"))
    assert len(achados) == 1
    assert achados[0].severity is Severity.CRITICAL
    assert achados[0].check_id == "known-compromised-action"


@given(
    raiz=st.sampled_from(_RAIZES),
    ref_seguro=st.text(_HEX, min_size=40, max_size=40).filter(
        lambda r: r.lower() not in _REFS_COMPROMETIDOS
    ),
)
def test_action_conhecida_em_ref_seguro_nunca_dispara(raiz: str, ref_seguro: str) -> None:
    """FP-classe (baixo-FP): a MESMA action comprometida, re-pinada num commit seguro (não-incidente),
    não gera achado. Casar por ref exato é o que separa 'está na lista' de 'usa a versão ruim'."""
    assert check_compromised_actions(_uses(f"{raiz}@{ref_seguro}")) == []


@given(
    owner=st.text("abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=12),
    nome=st.text("abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=12),
    ref=st.text(_HEX, min_size=40, max_size=40),
)
def test_action_fora_do_snapshot_nunca_dispara_offline(owner: str, nome: str, ref: str) -> None:
    """FP-classe: offline (sem lookup), uma action que não está no snapshot nunca é achado — não
    importa o ref. 'Inconclusivo não é ausência', mas também não é acusação."""
    raiz = f"{owner}/{nome}"
    if raiz.lower() in {r.lower() for r in _RAIZES}:
        return  # colidiu com uma raiz real; coberto pelos testes acima
    assert check_compromised_actions(_uses(f"{raiz}@{ref}")) == []


# --------------------------------------------------------------------------- #
# ai-agent (Regra de Dois) — classe de leg 1 / cap de fork / escada de severidade
# --------------------------------------------------------------------------- #

_GATILHOS_SEGUROS = ["push", "schedule", "workflow_dispatch", "release", "create", "deployment"]
_GATILHOS_NAO_CONFIAVEIS = sorted(_UNTRUSTED_AI_TRIGGERS)
_PERMS = ["write-all", "{contents: read}", "{}"]  # formas YAML inline válidas
_AGENTE = f"anthropics/claude-code-action@{_SHA}"


def _wf_agente(gatilho: str, perms: str, com_agente: bool) -> Workflow:
    passo = (
        f"      - uses: {_AGENTE}\n        with:\n          prompt: responda\n"
        if com_agente
        else "      - run: echo ola\n"
    )
    return _wf(
        f"on: {gatilho}\npermissions: {perms}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n{passo}"
    )


@given(
    gatilho=st.sampled_from(_GATILHOS_SEGUROS),
    perms=st.sampled_from(_PERMS),
    com_agente=st.booleans(),
)
def test_sem_gatilho_nao_confiavel_nunca_ha_achado(
    gatilho: str, perms: str, com_agente: bool
) -> None:
    """FP-classe (leg 1 ausente): sem entrada não-confiável, um agente de IA com qualquer canal de
    escrita NÃO é a Regra de Dois — zero achados, sempre."""
    assert check_ai_rule_of_two(_wf_agente(gatilho, perms, com_agente)) == []


@given(perms=st.sampled_from(_PERMS), com_agente=st.booleans())
def test_pull_request_de_fork_nunca_sobe_para_alta(perms: str, com_agente: bool) -> None:
    """Cap-classe: sob `pull_request` (fork isolado: o GitHub retém token e segredos), a Regra de
    Dois não fecha — nunca ALTA (`ai-agent-rule-of-two`), no máximo MÉDIA."""
    achados = check_ai_rule_of_two(_wf_agente("pull_request", perms, com_agente))
    assert all(a.check_id != "ai-agent-rule-of-two" for a in achados)
    assert all(a.severity is not Severity.HIGH for a in achados)


# Gatilhos não-confiáveis que NÃO são fork isolado: aqui o token de escrita e os segredos NÃO são
# retidos, então a leg 3 (canal) de fato alcança um contexto privilegiado — a Regra de Dois fecha.
_GATILHOS_NAO_CONFIAVEIS_NAO_FORK = sorted(_UNTRUSTED_AI_TRIGGERS - _FORK_ISOLATED_TRIGGERS)


@given(gatilho=st.sampled_from(_GATILHOS_NAO_CONFIAVEIS_NAO_FORK))
def test_regra_de_dois_completa_sempre_dispara_alta(gatilho: str) -> None:
    """FN-classe (o lado positivo, que o teste de severidade só checava de forma vacuosa): gatilho
    não-confiável NÃO-fork + agente de IA + canal de escrita (`write-all`) no MESMO job SEMPRE
    fecha a Regra de Dois — exatamente um achado ALTO `ai-agent-rule-of-two`. Afrouxar qualquer
    das três pernas (deixar de detectar o agente, o gatilho ou o canal) fica vermelho aqui."""
    achados = check_ai_rule_of_two(_wf_agente(gatilho, "write-all", com_agente=True))
    assert len(achados) == 1, f"a Regra de Dois não fechou para {gatilho!r}: {achados!r}"
    assert achados[0].check_id == "ai-agent-rule-of-two"
    assert achados[0].severity is Severity.HIGH


@given(
    gatilho=st.sampled_from(_GATILHOS_NAO_CONFIAVEIS),
    perms=st.sampled_from(_PERMS),
    com_agente=st.booleans(),
)
def test_severidade_emitida_e_sempre_alta_ou_media(
    gatilho: str, perms: str, com_agente: bool
) -> None:
    """Escada-classe: todo achado de IA é ALTA (Regra de Dois completa) ou MÉDIA (entrada
    não-confiável sem canal), nunca outra severidade."""
    for a in check_ai_rule_of_two(_wf_agente(gatilho, perms, com_agente)):
        assert a.severity in (Severity.HIGH, Severity.MEDIUM)
        assert a.check_id in ("ai-agent-rule-of-two", "ai-agent-untrusted-input")


@given(
    gatilho=st.sampled_from(_GATILHOS_NAO_CONFIAVEIS),
    assoc=st.sampled_from(["OWNER", "MEMBER", "COLLABORATOR"]),
)
def test_gate_de_autor_confiavel_neutraliza_o_job(gatilho: str, assoc: str) -> None:
    """FP-classe (leg 1 neutralizada): um `if:` que exige author_association confiável derruba a
    entrada não-confiável — o job não vira achado mesmo com agente + escrita."""
    wf = _wf(
        f"on: {gatilho}\npermissions: write-all\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        f"    if: github.event.pull_request.author_association == '{assoc}'\n    steps:\n"
        f"      - uses: {_AGENTE}\n        with:\n          prompt: x\n"
    )
    assert check_ai_rule_of_two(wf) == []


# --------------------------------------------------------------------------- #
# cache-poisoning — chave por-run / contexto simétrico nunca são achado
# --------------------------------------------------------------------------- #

_TOKENS_POR_RUN = [
    "${{ github.sha }}",
    "${{ github.run_id }}",
    "${{ github.ref_name }}",
    "${{ github.head_ref }}",
]


def _wf_cache(write_key: str, restore_key: str, write_ev: str, restore_ev: str) -> Workflow:
    return _wf(
        "on: [pull_request, push]\njobs:\n"
        f"  w:\n    runs-on: ubuntu-latest\n    if: github.event_name == '{write_ev}'\n    steps:\n"
        f"      - uses: actions/cache/save@{_SHA}\n        with:\n          key: {write_key}\n"
        f"          path: build\n"
        f"  r:\n    runs-on: ubuntu-latest\n    if: github.event_name == '{restore_ev}'\n    steps:\n"
        f"      - uses: actions/cache/restore@{_SHA}\n        with:\n          key: {restore_key}\n"
        f"          path: build\n"
    )


@given(token=st.sampled_from(_TOKENS_POR_RUN), sufixo=st.text("abc-", min_size=0, max_size=6))
def test_chave_de_cache_por_run_nunca_e_achado(token: str, sufixo: str) -> None:
    """FP-classe: uma chave que inclui um discriminador por-run/contexto (`github.sha`, `ref_name`…)
    calcula valores DIFERENTES nos dois contextos — não há colisão para envenenar, então mesmo com
    escrita-em-PR/leitura-em-push não é achado."""
    chave = f"build-{token}-{sufixo}"
    assert check_cache_poisoning(_wf_cache(chave, chave, "pull_request", "push")) == []


@given(evento=st.sampled_from(["pull_request", "push"]))
def test_contexto_simetrico_de_cache_nunca_e_achado(evento: str) -> None:
    """FP-classe: escrita e restauração no MESMO contexto de gatilho (padrão save+restore benigno)
    não é envenenamento — só a ASSIMETRIA de confiança indica escrita-num / leitura-noutro."""
    assert check_cache_poisoning(_wf_cache("build-fixo", "build-fixo", evento, evento)) == []


@given(sufixo=st.text("abcABC0-", min_size=0, max_size=8))
def test_cache_assimetrico_com_chave_estavel_sempre_dispara(sufixo: str) -> None:
    """FN-classe (o lado positivo, que `so_emite_seu_proprio_id` só checava de forma vacuosa): uma
    chave ESTÁVEL (sem discriminador por-run) escrita em `pull_request` e restaurada em `push`
    — contextos ASSIMÉTRICOS de confiança — SEMPRE gera exatamente um achado ALTO `cache-poisoning`.
    É o vetor real; deixar de detectá-lo (o FN) fica vermelho aqui antes do merge."""
    chave = f"build-{sufixo}"  # estável: nenhum token github.sha/ref/run_id
    achados = check_cache_poisoning(_wf_cache(chave, chave, "pull_request", "push"))
    assert len(achados) == 1, f"cache-poisoning não disparou para {chave!r}: {achados!r}"
    assert achados[0].check_id == "cache-poisoning"
    assert achados[0].severity is Severity.HIGH


@given(sufixo=st.text("abcABC0-", min_size=0, max_size=8))
def test_cache_poisoning_so_emite_seu_proprio_id(sufixo: str) -> None:
    """Todo achado de cache-poisoning tem o id e a severidade fixados (nunca outra classe)."""
    wf = _wf_cache(f"build-{sufixo}", f"build-{sufixo}", "pull_request", "push")
    for a in check_cache_poisoning(wf):
        assert a.check_id == "cache-poisoning"
        assert a.severity is Severity.HIGH


# --------------------------------------------------------------------------- #
# falsifiable-actor — só o == que CONCEDE a um bot; != / negação nunca
# --------------------------------------------------------------------------- #

_BOTS = ["dependabot[bot]", "renovate[bot]", "github-actions[bot]"]
_HUMANOS = ["alice", "bob-maintainer", "my-dependabot-helper", "renovate-fan"]


def _wf_actor(if_expr: str) -> Workflow:
    # `if:` entre aspas duplas: a expressão carrega aspas simples (`'dependabot[bot]'`) e o `!(`
    # da negação, que o YAML tomaria por uma tag. O detector lê o VALOR string do `if:`.
    return _wf(
        "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        f'    if: "{if_expr}"\n    steps:\n      - run: echo ok\n'
    )


@given(bot=st.sampled_from(_BOTS))
def test_igualdade_com_bot_falsificavel_dispara(bot: str) -> None:
    """FN-classe: `if: github.actor == '<bot>'` como porta de privilégio SEMPRE é achado MÉDIO —
    o ator é falsificável e muda em re-runs/workflow_run."""
    achados = check_falsifiable_actor(_wf_actor(f"github.actor == '{bot}'"))
    assert len(achados) == 1
    assert achados[0].check_id == "falsifiable-actor-condition"
    assert achados[0].severity is Severity.MEDIUM


@given(bot=st.sampled_from(_BOTS))
def test_desigualdade_ou_negacao_de_ator_nunca_dispara(bot: str) -> None:
    """FP-classe: `!=` e a negação `!(... == bot)` EXCLUEM o ator (direção segura/comum) — nunca
    são achado. Confundir exclusão com concessão seria FP no padrão mais frequente."""
    assert check_falsifiable_actor(_wf_actor(f"github.actor != '{bot}'")) == []
    assert check_falsifiable_actor(_wf_actor(f"!(github.actor == '{bot}')")) == []


@given(humano=st.sampled_from(_HUMANOS))
def test_igualdade_com_login_humano_nunca_dispara(humano: str) -> None:
    """FP-classe: `github.actor == '<humano>'` não é a classe deste detector (ele mira BOT como
    porta) — um login humano, inclusive um que CONTÉM 'dependabot', não pode virar achado."""
    assert check_falsifiable_actor(_wf_actor(f"github.actor == '{humano}'")) == []


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(
    op=st.sampled_from(["==", "!="]),
    ator=st.sampled_from(["github.actor", "github.event.pull_request.user.login"]),
    quem=st.sampled_from(_BOTS + _HUMANOS),
)
def test_so_actor_falsificavel_com_igualdade_a_bot_e_achado(op: str, ator: str, quem: str) -> None:
    """Classe consolidada: é achado SE e SÓ SE (campo de ATOR falsificável) ∧ (==) ∧ (login de bot).
    O autor REAL do PR (`pull_request.user.login`) é a alternativa robusta — nunca é achado."""
    from esteira.checks.hardening_extra import _is_bot_login

    achados = check_falsifiable_actor(_wf_actor(f"{ator} {op} '{quem}'"))
    esperado = (ator == "github.actor") and (op == "==") and _is_bot_login(quem)
    assert bool(achados) == esperado
