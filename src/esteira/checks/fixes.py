"""Fixers seguros e determinísticos, registrados por regra no `CATALOG` (`CheckMeta.fixer`).

Cada fixer resolve exatamente o que a `recommendation` da própria regra já pede — nunca um
palpite: quando não consegue confirmar a correção (nó não encontrado, já corrigido, rede
indisponível para resolver a tag), devolve False e `apply_safe_fixes` não toca naquele
achado. "Seguro" aqui quer dizer: a correção não pode mudar o COMPORTAMENTO do workflow,
só endurecer a postura de segurança — pinar por SHA não muda qual código roda hoje (é o
mesmo commit que a tag aponta agora), `contents: read` e `persist-credentials: false`
só RESTRINGEM o que o job pode fazer.
"""

from __future__ import annotations

import dataclasses
import subprocess
from collections.abc import Callable
from typing import Any

from ruamel.yaml.comments import CommentedMap

from esteira.checks.catalog import CATALOG
from esteira.checks.detectors import _SHA, _action_ref
from esteira.core.fixer import Fixer
from esteira.core.models import Finding

# Resolve '(action, ref)' (ex.: ("actions/checkout", "v4")) para o SHA de commit que 'ref'
# aponta AGORA, ou None se não deu para confirmar. Parâmetro injetável para os testes não
# dependerem de rede real; o padrão (`_git_ls_remote_sha`) consulta o GitHub de verdade.
TagResolver = Callable[[str, str], "str | None"]

_PERSIST_CREDENTIALS_FALSY = frozenset({"false", "no", "off"})


def _git_ls_remote_sha(action: str, ref: str) -> str | None:
    """SHA do commit que `ref` (tag ou branch) aponta no repositório de `action` AGORA.

    `action` pode ter subpath (ex.: `github/codeql-action/analyze`, uma action dentro de um
    monorepo) — o repositório git de verdade são só os dois primeiros segmentos; o resto é
    caminho dentro dele, irrelevante para resolver a ref. Falha de rede, ref inexistente ou
    saída inesperada devolvem None: fail-closed, o fixer só aplica o que confirmou de fato.
    """
    partes = action.split("/")
    if len(partes) < 2 or not partes[0] or not partes[1]:
        return None
    url = f"https://github.com/{partes[0]}/{partes[1]}"
    try:
        resultado = subprocess.run(
            ["git", "ls-remote", url, ref],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if resultado.returncode != 0:
        return None
    linhas = [ln for ln in resultado.stdout.splitlines() if ln.strip()]
    if not linhas:
        return None
    # Tag anotada: 'ls-remote' devolve a própria tag E 'ref^{}' (o commit que ela aponta —
    # o que o checkout de fato usa). Prioriza o commit peeled quando presente.
    for linha in linhas:
        if linha.endswith("^{}"):
            sha = linha.split()[0]
            return sha if _SHA.match(sha) else None
    sha = linhas[0].split()[0]
    return sha if _SHA.match(sha) else None


def _key_line(node: Any, key: str) -> int | None:
    """Linha (1-based) em que `key` aparece em `node`, ou None se ausente/sem rastro de linha."""
    if not isinstance(node, CommentedMap) or key not in node:
        return None
    try:
        line, _col = node.lc.key(key)
    except (AttributeError, KeyError, TypeError):
        return None
    return int(line) + 1


def _steps_of_node(node: Any) -> list[CommentedMap]:
    steps = node.get("steps") if isinstance(node, CommentedMap) else None
    return [s for s in steps if isinstance(s, CommentedMap)] if isinstance(steps, list) else []


def _all_steps(doc: Any) -> list[CommentedMap]:
    """Todo step de todo job (workflow) ou de `runs:` (composite action)."""
    out: list[CommentedMap] = []
    jobs = doc.get("jobs") if isinstance(doc, CommentedMap) else None
    if isinstance(jobs, CommentedMap):
        for job in jobs.values():
            if isinstance(job, CommentedMap):
                out += _steps_of_node(job)
    out += _steps_of_node(doc.get("runs")) if isinstance(doc, CommentedMap) else []
    return out


def _all_uses_nodes(doc: Any) -> list[CommentedMap]:
    """Todo mapeamento com uma chave `uses:` que o fixer de pinagem pode mirar: steps + jobs
    que chamam reusable workflow direto (`job.uses:`, sem `steps:`)."""
    out = list(_all_steps(doc))
    jobs = doc.get("jobs") if isinstance(doc, CommentedMap) else None
    if isinstance(jobs, CommentedMap):
        out += [j for j in jobs.values() if isinstance(j, CommentedMap) and "uses" in j]
    return [n for n in out if isinstance(n.get("uses"), str)]


def _persist_credentials_disabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in _PERSIST_CREDENTIALS_FALSY
    return False


def fix_missing_permissions(doc: Any, _finding: Finding) -> bool:
    """`missing-permissions`: acrescenta `permissions: {contents: read}` logo após `on:`.

    Logo após `on:` (nunca ausente num workflow) e não imediatamente antes de `jobs:` de
    propósito: um comentário que precede `jobs:` no arquivo original fica preso entre a
    chave anterior e a nova (limitação do modelo de comentário do ruamel ao inserir uma
    chave nova MEIO de duas existentes) — inserir sempre no mesmo ponto fixo (`on:`) torna
    esse deslocamento previsível e raro (só ocorre se houver comentário bem ali).
    """
    if not isinstance(doc, CommentedMap) or "permissions" in doc:
        return False
    permissoes = CommentedMap()
    permissoes["contents"] = "read"
    chaves = list(doc.keys())
    indice = chaves.index("on") + 1 if "on" in chaves else len(chaves)
    doc.insert(indice, "permissions", permissoes)
    return True


def fix_checkout_credentials(doc: Any, finding: Finding) -> bool:
    """`checkout-credentials-in-artifact`: `persist-credentials: false` no checkout exposto.

    Mira o step EXATO (pela linha do achado) para não mexer num checkout homônimo de outro
    job no mesmo arquivo.
    """
    for step in _all_steps(doc):
        uses = step.get("uses")
        if not isinstance(uses, str) or not uses.startswith("actions/checkout"):
            continue
        if _key_line(step, "uses") != finding.line:
            continue
        with_ = step.get("with")
        if not isinstance(with_, CommentedMap):
            with_ = CommentedMap()
            step["with"] = with_
        if _persist_credentials_disabled(with_.get("persist-credentials")):
            return False  # idempotente: já estava desabilitado
        with_["persist-credentials"] = False
        return True
    return False


def _fix_unpinned(doc: Any, finding: Finding, resolve: TagResolver) -> bool:
    for node in _all_uses_nodes(doc):
        uses = node["uses"]
        if _key_line(node, "uses") != finding.line:
            continue
        parsed = _action_ref(uses)
        if parsed is None:
            return False
        action, ref = parsed
        if _SHA.match(ref):
            return False  # idempotente: já pinado por SHA
        sha = resolve(action, ref)
        if sha is None:
            return False  # não deu para confirmar o SHA atual — não aplica (fail-closed)
        _, key_col = node.lc.key("uses")
        novo_valor = f"{action}@{sha}"
        node["uses"] = novo_valor
        # Mesma convenção do próprio .github/workflows/ deste repositório: o ref original
        # fica como comentário ao lado do SHA ('# v4'), não embutido na string.
        coluna = key_col + len("uses: ") + len(novo_valor) + 1
        node.yaml_add_eol_comment(ref, key="uses", column=coluna)
        return True
    return False


def make_unpinned_fixer(resolve: TagResolver) -> Fixer:
    """Fábrica (não uma closure fixa no módulo) para os testes poderem injetar um
    `TagResolver` falso sem depender de rede nem de monkeypatch no símbolo do módulo."""

    def _fixer(doc: Any, finding: Finding) -> bool:
        return _fix_unpinned(doc, finding, resolve)

    return _fixer


def _register(check_id: str, fixer: Fixer) -> None:
    CATALOG[check_id] = dataclasses.replace(CATALOG[check_id], fixer=fixer)


_register("missing-permissions", fix_missing_permissions)
_register("checkout-credentials-in-artifact", fix_checkout_credentials)
_unpinned_fixer = make_unpinned_fixer(_git_ls_remote_sha)
_register("unpinned-action-thirdparty", _unpinned_fixer)
_register("unpinned-action-firstparty", _unpinned_fixer)
