"""Motor de correção automática: round-trip YAML (ruamel) + aplicação determinística por regra.

Por que ruamel e não o `yaml` (PyYAML) que o resto do Esteira usa para ler: PyYAML não
devolve a árvore de volta em texto — ele serializa do zero, perdendo comentário, aspas e
estilo de indentação originais. Para *escrever* de volta num workflow de produção isso é
inaceitável (o dono do arquivo vê um diff gigante de reformatação escondendo a correção
real). O ruamel em modo "rt" (round-trip) carrega preservando esses detalhes — mas só se o
estilo de indentação da sequência (quantos espaços antes do '-' e quanto o conteúdo recua)
for configurado para bater com o do arquivo de origem; por padrão o ruamel usa um estilo
(`sequence=2, offset=0`) diferente do mais comum em workflows do GitHub Actions
(`sequence=4, offset=2`, o do próprio `.github/workflows/` deste repositório). `_detect_indent`
lê o PRIMEIRO par chave-mapeamento/item-de-lista do texto para inferir o estilo real do
arquivo, em vez de impor um só convenção a todo mundo.
"""

from __future__ import annotations

import io
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ruamel.yaml import YAML

from esteira.core.models import Finding

# Um Fixer recebe o documento ruamel (raiz round-trip) e o Finding que apontou o problema, e
# tenta corrigi-lo IN PLACE. Devolve True se mudou algo (o chamador então serializa de volta);
# False se não havia nada a fazer — nó não encontrado (arquivo mudou desde a varredura) ou já
# corrigido (idempotente). Nunca lança: um fixer que não tem certeza devolve False, não chuta.
Fixer = Callable[[Any, Finding], bool]

_KEY_LINE = re.compile(r"^( *)\S.*:\s*(#.*)?$")
_DASH_LINE = re.compile(r"^( *)-( |$)")


def _detect_indent(text: str) -> tuple[int, int]:
    """(sequence, offset) do `YAML.indent()` que reproduz o estilo do arquivo.

    Acha o primeiro par (chave de mapeamento seguida de item de lista) no texto e mede a
    distância entre a chave e o '-', e entre a chave e onde o conteúdo do item começa. Sem
    esse par (nenhuma lista no documento), cai no padrão do próprio ruamel (2, 0).
    """
    lines = text.splitlines()
    for i in range(len(lines) - 1):
        key_m = _KEY_LINE.match(lines[i])
        dash_m = _DASH_LINE.match(lines[i + 1])
        if not key_m or not dash_m:
            continue
        key_indent = len(key_m.group(1))
        dash_indent = len(dash_m.group(1))
        if dash_indent < key_indent:
            continue  # o '-' não é filho desta chave (lista fechou antes)
        content_indent = dash_indent + 2  # '- ' tem 2 caracteres
        return content_indent - key_indent, dash_indent - key_indent
    return 2, 0


def make_yaml(text: str) -> YAML:
    """`YAML` round-trip configurado para reproduzir o estilo de indentação de `text`."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.width = 1_000_000  # nunca quebra linha longa (run: de uma linha, URL em comentário…)
    sequence, offset = _detect_indent(text)
    yaml.indent(mapping=2, sequence=sequence, offset=offset)
    return yaml


def load_round_trip(text: str) -> Any:
    return make_yaml(text).load(text)


def dump_round_trip(yaml: YAML, doc: Any) -> str:
    buf = io.StringIO()
    yaml.dump(doc, buf)
    return buf.getvalue()


@dataclass(frozen=True)
class FixOutcome:
    path: str
    text: str
    applied: tuple[Finding, ...]

    @property
    def changed(self) -> bool:
        return bool(self.applied)


def apply_safe_fixes(path: str, text: str, findings: Sequence[Finding]) -> FixOutcome:
    """Aplica, em `text`, os fixers registrados em `CheckMeta.fixer` dos `findings` dados.

    Achado sem fixer registrado é ignorado (não é 'seguro', quem chama já devia ter filtrado
    por `--only` as regras com `fixer is not None`; aqui é defesa, não a primeira barreira).
    Importa `CATALOG` no corpo da função, não no topo do módulo: `checks.fixes` registra os
    fixers no `CATALOG` por efeito de import, e um import no topo deste módulo correria risco
    de rodar ANTES desse registro, a depender de quem importa o quê primeiro.
    """
    from esteira.checks.catalog import CATALOG

    yaml = make_yaml(text)
    doc = yaml.load(text)
    applied: list[Finding] = []
    for finding in sorted(findings, key=lambda f: f.line):
        meta = CATALOG.get(finding.check_id)
        fixer = meta.fixer if meta is not None else None
        if fixer is None:
            continue
        if fixer(doc, finding):
            applied.append(finding)
    if not applied:
        # Propriedade central do fix: nenhum achado corrigido ⇒ devolve o texto ORIGINAL,
        # byte a byte — nunca serializa de volta um documento intocado (isso sozinho já
        # garante escrever(ler(x)) == x quando nada muda, sem depender da fidelidade do dump
        # para o caso comum e mais arriscado de ficar bom).
        return FixOutcome(path=path, text=text, applied=())
    return FixOutcome(path=path, text=dump_round_trip(yaml, doc), applied=tuple(applied))
