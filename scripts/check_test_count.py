#!/usr/bin/env python3
"""Portão de badge: o número de testes ANUNCIADO == ``pytest --collect-only``.

A contagem de testes no README e no badge é fácil de digitar e envelhecer — na auditoria cruzada,
3 dos 4 repos da suíte estavam com o badge defasado do real; a Esteira era o único exato (418 =
418). Este portão transforma "confiar na disciplina" em "conta gerada, não digitada": ele COLETA o
número real e falha se qualquer fonte anunciada (o SVG do chip, o alt-text do badge, a prosa do
README em PT e EN) divergir.

Fontes anunciadas verificadas:
* ``assets/chip-tests.svg`` — o número que o badge renderiza (``NNN TESTS``);
* ``README.md`` / ``README.en.md`` — ``NNN tests passing`` / ``NNN testes verdes`` / ``NNN passing
  tests`` — todas as formas em que a contagem aparece em texto.

Uso: ``python scripts/check_test_count.py`` (sai 0 se tudo bate, 1 na divergência). Roda no CI,
depois de instalar o pacote de dev. Não é chamado de dentro do ``pytest`` (evita recursão de
coleta): a consistência SVG↔README é checada por um teste barato; a igualdade com a coleta real,
por este script no CI.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SVG_TESTS = RAIZ / "assets" / "chip-tests.svg"
READMES = (RAIZ / "README.md", RAIZ / "README.en.md")

# Todas as formas em que a contagem de testes aparece anunciada, em PT e EN. Cada padrão captura
# só o número que ACOMPANHA a palavra "test(s)/teste(s)" — nunca um número solto do documento.
_PADROES_TEXTO: tuple[re.Pattern[str], ...] = (
    re.compile(r"(\d+)\s+tests?\s+passing", re.IGNORECASE),
    re.compile(r"(\d+)\s+passing\s+tests?", re.IGNORECASE),
    re.compile(r"(\d+)\s+testes\s+verdes", re.IGNORECASE),
    re.compile(r"(\d+)\s+testes\s+passando", re.IGNORECASE),
)
_PADRAO_SVG = re.compile(r"(\d+)\s*TESTS", re.IGNORECASE)


def contagem_real() -> int:
    """Número REAL de testes coletados por ``pytest --collect-only`` (sem cobertura, para ser
    rápido). É a fonte-de-verdade; tudo o mais é comparado contra ela."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-cov"],
        cwd=RAIZ,
        capture_output=True,
        text=True,
        check=True,
    )
    saida = proc.stdout
    # pytest imprime, no fim, "N tests collected" (ou "N test collected").
    m = re.search(r"(\d+)\s+tests?\s+collected", saida)
    if m is not None:
        return int(m.group(1))
    # Fallback para o modo `-q` que lista "caminho/arquivo.py: N" por arquivo: soma os N.
    total = 0
    visto = False
    for linha in saida.splitlines():
        mm = re.match(r"^\S+?\.py: (\d+)$", linha.strip())
        if mm is not None:
            total += int(mm.group(1))
            visto = True
    if not visto:
        raise SystemExit(f"não consegui extrair a contagem de testes da saída do pytest:\n{saida}")
    return total


def numeros_anunciados() -> dict[str, int]:
    """Cada fonte anunciada → o número que ela declara. Uma fonte que declara mais de um número
    diferente (typo entre badge e prosa) já é falha — devolvemos todos, rotulados pela origem."""
    achados: dict[str, int] = {}
    if SVG_TESTS.is_file():
        m = _PADRAO_SVG.search(SVG_TESTS.read_text(encoding="utf-8"))
        if m is not None:
            achados["assets/chip-tests.svg"] = int(m.group(1))
    for readme in READMES:
        if not readme.is_file():
            continue
        texto = readme.read_text(encoding="utf-8")
        vistos = {int(m.group(1)) for padrao in _PADROES_TEXTO for m in padrao.finditer(texto)}
        for i, valor in enumerate(sorted(vistos)):
            achados[f"{readme.name}#{i + 1}"] = valor
    return achados


def main() -> int:
    real = contagem_real()
    anunciados = numeros_anunciados()
    if not anunciados:
        print(
            "nenhuma contagem anunciada encontrada (badge/README) — nada a verificar.",
            file=sys.stderr,
        )
        return 1
    divergentes = {origem: n for origem, n in anunciados.items() if n != real}
    if divergentes:
        print(f"PORTÃO DE BADGE: contagem real (pytest --collect-only) = {real}", file=sys.stderr)
        for origem, n in sorted(divergentes.items()):
            print(f"  divergência: {origem} anuncia {n} (esperado {real})", file=sys.stderr)
        print(
            "Atualize o badge (assets/chip-tests.svg) e o README para o número real acima.",
            file=sys.stderr,
        )
        return 1
    print(f"badge de testes OK: {real} anunciado == coletado, em {len(anunciados)} fonte(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
