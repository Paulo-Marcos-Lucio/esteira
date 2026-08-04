"""Mede a Esteira contra o corpus rotulado de `bench/`.

Uso:
    python bench/avaliar.py

Varre `positivos/` e `negativos/` pelo mesmo caminho que a CLI usa e confronta o resultado com
o `manifest.json`. Imprime recall e precisão com intervalo de confiança de Wilson — porque com
n=19 um número redondo sozinho anuncia uma exatidão que a amostra não comporta.

O casamento exige a REGRA certa, não só a linha certa: um achado na linha esperada com o id
errado conta como falso-positivo e como falso-negativo ao mesmo tempo. É o que se quer — a
regra é o que vai para a aba Security e para o relatório do cliente.
"""

from __future__ import annotations

import json
import math
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(BASE), "src"))

from esteira.checks.engine import scan  # noqa: E402  (depois do sys.path)

TOLERANCIA_DE_LINHA = 1  # o rótulo aponta a linha do defeito, não a do bloco que o contém


def wilson(acertos: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Intervalo de confiança de Wilson — honesto para amostra pequena."""
    if total == 0:
        return (0.0, 0.0)
    p = acertos / total
    denom = 1 + z * z / total
    centro = (p + z * z / (2 * total)) / denom
    margem = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centro - margem), min(1.0, centro + margem))


def encontrados() -> list[tuple[str, int, str]]:
    """(arquivo relativo ao bench, linha, regra) de cada achado das duas pastas."""
    saida: list[tuple[str, int, str]] = []
    for pasta in ("positivos", "negativos"):
        for achado in scan(os.path.join(BASE, pasta)).sorted():
            saida.append((f"{pasta}/{os.path.basename(achado.path)}", achado.line, achado.check_id))
    return saida


def main() -> int:
    with open(os.path.join(BASE, "manifest.json"), encoding="utf-8") as fh:
        manifesto = json.load(fh)

    achados = encontrados()
    positivos = [m for m in manifesto if m["eh_achado"]]

    def casou(rotulo: dict[str, object]) -> bool:
        return any(
            arquivo == rotulo["arquivo"]
            and regra == rotulo["regra"]
            and abs(linha - int(str(rotulo["linha"]))) <= TOLERANCIA_DE_LINHA
            for arquivo, linha, regra in achados
        )

    tp = [m for m in positivos if casou(m)]
    fn = [m for m in positivos if not casou(m)]
    fp = [
        (arquivo, linha, regra)
        for arquivo, linha, regra in achados
        if not any(
            arquivo == m["arquivo"]
            and regra == m["regra"]
            and abs(linha - int(str(m["linha"]))) <= TOLERANCIA_DE_LINHA
            for m in positivos
        )
    ]

    recall = len(tp) / len(positivos) if positivos else 0.0
    baixo, alto = wilson(len(tp), len(positivos))
    precisao = len(tp) / len(achados) if achados else 0.0
    p_baixo, p_alto = wilson(len(tp), len(achados))

    print("== bench da Esteira ==")
    print(f"  achados brutos : {len(achados)}")
    print(
        f"  RECALL         : {len(tp)}/{len(positivos)} = {recall:.0%}   IC95% = [{baixo:.0%} ; {alto:.0%}]"
    )
    print(
        f"  PRECISAO       : {len(tp)}/{len(achados)} = {precisao:.0%}   IC95% = [{p_baixo:.0%} ; {p_alto:.0%}]"
    )
    print(
        f"  FALSO-POSITIVO : {len(fp)}  ({sum(1 for f in fp if f[0].startswith('negativos/'))} em negativos)"
    )
    if fn:
        print("  FALSO-NEGATIVO (o que escapou):")
        for item in fn:
            print(f"    - {item['arquivo']}:{item['linha']}  [{item['regra']}]")
    if fp:
        print("  FALSO-POSITIVO (o que sobrou):")
        for arquivo, linha, regra in fp:
            print(f"    - {arquivo}:{linha}  [{regra}]")

    regras_cobertas = {m["regra"] for m in positivos}
    from esteira.checks.catalog import CATALOG

    faltando = sorted(set(CATALOG) - regras_cobertas)
    print(
        f"  COBERTURA DO CATALOGO : {len(regras_cobertas)}/{len(CATALOG)} regras com caso positivo"
    )
    if faltando:
        print(f"    sem caso no corpus: {', '.join(faltando)}")
    return 0 if not fn and not fp else 1


if __name__ == "__main__":
    raise SystemExit(main())
