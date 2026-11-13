"""Roda zizmor, actionlint, octoscan e poutine lado a lado contra `bench/` e republica
`BENCHMARK.md` com o resultado.

Diferente de medir falso-positivo em campo (que exigiria escolher repositórios de terceiro e
adjudicar achado por achado sobre código que não escrevemos — decisão de produto, não deste
script), aqui o corpus já tem verdade estabelecida: `bench/manifest.json`, autoral, com
arquivo+linha+regra conhecidos de antemão. O que este script faz é mecânico e reproduzível:
roda os quatro concorrentes contra o MESMO corpus que a Esteira já mede em `bench/avaliar.py`
e confere, achado a achado, se cada concorrente também encontrou o que o manifesto rotula.

O casamento entre a regra da Esteira e a regra equivalente de cada concorrente não é decidido
na hora — vem de `bench/equivalencias.json`, com nota explicando cada "null" (concorrente não
tem checagem equivalente) e cada caso onde uma checagem parecida existe mas mede outra coisa.
Quem discordar de uma linha desse arquivo abre uma issue ou PR nele; o script só aplica o que
está declarado.

Uso:
    pip install -e ".[dev]"
    pip install zizmor==1.31.1
    go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
    go install github.com/boostsecurityio/poutine@v1.1.6
    git clone --branch v0.1.7 https://github.com/synacktiv/octoscan /tmp/octoscan-src \
        && go build -o /tmp/octoscan-src/octoscan-bin /tmp/octoscan-src
    OCTOSCAN_BIN=/tmp/octoscan-src/octoscan-bin python bench/comparar_concorrentes.py

As checagens que dependem de rede (verificação de autor/commit contra a API do GitHub, no
zizmor e no octoscan) ficam desligadas de propósito: sem token, elas falham ou retornam
achados que variam a cada corrida, e isso quebraria o "comando único reproduzível" que o
BENCHMARK.md promete. O que fica de fora por causa disso está anotado no próprio arquivo.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

BENCH = Path(__file__).resolve().parent
RAIZ = BENCH.parent
TOLERANCIA_DE_LINHA = 1

# A regra "invalid-yaml" não tem uma linha comparável entre ferramentas: a Esteira sempre
# rotula o arquivo quebrado na linha 1 (convenção de "arquivo inteiro é o problema"), mas um
# linter de sintaxe aponta a linha onde o parser efetivamente travou. Casar só por arquivo
# evita contar isso como miss por motivo errado.
REGRAS_SO_ARQUIVO = {"invalid-yaml"}

FERRAMENTAS = ("zizmor", "actionlint", "octoscan", "poutine")

VERSOES_FIXADAS = {
    "zizmor": "1.31.1",
    "actionlint": "v1.7.12",
    "octoscan": "v0.1.7",
    "poutine": "v1.1.6",
}

Achado = tuple[str, int, str]  # (arquivo-base, linha, regra-da-ferramenta)


class ResultadoFerramenta(NamedTuple):
    nome: str
    achados: list[Achado]
    erro: str | None  # presente quando a ferramenta não pôde rodar (não instalada etc.)


def ler_manifesto() -> list[dict[str, object]]:
    with open(BENCH / "manifest.json", encoding="utf-8") as fh:
        dados: list[dict[str, object]] = json.load(fh)
    return dados


def ler_equivalencias() -> dict[str, dict[str, object]]:
    with open(BENCH / "equivalencias.json", encoding="utf-8") as fh:
        dados: list[dict[str, object]] = json.load(fh)
    return {str(item["regra"]): item for item in dados}


def bate(regra: str, linha_rotulo: int, linha_achado: int) -> bool:
    if regra in REGRAS_SO_ARQUIVO:
        return True
    return abs(linha_rotulo - linha_achado) <= TOLERANCIA_DE_LINHA


# ---------------------------------------------------------------------------------------
# Parsers puros — recebem a saída bruta (já capturada) de cada ferramenta e devolvem achados
# normalizados. Ficam separados da execução (`_rodar_*`) para serem testáveis sem instalar
# nenhum binário externo: um teste pode alimentar aqui uma string JSON gravada de uma corrida
# real e conferir o resultado.
# ---------------------------------------------------------------------------------------


def parse_zizmor(saida_json: str) -> list[Achado]:
    inicio = saida_json.find("[")
    if inicio == -1:
        return []
    dados = json.loads(saida_json[inicio:])
    achados: set[Achado] = set()
    for achado in dados:
        ident = str(achado["ident"])
        for loc in achado["locations"]:
            caminho = os.path.basename(loc["symbolic"]["key"]["Local"]["verbatim_path"])
            linha = int(loc["concrete"]["location"]["start_point"]["row"]) + 1
            achados.add((caminho, linha, ident))
    return sorted(achados)


def parse_actionlint(saida_json: str) -> list[Achado]:
    if not saida_json.strip():
        return []
    dados = json.loads(saida_json)
    return sorted(
        {(os.path.basename(x["filepath"]), int(x["line"]), str(x["kind"])) for x in dados}
    )


def parse_octoscan(saida_json: str) -> list[Achado]:
    if not saida_json.strip():
        return []
    dados = json.loads(saida_json)
    return sorted(
        {(os.path.basename(x["filepath"]), int(x["line"]), str(x["kind"])) for x in dados}
    )


def parse_poutine(saida_json: str) -> list[Achado]:
    dados = json.loads(saida_json)
    achados: set[Achado] = set()
    for achado in dados.get("findings", []):
        meta = achado.get("meta", {})
        if "line" not in meta or "path" not in meta:
            continue
        achados.add((os.path.basename(meta["path"]), int(meta["line"]), str(achado["rule_id"])))
    return sorted(achados)


PARSERS = {
    "zizmor": parse_zizmor,
    "actionlint": parse_actionlint,
    "octoscan": parse_octoscan,
    "poutine": parse_poutine,
}


# ---------------------------------------------------------------------------------------
# Execução das ferramentas — isola o shell-out para o resto do script poder ser testado sem ele.
# ---------------------------------------------------------------------------------------


def _staging_dir() -> Path:
    """Copia positivos/ e negativos/ para `.github/workflows/` de um repo git descartável.

    poutine só varre o layout padrão de repositório (`.github/workflows/`); zizmor em modo
    diretório também espera esse caminho. Rodar todo mundo contra o mesmo staging evita
    divergência de comportamento por causa do layout de entrada, não do que cada um detecta.
    """
    tmp = Path(tempfile.mkdtemp(prefix="esteira-bench-concorrentes-"))
    alvo = tmp / ".github" / "workflows"
    alvo.mkdir(parents=True)
    for pasta in ("positivos", "negativos"):
        for arquivo in sorted((BENCH / pasta).glob("*.yml")):
            shutil.copy2(arquivo, alvo / arquivo.name)
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=bench@local",
            "-c",
            "user.name=bench",
            "commit",
            "-q",
            "-m",
            "staging",
        ],
        cwd=tmp,
        check=True,
    )
    return tmp


def _rodar(
    nome_binario: str, argv: list[str], **kwargs: object
) -> subprocess.CompletedProcess[str]:
    caminho = shutil.which(nome_binario) or os.environ.get(f"{nome_binario.upper()}_BIN")
    if not caminho or not Path(caminho).exists():
        raise FileNotFoundError(nome_binario)
    return subprocess.run([caminho, *argv], capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]


def rodar_zizmor(staging: Path) -> ResultadoFerramenta:
    try:
        r = _rodar(
            "zizmor",
            ["--no-online-audits", "--format", "json", str(staging / ".github" / "workflows")],
        )
    except FileNotFoundError:
        return ResultadoFerramenta(
            "zizmor", [], "binário não encontrado (pip install zizmor==1.31.1)"
        )
    try:
        return ResultadoFerramenta("zizmor", parse_zizmor(r.stdout), None)
    except (ValueError, KeyError) as exc:
        return ResultadoFerramenta("zizmor", [], f"saída inesperada: {exc}")


def rodar_actionlint(staging: Path) -> ResultadoFerramenta:
    workflows = sorted((staging / ".github" / "workflows").glob("*.yml"))
    try:
        r = _rodar("actionlint", ["-format", "{{json .}}", *[str(w) for w in workflows]])
    except FileNotFoundError:
        return ResultadoFerramenta(
            "actionlint", [], "binário não encontrado (go install .../actionlint@v1.7.12)"
        )
    try:
        return ResultadoFerramenta("actionlint", parse_actionlint(r.stdout), None)
    except (ValueError, KeyError) as exc:
        return ResultadoFerramenta("actionlint", [], f"saída inesperada: {exc}")


def rodar_octoscan(staging: Path) -> ResultadoFerramenta:
    caminho = shutil.which("octoscan") or os.environ.get("OCTOSCAN_BIN")
    if not caminho or not Path(caminho).exists():
        return ResultadoFerramenta(
            "octoscan",
            [],
            "binário não encontrado (ver instruções de build no cabeçalho deste script)",
        )
    r = subprocess.run(
        [caminho, "scan", "--format", "json", ".", "--disable-rules", "repo-jacking"],
        capture_output=True,
        text=True,
        cwd=staging,
    )
    try:
        return ResultadoFerramenta("octoscan", parse_octoscan(r.stdout), None)
    except (ValueError, KeyError) as exc:
        return ResultadoFerramenta("octoscan", [], f"saída inesperada: {exc}")


def rodar_poutine(staging: Path) -> ResultadoFerramenta:
    try:
        r = _rodar("poutine", ["analyze_local", "--format", "json", str(staging)])
    except FileNotFoundError:
        return ResultadoFerramenta(
            "poutine", [], "binário não encontrado (go install .../poutine@v1.1.6)"
        )
    try:
        return ResultadoFerramenta("poutine", parse_poutine(r.stdout), None)
    except (ValueError, KeyError) as exc:
        return ResultadoFerramenta("poutine", [], f"saída inesperada: {exc}")


RODADORES = {
    "zizmor": rodar_zizmor,
    "actionlint": rodar_actionlint,
    "octoscan": rodar_octoscan,
    "poutine": rodar_poutine,
}


def resultados_esteira() -> list[Achado]:
    sys.path.insert(0, str(RAIZ / "src"))
    from esteira.checks.engine import scan

    achados: set[Achado] = set()
    for pasta in ("positivos", "negativos"):
        for achado in scan(BENCH / pasta).findings:
            achados.add((os.path.basename(achado.path), achado.line, achado.check_id))
    return sorted(achados)


# ---------------------------------------------------------------------------------------
# Avaliação: cruza manifesto + equivalências + achados de cada ferramenta.
# ---------------------------------------------------------------------------------------


def tem_achado(
    achados: list[Achado], arquivo: str, linha: int, regra_ferramenta: str, regra_esteira: str
) -> bool:
    return any(
        a == arquivo and r == regra_ferramenta and bate(regra_esteira, linha, linha_achado)
        for a, linha_achado, r in achados
    )


def tem_qualquer_achado(achados: list[Achado], arquivo: str, linha: int) -> bool:
    """Para falso-positivo em negativos/: qualquer achado na linha-armadilha conta, de
    qualquer regra da ferramenta — não exige a mesma regra que um achado positivo usaria."""
    return any(
        a == arquivo and abs(linha_achado - linha) <= TOLERANCIA_DE_LINHA
        for a, linha_achado, _r in achados
    )


class Linha(NamedTuple):
    arquivo: str
    linha: int
    regra: str
    eh_achado: bool
    nota: str
    por_ferramenta: dict[str, str | None]  # None = sem checagem equivalente; True/False via "x"/""


def montar_linhas(
    manifesto: list[dict[str, object]],
    equivalencias: dict[str, dict[str, object]],
    achados_esteira: list[Achado],
    achados_por_ferramenta: dict[str, ResultadoFerramenta],
) -> list[Linha]:
    linhas = []
    for rotulo in manifesto:
        arquivo = os.path.basename(str(rotulo["arquivo"]))
        linha_n = int(str(rotulo["linha"]))
        eh_achado = bool(rotulo["eh_achado"])
        regra = str(rotulo["regra"]) if rotulo.get("regra") else ""

        por_ferramenta: dict[str, str | None] = {}
        if eh_achado:
            esteira_hit = tem_achado(achados_esteira, arquivo, linha_n, regra, regra)
            equivalencia = equivalencias.get(regra, {})
            for ferramenta in FERRAMENTAS:
                regra_ferramenta = equivalencia.get(ferramenta)
                resultado = achados_por_ferramenta[ferramenta]
                if resultado.erro is not None or regra_ferramenta is None:
                    por_ferramenta[ferramenta] = None
                else:
                    hit = tem_achado(
                        resultado.achados, arquivo, linha_n, str(regra_ferramenta), regra
                    )
                    por_ferramenta[ferramenta] = "hit" if hit else "miss"
            nota = str(equivalencia.get("nota") or "")
        else:
            esteira_hit = tem_qualquer_achado(achados_esteira, arquivo, linha_n)
            for ferramenta in FERRAMENTAS:
                resultado = achados_por_ferramenta[ferramenta]
                if resultado.erro is not None:
                    por_ferramenta[ferramenta] = None
                else:
                    fp = tem_qualquer_achado(resultado.achados, arquivo, linha_n)
                    por_ferramenta[ferramenta] = "fp" if fp else "ok"
            nota = str(rotulo.get("nota", ""))

        if eh_achado:
            por_ferramenta["esteira"] = "hit" if esteira_hit else "miss"
        else:
            por_ferramenta["esteira"] = "fp" if esteira_hit else "ok"
        linhas.append(Linha(arquivo, linha_n, regra, eh_achado, nota, por_ferramenta))
    return linhas


def gerar_markdown(
    linhas: list[Linha],
    achados_por_ferramenta: dict[str, ResultadoFerramenta],
    equivalencias: dict[str, dict[str, object]],
) -> str:
    positivos = [linha_item for linha_item in linhas if linha_item.eh_achado]
    negativos = [linha_item for linha_item in linhas if not linha_item.eh_achado]

    colunas = ["esteira", *FERRAMENTAS]

    def simbolo(valor: str | None) -> str:
        return {"hit": "✅", "miss": "❌", "fp": "⚠️ FP", "ok": "—", None: "·"}.get(valor, "·")

    partes = []
    partes.append("# BENCHMARK — Esteira x zizmor x actionlint x octoscan x poutine\n")
    partes.append(
        "Comparação lado a lado contra o corpus rotulado de `bench/` — o mesmo que "
        "`bench/avaliar.py` mede para a própria Esteira. Gerado por "
        "`bench/comparar_concorrentes.py`; **não edite este arquivo à mão**, ele é "
        "republicado pelo script.\n"
    )
    partes.append(
        "**Convite explícito à contestação:** o casamento entre a regra da Esteira e a "
        "regra equivalente de cada concorrente está em `bench/equivalencias.json`, não "
        "decidida na hora por este script. Se você acha que um `—` deveria ser um `✅` "
        "(ou vice-versa), abra uma issue ou um PR mudando aquele arquivo — a tabela abaixo "
        "é reprodutível com um comando (ver `bench/comparar_concorrentes.py`), então "
        "qualquer divergência é verificável, não uma questão de confiança.\n"
    )

    partes.append("## Versões fixadas\n")
    for nome in FERRAMENTAS:
        resultado = achados_por_ferramenta[nome]
        status = (
            f"`{VERSOES_FIXADAS[nome]}`"
            if resultado.erro is None
            else f"**não rodou** — {resultado.erro}"
        )
        partes.append(f"- **{nome}**: {status}")
    partes.append("")

    partes.append("## Positivos — a Esteira e cada concorrente encontram o achado rotulado?\n")
    partes.append("| Arquivo:linha | Regra (Esteira) | Esteira | " + " | ".join(FERRAMENTAS) + " |")
    partes.append("|---|---|---|" + "---|" * len(FERRAMENTAS))
    for linha_item in positivos:
        celulas = [simbolo(linha_item.por_ferramenta[c]) for c in colunas]
        partes.append(
            f"| `{linha_item.arquivo}:{linha_item.linha}` | `{linha_item.regra}` | "
            + " | ".join(celulas)
            + " |"
        )
    partes.append("")
    partes.append(
        "`✅` = achou o mesmo achado (mesma regra equivalente, arquivo e linha dentro da "
        "tolerância de ±1). `❌` = tem checagem equivalente mapeada e não achou. `·` = "
        "nenhum concorrente tem checagem equivalente declarada em `equivalencias.json` "
        "(não é falha do concorrente em algo que ele não se propõe a medir).\n"
    )

    partes.append("## Negativos — alguém dispara na linha-armadilha que não deveria?\n")
    partes.append("| Arquivo:linha | Esteira | " + " | ".join(FERRAMENTAS) + " |")
    partes.append("|---|---|" + "---|" * len(FERRAMENTAS))
    for linha_item in negativos:
        celulas = [simbolo(linha_item.por_ferramenta[c]) for c in colunas]
        partes.append(
            f"| `{linha_item.arquivo}:{linha_item.linha}` | " + " | ".join(celulas) + " |"
        )
    partes.append("")
    partes.append(
        "`⚠️ FP` = disparou na linha que o corpus rotula como armadilha legítima "
        "(falso-positivo). `—` = não disparou ali (correto). `·` = a ferramenta não rodou "
        'nesta corrida (ver "Versões fixadas").\n'
    )

    partes.append("## Resumo\n")
    partes.append(
        "| Ferramenta | Recall (achou / rotulado) | Falso-positivo (de 8 armadilhas) | Cobertura declarada (regras com equivalente mapeado) |"
    )
    partes.append("|---|---|---|---|")
    total_positivos = len(positivos)
    total_negativos = len(negativos)
    for nome in ("esteira", *FERRAMENTAS):
        hits = sum(1 for linha_item in positivos if linha_item.por_ferramenta[nome] == "hit")
        fps = sum(1 for linha_item in negativos if linha_item.por_ferramenta[nome] == "fp")
        if nome == "esteira":
            cobertura = f"{total_positivos}/{total_positivos} (é a própria ferramenta medida)"
        else:
            mapeadas = sum(1 for item in equivalencias.values() if item.get(nome) is not None)
            cobertura = f"{mapeadas}/{len(equivalencias)}"
        erro = achados_por_ferramenta.get(nome).erro if nome != "esteira" else None
        if erro:
            partes.append(f"| {nome} | não rodou | não rodou | {cobertura} |")
        else:
            partes.append(
                f"| {nome} | {hits}/{total_positivos} | {fps}/{total_negativos} | {cobertura} |"
            )
    partes.append("")

    partes.append("## O que este benchmark não é\n")
    partes.append(
        "- **Não é medição de campo.** Mesma ressalva de `bench/README.md`: o corpus é "
        "autoral, pequeno (25 achados positivos, 8 armadilhas negativas) e mede cobertura "
        "contra casos canônicos, não acurácia contra pipelines arbitrários de produção.\n"
        "- **Não mede com token de API.** `zizmor` e `octoscan` têm checagens que "
        "consultam a API do GitHub (commit-impostor, repo-jacking); elas ficam desligadas "
        "aqui porque exigiriam um token válido para serem reprodutíveis, e sem ele falham "
        "ou retornam resultado diferente a cada corrida. Um token válido pode mudar os "
        "números acima para zizmor e octoscan — não para actionlint nem poutine, que não "
        "têm esse tipo de checagem.\n"
        "- **Não equivale regras por nome, só por comportamento observado.** Um `✅` "
        "significa que a ferramenta disparou uma checagem que `bench/equivalencias.json` "
        "declara equivalente — não que as duas regras tenham o mesmo nome ou a mesma "
        "descrição. Onde uma checagem parecida existe mas mede outra coisa (ex.: "
        '"autor verificado" não é "fixado por SHA"), o arquivo de equivalências diz '
        "isso explicitamente em vez de inflar a cobertura do concorrente.\n"
    )
    return "\n".join(partes) + "\n"


def main() -> int:
    staging = _staging_dir()
    try:
        achados_por_ferramenta = {nome: RODADORES[nome](staging) for nome in FERRAMENTAS}
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    manifesto = ler_manifesto()
    equivalencias = ler_equivalencias()
    achados_esteira = resultados_esteira()

    linhas = montar_linhas(manifesto, equivalencias, achados_esteira, achados_por_ferramenta)
    markdown = gerar_markdown(linhas, achados_por_ferramenta, equivalencias)

    destino = RAIZ / "BENCHMARK.md"
    destino.write_text(markdown, encoding="utf-8")
    print(f"BENCHMARK.md escrito em {destino}")

    faltando = [nome for nome, r in achados_por_ferramenta.items() if r.erro is not None]
    if faltando:
        print(f"AVISO: não rodaram (binário ausente): {', '.join(faltando)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
