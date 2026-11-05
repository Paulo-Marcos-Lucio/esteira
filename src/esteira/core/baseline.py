"""Baseline: achados já conhecidos não reabrem o portão do CI.

Um repositório legado que roda o Esteira pela primeira vez pode ter dezenas de achados
antigos que ninguém vai corrigir hoje — sem uma baseline, `--fail-on` fica vermelho para
sempre e o time aprende a ignorar o portão. `esteira baseline gravar` fotografa os achados
atuais; `esteira scan --baseline` marca quem já estava na foto com `origem="baseline"` (ver
`ScanResult.max_severity`) sem escondê-lo do relatório — o achado continua visível, só não
derruba o build.

A identidade de um achado é o MESMO fingerprint do SARIF (`report.sarif._fingerprint`): sem
o número da linha, então reindentar o workflow não move o achado para fora da baseline.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from esteira.core.models import Finding, ScanResult
from esteira.report.sarif import _fingerprint

SCHEMA = "esteira-baseline/1"


class BaselineInvalida(Exception):
    """Arquivo de baseline ausente, ilegível ou de schema desconhecido.

    Fail-closed por escolha: um `--baseline` apontando para um caminho com erro de digitação
    não pode rodar SILENCIOSAMENTE sem baseline — isso reabriria achados que o operador
    considerava suprimidos, sem aviso nenhum. Preferível a varredura parar.
    """


def _fingerprints_por_achado(result: ScanResult) -> list[tuple[Finding, str]]:
    """Um fingerprint por achado, na MESMA ordem/desempate que `report.sarif._results` usa.

    O desempate por ordinal importa aqui tanto quanto no SARIF: dois achados idênticos (mesma
    checagem, caminho e evidência) recebem fingerprints diferentes, senão gravar a baseline com
    um dos dois suprimiria os dois.
    """
    vistos: dict[tuple[str, str, str], int] = {}
    saida: list[tuple[Finding, str]] = []
    for finding in result.sorted():
        chave = (finding.check_id, finding.path, finding.evidence or finding.detail)
        ordinal = vistos.get(chave, 0)
        vistos[chave] = ordinal + 1
        saida.append((finding, _fingerprint(finding, ordinal)))
    return saida


def gravar(path: Path, result: ScanResult) -> int:
    """Grava em `path` o fingerprint de cada achado da varredura atual.

    Devolve quantos achados entraram na baseline. Lista ordenada: o arquivo é gravado de novo
    a cada `baseline gravar` e um diff de git legível importa mais que a ordem de descoberta.
    """
    fingerprints = sorted({fp for _, fp in _fingerprints_por_achado(result)})
    documento = {"schema": SCHEMA, "fingerprints": fingerprints}
    path.write_text(json.dumps(documento, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(fingerprints)


def carregar(path: Path) -> frozenset[str]:
    """Lê uma baseline gravada. Qualquer coisa fora do formato esperado é `BaselineInvalida`
    — nunca um conjunto vazio silencioso, que equivaleria a rodar sem `--baseline`."""
    if not path.is_file():
        raise BaselineInvalida(f"arquivo de baseline não encontrado: {path}")
    try:
        documento = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineInvalida(f"baseline não é JSON válido ({path}): {exc}") from exc
    if not isinstance(documento, dict) or documento.get("schema") != SCHEMA:
        raise BaselineInvalida(f"baseline com schema ausente ou desconhecido: {path}")
    fingerprints = documento.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(f, str) for f in fingerprints):
        raise BaselineInvalida(f"baseline malformada (campo 'fingerprints'): {path}")
    return frozenset(fingerprints)


def aplicar(result: ScanResult, fingerprints: frozenset[str]) -> ScanResult:
    """Marca `origem="baseline"` nos achados cujo fingerprint já estava na baseline.

    Não remove nada de `findings` nem reordena: o relatório (console/JSON/SARIF) continua
    listando o achado, e só `ScanResult.max_severity` — logo `--fail-on` — passa a ignorá-lo.
    """
    if not fingerprints:
        return result
    fp_por_id = {id(finding): fp for finding, fp in _fingerprints_por_achado(result)}
    marcados = [
        dataclasses.replace(finding, origem="baseline")
        if fp_por_id[id(finding)] in fingerprints
        else finding
        for finding in result.findings
    ]
    return dataclasses.replace(result, findings=marcados)
