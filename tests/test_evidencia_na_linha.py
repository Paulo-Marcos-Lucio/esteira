"""ES-02c — invariante geral: 'a evidência citada existe na linha citada'.

Cada detector decide sozinho qual `line` ancorar e qual `evidence` citar — são ~30 pontos de
código que fazem essa escolha de forma independente (grep por `evidence=` no pacote `checks/`).
Nada impedia um deles de divergir: ancorar num step e citar o texto de outro. Quem lê o achado
no console/SARIF confia que abrir o arquivo na linha indicada mostra o que está sendo apontado —
se a evidência mora em outra linha, a citação engana.

Este teste roda os DOIS lados do corpus rotulado (`bench/positivos` + `bench/negativos`, que
`test_bench.py::test_corpus_cobre_o_catalogo_inteiro` já obriga a cobrir o catálogo inteiro) e
afirma, para TODO achado com evidência, que ela é substring literal da linha citada. Rodar sobre
o corpus real (via Hypothesis, não uma lista fixa de exemplos por checagem) é o que faz isto ser
uma invariante de TODOS os detectores, não um teste por checagem.

Escrever este teste expôs um caso real: `checkout-credentials-in-artifact` ancorava no `checkout`
e citava como evidência o `uses:` do `upload-artifact` — texto de outra linha. Corrigido em
`check_checkout_credentials` (detectors.py) para ancorar onde a evidência de fato está.

Allowlist (`_EVIDENCIA_SINTETICA`): dois check_ids cuja evidência não é, por desenho, um recorte
da linha citada:

  * `cache-poisoning` — ancora deliberadamente na ESCRITA não-confiável (o step acionável), não
    na linha da `key:`; `test_hardening.py::test_cache_poisoning_dispara` já tranca essa escolha
    junto com `evidence == "build-artifacts-shared"`. Mudar o anchor quebraria esse teste por uma
    troca de convenção, não por um bug.
  * `invalid-yaml` (ramo de falha de parse, `run_all`) — a evidência é a mensagem de erro do
    parser YAML (ex.: "expected ... (linha 11, coluna 1)"), um diagnóstico sintetizado por
    `_format_yaml_error`, nunca um recorte do arquivo — o arquivo não parseou, não há uma "linha
    do achado" no sentido normal.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.engine import scan

BENCH = Path(__file__).resolve().parent.parent / "bench"

_ARQUIVOS_CORPUS = sorted(
    p for sub in ("positivos", "negativos") for p in (BENCH / sub).glob("*.y*ml")
)
assert _ARQUIVOS_CORPUS, "corpus bench/ vazio — nada para o property test rodar"

# rótulos sintéticos: evidência que não é, por desenho, um recorte da linha citada (ver docstring)
_EVIDENCIA_SINTETICA = frozenset({"cache-poisoning", "invalid-yaml"})


@settings(max_examples=len(_ARQUIVOS_CORPUS), suppress_health_check=[HealthCheck.too_slow])
@given(arquivo=st.sampled_from(_ARQUIVOS_CORPUS))
def test_evidencia_e_substring_da_linha_citada(arquivo: Path) -> None:
    linhas = arquivo.read_text(encoding="utf-8").splitlines()
    for achado in scan(arquivo).findings:
        if achado.evidence is None or achado.check_id in _EVIDENCIA_SINTETICA:
            continue
        assert 1 <= achado.line <= len(linhas), (
            f"{arquivo.name}: {achado.check_id} cita a linha {achado.line}, fora do arquivo "
            f"({len(linhas)} linhas)"
        )
        linha_citada = linhas[achado.line - 1]
        assert achado.evidence in linha_citada, (
            f"{arquivo.name}: {achado.check_id} cita evidência {achado.evidence!r} que não "
            f"aparece na linha {achado.line} citada ({linha_citada!r})"
        )


def test_corpus_de_fato_exercita_achados_com_evidencia() -> None:
    """Sem isto, um corpus vazio ou um bug que zerasse `evidence` em toda parte deixaria o
    teste acima verde por vacuidade — o oposto do que ele deveria travar."""
    total = sum(
        1
        for arquivo in _ARQUIVOS_CORPUS
        for achado in scan(arquivo).findings
        if achado.evidence is not None and achado.check_id not in _EVIDENCIA_SINTETICA
    )
    assert total >= 10, f"corpus gerou só {total} achados com evidência não-sintética"
