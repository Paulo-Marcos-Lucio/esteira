"""ES-02b — `secret-to-thirdparty-action` subsome `unpinned-action-thirdparty` quando os dois
caem no mesmo (path, linha do `uses:`, `action@ref`).

Antes, uma action de terceiros não fixada por SHA que também recebia um segredo gerava DOIS
achados sobre a MESMA linha: `unpinned-action-thirdparty` (a pinagem) e
`secret-to-thirdparty-action` (o segredo indo para essa pinagem) — o segundo é estritamente
mais informativo que o primeiro (ele já diz que não é SHA E que carrega segredo), então listar
os dois é o mesmo defeito contado duas vezes. `_SUBSUME` em `detectors.py` resolve isso: o
achado mais específico continua visível, o mais genérico migra para `suppressed` com
`origem="subsuncao"`.

Os testes aqui são de CLASSE (property-based, Hypothesis): não fixam um exemplo, variam quantos
steps existem e quais carregam segredo, e afirmam o invariante que não pode voltar a quebrar —
inclusive o caso de borda em que o achado subsumidor foi ele mesmo calado por diretiva inline
(aí o subsumido TEM que voltar a aparecer, senão os dois somem e o problema de pinagem, que
ninguém pediu para ignorar, fica sem nenhum rastro no relatório).
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.engine import scan


def _write(tmp_path: Path, body: str) -> Path:
    wf = tmp_path / ".github" / "workflows" / "w.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + body,
        encoding="utf-8",
    )
    return tmp_path


def _step(i: int, *, com_segredo: bool) -> str:
    uses = f"      - uses: some-org/action-{i}@v1\n"
    if not com_segredo:
        return uses
    return uses + "        with:\n          token: ${{ secrets.GITHUB_TOKEN }}\n"


def _visiveis(root: Path, cid: str) -> list:
    return [f for f in scan(root).findings if f.check_id == cid]


def _suprimidos(root: Path, cid: str) -> list:
    return [s for s in scan(root).suppressed if s.finding.check_id == cid]


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(com_segredo=st.lists(st.booleans(), min_size=1, max_size=8))
def test_subsuncao_e_exatamente_os_steps_com_segredo(
    com_segredo: list[bool], tmp_path: Path
) -> None:
    """Invariante de classe: para QUALQUER mistura de steps de terceiros não fixados por SHA,
    com e sem segredo, 'unpinned-action-thirdparty' fica suprimido (origem='subsuncao') SE E
    SÓ SE aquele step também disparou 'secret-to-thirdparty-action' — nunca menos (perderia o
    segredo) nem mais (apagaria pinagem de step que não tem segredo nenhum)."""
    body = "".join(_step(i, com_segredo=c) for i, c in enumerate(com_segredo))
    root = _write(tmp_path, body)

    n_com_segredo = sum(com_segredo)
    n_sem_segredo = len(com_segredo) - n_com_segredo

    assert len(_visiveis(root, "secret-to-thirdparty-action")) == n_com_segredo
    # exatamente os steps SEM segredo continuam com unpinned-action-thirdparty visível
    assert len(_visiveis(root, "unpinned-action-thirdparty")) == n_sem_segredo
    # exatamente os steps COM segredo tiveram o par redundante calado por subsunção
    suprimidos = _suprimidos(root, "unpinned-action-thirdparty")
    assert len(suprimidos) == n_com_segredo
    assert all(s.origem == "subsuncao" for s in suprimidos)


def test_subsumidor_suprimido_inline_nao_apaga_o_subsumido(tmp_path: Path) -> None:
    """Caso de borda: se alguém calar especificamente o achado mais específico
    ('# esteira: ignore[secret-to-thirdparty-action]'), o mais genérico não pode desaparecer
    junto — senão a pinagem por tag, que ninguém pediu para ignorar, fica sem nenhum rastro."""
    root = _write(
        tmp_path,
        "      - uses: some-org/deploy-action@v1\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}  "
        "# esteira: ignore[secret-to-thirdparty-action]\n",
    )
    result = scan(root)
    visiveis_ids = {f.check_id for f in result.findings}
    assert "unpinned-action-thirdparty" in visiveis_ids
    assert "secret-to-thirdparty-action" not in visiveis_ids
    suprimidos_por_id = {s.finding.check_id: s.origem for s in result.suppressed}
    assert suprimidos_por_id["secret-to-thirdparty-action"] == "inline"
    assert "unpinned-action-thirdparty" not in suprimidos_por_id


def test_action_oficial_ou_pinada_nunca_gera_subsuncao(tmp_path: Path) -> None:
    """Contraste: nem action oficial nem action de terceiro já fixada por SHA disparam
    'secret-to-thirdparty-action' — sem o subsumidor, não há subsunção, e nenhuma das duas
    tem 'unpinned-action-thirdparty' pra começo de conversa (oficial e SHA não disparam essa
    checagem também). A supressão não pode inventar achado onde não existia nenhum."""
    sha = "b4ffde65f46336ab88eb53be808477a3936bae11"
    root = _write(
        tmp_path,
        f"      - uses: actions/checkout@{sha}\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n"
        f"      - uses: peter-evans/create-pull-request@{sha}\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    result = scan(root)
    ids_todos = {f.check_id for f in result.findings} | {
        s.finding.check_id for s in result.suppressed
    }
    assert "secret-to-thirdparty-action" not in ids_todos
    assert "unpinned-action-thirdparty" not in ids_todos
