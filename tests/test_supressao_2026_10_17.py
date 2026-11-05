"""ES-01b — ``_supressao()`` devolve ``Supressao`` em vez de bool; ``run_all`` não filtra, anexa.

INVARIANTE central do item: nenhum achado desaparece do pipeline por causa de supressão
inline. Antes, o booleano de ``_is_suppressed`` filtrava o achado fora de ``run_all`` — um
``# esteira: ignore`` ou ``# zizmor: ignore`` ficava indistinguível de um achado que nunca
existiu. Agora o achado sobrevive em ``ScanResult.findings`` com ``Finding.suppression``
preenchido; só ``visiveis()``/``suprimidos()`` particionam por ele, e é esse particionamento
— não mais a lista crua — que decide ``max_severity()`` e, por consequência, o portão de
saída do CI (mantém o comportamento de hoje sem apagar informação no caminho).
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esteira.checks.engine import scan


def _linha(indice: int, suprimir: bool) -> str:
    sufixo = "  # esteira: ignore[script-injection]" if suprimir else ""
    return f'      - run: echo "achado {indice} ${{{{ github.event.issue.title }}}}"' + sufixo


def _escrever(tmp_path: Path, flags: list[bool]) -> Path:
    steps = "\n".join(_linha(i, flag) for i, flag in enumerate(flags))
    texto = (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n" + steps + "\n"
    )
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "w.yml").write_text(texto, encoding="utf-8")
    return tmp_path


@settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(flags=st.lists(st.booleans(), min_size=1, max_size=8))
def test_supressao_nunca_deleta_achado_do_pipeline(flags: list[bool], tmp_path: Path) -> None:
    """Para QUALQUER combinação de linhas suprimidas/não suprimidas, ``.findings`` tem um achado
    por ocorrência — suprimida ou não — e ``visiveis()``/``suprimidos()`` particionam exatamente
    por quem tinha a diretiva na linha, sem sobra e sem sobreposição."""
    resultado = scan(_escrever(tmp_path, flags))
    achados = [f for f in resultado.findings if f.check_id == "script-injection"]
    assert len(achados) == len(flags), "achado suprimido não pode desaparecer de .findings"
    assert len(resultado.suprimidos()) == sum(flags)
    assert len(resultado.visiveis()) == len(flags) - sum(flags)
    assert len(resultado.visiveis()) + len(resultado.suprimidos()) == len(resultado.findings)
    assert {id(f) for f in resultado.visiveis()} & {id(f) for f in resultado.suprimidos()} == set()


def test_achado_suprimido_fica_marcado_em_vez_de_apagado(tmp_path: Path) -> None:
    resultado = scan(_escrever(tmp_path, [True]))
    (achado,) = [f for f in resultado.findings if f.check_id == "script-injection"]
    assert achado.suppression is not None
    assert achado.suppression.diretiva == "esteira: ignore[script-injection]"
    assert achado not in resultado.visiveis()
    assert achado in resultado.suprimidos()


def test_achado_sem_diretiva_nao_tem_suppression(tmp_path: Path) -> None:
    resultado = scan(_escrever(tmp_path, [False]))
    (achado,) = [f for f in resultado.findings if f.check_id == "script-injection"]
    assert achado.suppression is None
    assert achado in resultado.visiveis()
    assert resultado.suprimidos() == []


def test_max_severity_opera_sobre_visiveis_nao_sobre_findings(tmp_path: Path) -> None:
    """O único achado do workflow está suprimido: max_severity() não pode herdar a severidade
    dele — é exatamente o comportamento de hoje (achado suprimido não reprovava o portão)."""
    resultado = scan(_escrever(tmp_path, [True]))
    assert {f.check_id for f in resultado.findings} == {"script-injection"}
    assert resultado.max_severity() is None


def test_zizmor_ignore_tambem_e_registrado_como_supressao(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    texto = (
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"  # zizmor: ignore[template-injection]\n'
    )
    (wf_dir / "w.yml").write_text(texto, encoding="utf-8")
    resultado = scan(tmp_path)
    (achado,) = [f for f in resultado.findings if f.check_id == "script-injection"]
    assert achado.suppression is not None
    assert achado.suppression.diretiva == "zizmor: ignore[template-injection]"
    assert achado in resultado.suprimidos()
