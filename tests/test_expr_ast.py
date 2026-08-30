"""Parser de expressão do GitHub Actions (`checks/expr_ast.py`): literais, contextos,
funções, operadores e os quatro casos citados no item (aninhamento, `format()`,
`contains()`, `&&`/`||`) e strings com chaves — mais a invariante de robustez contra
entrada hostil (o workflow é escrito por quem abre a PR de fork, não por quem audita).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esteira.checks.detectors import _EXPR
from esteira.checks.expr_ast import (
    BinaryOp,
    Call,
    ContextRoot,
    ExpressionSyntaxError,
    Literal,
    Member,
    Node,
    UnaryOp,
    context_path,
    parse,
)

# -- literais ------------------------------------------------------------------- #


def test_numeros_inteiro_float_negativo_e_notacao_cientifica() -> None:
    assert parse("42") == Literal(42)
    assert parse("3.14") == Literal(3.14)
    assert parse("-7") == Literal(-7)
    assert parse("1e-3") == Literal(0.001)


def test_string_simples_e_aspa_escapada() -> None:
    assert parse("'wip'") == Literal("wip")
    assert parse("'it''s here'") == Literal("it's here")


def test_booleanos_e_null_case_insensitive() -> None:
    assert parse("true") == Literal(True)
    assert parse("FALSE") == Literal(False)
    assert parse("Null") == Literal(None)


# -- contextos -------------------------------------------------------------------- #


def test_contexto_encadeado_por_ponto() -> None:
    arvore = parse("github.event.issue.title")
    assert arvore == Member(
        obj=Member(obj=Member(obj=ContextRoot("github"), name="event"), name="issue"),
        name="title",
    )
    assert context_path(arvore) == "github.event.issue.title"


def test_contexto_por_colchete_produz_a_mesma_arvore_que_por_ponto() -> None:
    """`github['event']['issue']['title']` é o MESMO contexto perigoso que a forma com
    ponto — só ofuscado. Um detector estrutural não pode deixar essa forma passar."""
    ponto = parse("github.event.issue.title")
    colchete = parse("github['event']['issue']['title']")
    assert ponto == colchete
    assert context_path(colchete) == "github.event.issue.title"


def test_member_exige_exatamente_uma_forma() -> None:
    """`Member` é `frozen`, mas não é irrestrito: `name`, `key` e `wildcard` são as
    TRÊS formas de acesso, mutuamente exclusivas — o parser nunca constrói um `Member`
    inconsistente, mas o dataclass barra isso mesmo assim (defesa em profundidade)."""
    base = ContextRoot("github")
    with pytest.raises(ValueError):
        Member(obj=base)  # nenhuma forma
    with pytest.raises(ValueError):
        Member(obj=base, name="event", wildcard=True)  # duas formas


def test_context_path_de_uma_chamada_e_none() -> None:
    """`success().foo` não é um contexto — a RAIZ da cadeia é uma chamada, não um
    `ContextRoot`, então não há path fixo para comparar contra `_UNTRUSTED`."""
    arvore = parse("success().foo")
    assert isinstance(arvore, Member)
    assert context_path(arvore) is None


def test_indice_computado_nao_normaliza_para_path_fixo() -> None:
    """`matrix[chave]` — `chave` é OUTRO contexto, não um literal: não dá para achatar
    num path fixo sem saber, em tempo de execução, o que `chave` vale."""
    arvore = parse("matrix[chave]")
    assert isinstance(arvore, Member)
    assert arvore.name is None
    assert arvore.key == ContextRoot("chave")
    assert context_path(arvore) is None


def test_filtro_de_objeto_wildcard() -> None:
    arvore = parse("github.event.commits.*.author")
    assert isinstance(arvore, Member)
    assert arvore.name == "author"  # o `.author` FINAL, depois do filtro
    filtro = arvore.obj
    assert isinstance(filtro, Member)
    assert filtro.wildcard is True
    assert context_path(arvore) is None  # wildcard no meio: sem path fixo


def test_filtro_de_objeto_wildcard_por_colchete() -> None:
    """`x[*]` é a mesma forma de filtro que `x.*`, só com sintaxe de colchete."""
    arvore = parse("github.event.commits[*].author")
    assert isinstance(arvore, Member) and arvore.name == "author"
    assert isinstance(arvore.obj, Member) and arvore.obj.wildcard is True


# -- funções (contains, format) ---------------------------------------------------- #


def test_contains_com_contexto_e_literal() -> None:
    arvore = parse("contains(github.event.head_commit.message, 'wip')")
    assert isinstance(arvore, Call)
    assert arvore.name == "contains"
    assert len(arvore.args) == 2
    assert context_path(arvore.args[0]) == "github.event.head_commit.message"
    assert arvore.args[1] == Literal("wip")


def test_format_com_string_contendo_chaves_nao_confunde_o_parser() -> None:
    """O CENÁRIO do item: `{0}`/`{1}` dentro da string do `format()` são texto — não
    podem virar token de expressão nem enganar o parser sobre onde a string termina."""
    arvore = parse("format('{0} disse: {1}', github.actor, 'oi')")
    assert isinstance(arvore, Call)
    assert arvore.name == "format"
    assert arvore.args[0] == Literal("{0} disse: {1}")
    assert context_path(arvore.args[1]) == "github.actor"
    assert arvore.args[2] == Literal("oi")


def test_chamada_aninhada_em_argumento() -> None:
    arvore = parse("contains(fromJSON(steps.x.outputs.result).items, 'a')")
    assert isinstance(arvore, Call)
    primeiro_arg = arvore.args[0]
    assert isinstance(primeiro_arg, Member)
    assert primeiro_arg.name == "items"
    assert isinstance(primeiro_arg.obj, Call)
    assert primeiro_arg.obj.name == "fromJSON"


def test_chamada_sem_argumentos() -> None:
    assert parse("success()") == Call(name="success", args=())


# -- operadores e precedência (&&/||, aninhamento por parênteses) ------------------ #


def test_and_e_or_com_precedencia_padrao() -> None:
    """`&&` prende mais forte que `||`: `a || b && c` é `a || (b && c)`, não
    `(a || b) && c` — é a MESMA regra de Python/C/JS que a especificação do GitHub
    Actions documenta para expressões."""
    arvore = parse("a == 1 || b == 2 && c")
    assert isinstance(arvore, BinaryOp)
    assert arvore.op == "||"
    assert isinstance(arvore.right, BinaryOp)
    assert arvore.right.op == "&&"


def test_parenteses_sobrepoe_a_precedencia() -> None:
    arvore = parse("(a || b) && c")
    assert isinstance(arvore, BinaryOp)
    assert arvore.op == "&&"
    assert isinstance(arvore.left, BinaryOp)
    assert arvore.left.op == "||"


def test_negacao_unaria_e_dupla() -> None:
    arvore = parse("!success()")
    assert arvore == UnaryOp(op="!", operand=Call(name="success", args=()))
    dupla = parse("!!contains(a, b)")
    assert isinstance(dupla, UnaryOp) and isinstance(dupla.operand, UnaryOp)


def test_todos_os_operadores_relacionais_e_de_igualdade() -> None:
    for op in ("==", "!=", "<", "<=", ">", ">="):
        arvore = parse(f"a {op} 1")
        assert isinstance(arvore, BinaryOp)
        assert arvore.op == op


def test_aninhamento_de_parenteses_profundo_mas_dentro_do_teto() -> None:
    profundidade = 40
    texto = "(" * profundidade + "true" + ")" * profundidade
    arvore = parse(texto)
    assert arvore == Literal(True)


# -- integração com o texto real de um workflow (via _EXPR, sem alterar detectors.py) - #


def test_parseia_toda_expressao_extraida_de_um_run_real() -> None:
    """Usa o MESMO regex que os detectores já usam para achar `${{ }}` num `run:` —
    prova que a árvore consegue receber o que `_EXPR` de fato extrai, sem tocar em
    `detectors.py`."""
    run = (
        "echo \"${{ format('Olá {0}, PR de {1}', github.actor, "
        'github.event.pull_request.title) }}"\n'
        "if [ \"${{ contains(github.event.head_commit.message, 'release') }}\" ]; then\n"
    )
    expressoes = [m.group(1) for m in _EXPR.finditer(run)]
    assert len(expressoes) == 2
    for expressao in expressoes:
        parse(expressao)  # não levanta


# -- entrada malformada: erro controlado, nunca exceção não documentada ------------ #


@pytest.mark.parametrize(
    "texto",
    [
        "",
        "(",
        "a ==",
        "a == ) b",
        "'sem fechar",
        "contains(a, b",
        "a && && b",
        "€",
        "a.{",
        "a[",
    ],
)
def test_entrada_malformada_levanta_expression_syntax_error(texto: str) -> None:
    with pytest.raises(ExpressionSyntaxError):
        parse(texto)


def test_aninhamento_alem_do_teto_e_erro_controlado_nao_recursionerror() -> None:
    """O arquivo de workflow é entrada de terceiro (PR de fork). Sem teto, aninhamento
    hostil (`((((...))))` fundo demais) estoura a pilha do Python — `RecursionError`,
    não documentado por `parse()` — em vez de um erro que o chamador já sabe tratar."""
    texto = "(" * 500 + "true" + ")" * 500
    with pytest.raises(ExpressionSyntaxError):
        parse(texto)


# -- invariante de classe: NUNCA uma exceção fora do contrato ---------------------- #

_CARACTERES = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,()[]{}'!&|=<>*_-\"$\n"
)


@given(texto=st.text(alphabet=_CARACTERES, min_size=0, max_size=60))
@settings(max_examples=500)
def test_parse_nunca_levanta_excecao_fora_do_contrato(texto: str) -> None:
    """Para QUALQUER string (não só as bem-formadas de propósito acima), `parse()`
    devolve uma árvore OU levanta `ExpressionSyntaxError` — nunca `RecursionError`,
    `IndexError`, `KeyError` ou qualquer outra exceção que o chamador não tem como
    prever. É a mesma classe de invariante que `MAX_JSON_DEPTH` prova no Chaveiro."""
    try:
        resultado = parse(texto)
    except ExpressionSyntaxError:
        return
    assert isinstance(resultado, Node)
