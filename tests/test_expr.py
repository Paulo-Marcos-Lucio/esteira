"""Gramática de expressão do GitHub Actions (ES-04a): `checks/expr.py`.

INVARIANTE DE CLASSE (a razão do módulo existir): um literal de string que contenha o
TEXTO de um caminho de contexto não é um ACESSO a esse contexto. `_untrusted_hit`
(`checks/detectors.py`) hoje confunde os dois porque casa substring sobre o texto
inteiro da expressão; `contextos(parse(e))` tem que separar os dois sempre — é essa
separação, não o parser em si, que vira entregável público quando `check_script_injection`
passar a consumi-lo (ES-04c, item separado).
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esteira.checks.expr import (
    BinOp,
    Chamada,
    Contexto,
    ExprError,
    Literal,
    UnOp,
    classificar,
    contextos,
    parse,
    sempre_verdadeira,
    tokenizar,
)

# --------------------------------------------------------------------------- #
# tokenizar
# --------------------------------------------------------------------------- #


def test_tokenizar_reconhece_cada_classe_de_token() -> None:
    tokens = tokenizar("github.actor == 'dependabot[bot]' && !contains(a, b)")
    tipos = [t.tipo for t in tokens]
    assert tipos == [
        "id", "dot", "id", "op", "str", "op", "op", "id", "lparen", "id", "comma", "id", "rparen",
    ]  # fmt: skip


def test_tokenizar_ignora_espacos_mas_preserva_posicao() -> None:
    tokens = tokenizar("  a  ==  b  ")
    assert [t.valor for t in tokens] == ["a", "==", "b"]
    assert tokens[0].pos == 2  # a posição aponta pro caractere real, não pro início


def test_tokenizar_idioma_sem_espaco_ao_redor_do_operador() -> None:
    """O idioma 'a||b' (sem espaço) tokeniza igual a 'a || b' — '||' não vira dois '|'."""
    assert [t.valor for t in tokenizar("a||b")] == ["a", "||", "b"]
    assert [t.valor for t in tokenizar("a&&b")] == ["a", "&&", "b"]


def test_tokenizar_string_com_aspas_simples_escapadas() -> None:
    # GitHub Actions escapa aspas simples DOBRANDO ('' dentro de '...'), sem backslash.
    [tok] = tokenizar("'it''s ok'")
    assert tok.tipo == "str"
    assert tok.valor == "'it''s ok'"


def test_tokenizar_caractere_fora_da_gramatica_levanta_exprerror() -> None:
    with pytest.raises(ExprError):
        tokenizar("a | b")  # '|' solto (só '||' existe)


# --------------------------------------------------------------------------- #
# parse — literais, acessos, chamadas, operadores (cada classe do critério)
# --------------------------------------------------------------------------- #


def test_parse_literal_string() -> None:
    assert parse("'abc'") == Literal("abc")


def test_parse_literal_numero_inteiro_e_decimal_e_negativo() -> None:
    assert parse("42") == Literal(42.0)
    assert parse("3.5") == Literal(3.5)
    assert parse("-1") == Literal(-1.0)


def test_parse_literal_booleano_e_null_sao_case_insensitive() -> None:
    assert parse("true") == Literal(True)
    assert parse("False") == Literal(False)
    assert parse("NULL") == Literal(None)


def test_parse_acesso_por_ponto() -> None:
    assert parse("github.event.issue.title") == Contexto(("github", "event", "issue", "title"))


def test_parse_acesso_por_colchete_normaliza_igual_ao_ponto() -> None:
    assert parse("github['event']['issue']['title']") == parse("github.event.issue.title")


def test_parse_acesso_mistura_ponto_e_colchete() -> None:
    assert parse("matrix.os['name']") == Contexto(("matrix", "os", "name"))


def test_parse_acesso_por_colchete_com_indice_numerico() -> None:
    assert parse("matrix.lista[0]") == Contexto(("matrix", "lista", "0"))


def test_parse_chamada_sem_args_com_1_e_com_varios() -> None:
    assert parse("success()") == Chamada("success", ())
    assert parse("contains(github.actor, 'x')") == Chamada(
        "contains", (Contexto(("github", "actor")), Literal("x"))
    )


def test_parse_operador_de_comparacao() -> None:
    assert parse("github.actor == 'x'") == BinOp("==", Contexto(("github", "actor")), Literal("x"))
    for op in ("==", "!=", "<", "<=", ">", ">="):
        parse(f"a {op} b")  # não levanta — todos os 6 comparadores são suportados


def test_parse_operador_unario_de_negacao() -> None:
    assert parse("!github.event.pages") == UnOp("!", Contexto(("github", "event", "pages")))


def test_parse_idioma_e_e_ou_com_e_sem_espaco() -> None:
    """'o idioma a||b': && e || — com e sem espaço ao redor — fazem parte da gramática."""
    esperado = BinOp("||", Contexto(("a",)), Contexto(("b",)))
    assert parse("a || b") == esperado
    assert parse("a||b") == esperado
    assert parse("a && b") == BinOp("&&", Contexto(("a",)), Contexto(("b",)))


def test_parse_precedencia_or_e_mais_baixa_que_and() -> None:
    # 'a && b || c' é '(a && b) || c', não 'a && (b || c)' — mesma precedência do
    # GitHub Actions (&& mais apertado que ||).
    assert parse("a && b || c") == BinOp(
        "||", BinOp("&&", Contexto(("a",)), Contexto(("b",))), Contexto(("c",))
    )


def test_parse_parenteses_alteram_precedencia() -> None:
    assert parse("a && (b || c)") == BinOp(
        "&&", Contexto(("a",)), BinOp("||", Contexto(("b",)), Contexto(("c",)))
    )


@pytest.mark.parametrize(
    "fonte",
    [
        "",
        "(a",
        "a +",
        "a | b",  # '|' solto
        "a.1x",  # propriedade não é identificador válido
        "foo[bar]",  # índice dinâmico (não-literal) — fora da gramática de propósito
        "a == b)",
        "a,b",
        "(a,b)",  # ')' esperado depois da expressão entre parênteses, achou ','
        ",a",  # posição de primário não aceita ','
        "f(a b)",  # args sem vírgula entre eles
        "a[0x]",  # ']' esperado depois do índice, achou outro token
    ],
)
def test_parse_sintaxe_fora_da_gramatica_levanta_exprerror(fonte: str) -> None:
    with pytest.raises(ExprError):
        parse(fonte)


# --------------------------------------------------------------------------- #
# contextos — round-trip determinístico, incluindo o caso que motivou o item
# --------------------------------------------------------------------------- #


def test_contextos_de_um_acesso_simples() -> None:
    assert contextos(parse("github.event.issue.title")) == {"github.event.issue.title"}


def test_contextos_normaliza_para_minusculo() -> None:
    assert contextos(parse("GitHub.Event.Issue.Title")) == {"github.event.issue.title"}


def test_contextos_atravessa_chamada_e_operadores() -> None:
    arvore = parse("contains(github.actor, 'x') && secrets.TOKEN != ''")
    assert contextos(arvore) == {"github.actor", "secrets.token"}


def test_contextos_de_um_literal_e_vazio() -> None:
    assert contextos(parse("'abc'")) == set()
    assert contextos(parse("42")) == set()


def test_contextos_nao_confunde_literal_de_string_com_acesso_ao_contexto() -> None:
    """O caso concreto que bloqueava ES-04c: o caminho dentro das aspas, como argumento
    LITERAL de format(), não é um acesso — contextos() não pode devolvê-lo."""
    arvore = parse("format('{0}', 'github.event.issue.title')")
    assert contextos(arvore) == set()


def test_contextos_de_tojson_continua_expondo_o_contexto_do_argumento() -> None:
    assert contextos(parse("toJSON(github.event.issue)")) == {"github.event.issue"}


def test_contextos_atravessa_negacao() -> None:
    assert contextos(parse("!github.actor")) == {"github.actor"}


@st.composite
def _expr_arvore(draw: st.DrawFn, profundidade: int = 3) -> tuple[str, frozenset[str]]:
    """Gera (texto, caminhos_plantados) de uma expressão GitHub Actions válida — a
    árvore cresce em `||`/`&&`/chamada, com literais e acessos a contexto nas folhas."""
    ident = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6)
    # 'true'/'false'/'null' são palavras reservadas da gramática: um identificador com
    # esse texto na PRIMEIRA posição de um caminho vira o literal, não um acesso — não é
    # bug do parser, é a mesma regra que o GitHub Actions real aplica. O gerador evita a
    # colisão em vez de ensinar o oráculo a prever essa ambiguidade.
    caminho_valido = st.lists(ident, min_size=1, max_size=4).filter(
        lambda partes: partes[0] not in ("true", "false", "null")
    )
    if profundidade <= 0 or draw(st.booleans()):
        escolha = draw(st.integers(0, 2))
        if escolha == 0:
            texto = draw(st.text(alphabet="abcxyz ", max_size=6))
            return f"'{texto}'", frozenset()
        if escolha == 1:
            return draw(st.sampled_from(["true", "false"])), frozenset()
        partes = draw(caminho_valido)
        caminho = ".".join(partes)
        return caminho, frozenset({caminho})
    escolha = draw(st.sampled_from(["||", "&&", "==", "chamada"]))
    if escolha == "chamada":
        nome = draw(ident)
        n = draw(st.integers(0, 2))
        textos: list[str] = []
        plantados: frozenset[str] = frozenset()
        for _ in range(n):
            texto, caminhos = draw(_expr_arvore(profundidade=profundidade - 1))
            textos.append(texto)
            plantados |= caminhos
        return f"{nome}({', '.join(textos)})", plantados
    esq_texto, esq_plantados = draw(_expr_arvore(profundidade=profundidade - 1))
    dir_texto, dir_plantados = draw(_expr_arvore(profundidade=profundidade - 1))
    return f"({esq_texto}) {escolha} ({dir_texto})", esq_plantados | dir_plantados


@given(par=_expr_arvore())
@settings(max_examples=200)
def test_contextos_contem_todos_os_caminhos_plantados(par: tuple[str, frozenset[str]]) -> None:
    """INVARIANTE DE CLASSE (round-trip): para qualquer expressão válida desta
    gramática, `contextos(parse(e))` contém TODO caminho de contexto plantado nela —
    não um subconjunto, não um caminho perdido dentro de um `&&`/`||`/chamada aninhado."""
    texto, plantados = par
    arvore = parse(texto)
    assert plantados <= contextos(arvore)


# --------------------------------------------------------------------------- #
# classificar
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fonte, esperado",
    [
        ("'x'", "literal"),
        ("42", "literal"),
        ("true", "literal"),
        ("github.actor", "acesso"),
        ("contains(a, b)", "chamada"),
        ("a == b", "operador"),
        ("!a", "operador"),
        ("a || b", "operador"),
    ],
)
def test_classificar_o_no_de_topo(fonte: str, esperado: str) -> None:
    assert classificar(parse(fonte)) == esperado


# --------------------------------------------------------------------------- #
# sempre_verdadeira
# --------------------------------------------------------------------------- #


def test_sempre_verdadeira_literal_true_e_false() -> None:
    assert sempre_verdadeira(parse("true")) is True
    assert sempre_verdadeira(parse("false")) is False


def test_sempre_verdadeira_autocomparacao_estrutural() -> None:
    assert sempre_verdadeira(parse("github.actor == github.actor")) is True
    # espaçamento/parênteses diferentes não mudam a árvore — mesma prova.
    assert sempre_verdadeira(parse("(github.actor)==(github.actor)")) is True


def test_sempre_verdadeira_comparacao_de_campos_diferentes_nao_e_provada() -> None:
    assert sempre_verdadeira(parse("github.actor == github.sha")) is False


def test_sempre_verdadeira_acesso_cru_nao_e_provada() -> None:
    # Um acesso a contexto sozinho não é booleano sabido — não é "sempre verdadeiro".
    assert sempre_verdadeira(parse("github.actor")) is False


def test_sempre_verdadeira_idioma_or_e_and_propaga_a_prova() -> None:
    """O idioma 'a || b': se um lado já está provado, '||' todo está — com
    curto-circuito, não importa o que o outro lado seja."""
    assert sempre_verdadeira(parse("true || github.actor == 'x'")) is True
    assert sempre_verdadeira(parse("github.actor == 'x' || true")) is True
    assert sempre_verdadeira(parse("false && github.actor == 'x'")) is False
    assert sempre_verdadeira(parse("true && true")) is True


def test_sempre_verdadeira_nao_tenta_tautologia_geral() -> None:
    # Falso negativo é seguro aqui (só não dispara); o item pede só a prova estreita.
    assert sempre_verdadeira(parse("!(!true)")) is False
