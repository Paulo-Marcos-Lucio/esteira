"""Parser da linguagem de expressão do GitHub Actions (``${{ … }}``) — literais,
contextos, funções e operadores, virando ÁRVORE em vez de string.

Por quê: os detectores de hoje decidem por REGEX sobre o texto inteiro dentro de
``${{ }}`` (``_UNTRUSTED_RE`` em `detectors.py`) — "a substring `github.event.issue.body`
aparece em algum lugar da expressão" é tudo que se consegue perguntar. Isso não distingue
``github.event.issue.body`` usado de verdade de ``format('{0}', 'github.event.issue.body')``
(o mesmo texto, dentro de uma STRING — não é contexto nenhum) nem enxerga através de
``contains(needs.x.outputs.y, 'z')`` para saber que o primeiro argumento é um contexto e o
segundo é um literal. Uma árvore resolve os dois: cada nó SABE se é literal, referência de
contexto ou chamada de função, e apenas contextos preservam a semântica "isto vem de fora".

Este módulo só PARSEIA — não decide nada sobre confiabilidade nem altera nenhum detector.
``detectors.py`` continua usando ``_EXPR``/``_UNTRUSTED_RE`` como hoje; a substituição
desses regexes pela árvore é trabalho de item futuro, deliberadamente fora deste.

Gramática (baseada na especificação de expressões do GitHub Actions), do menor para o
maior precedência — segue a mesma ordem de ``||`` < ``&&`` < igualdade < relacional <
``!`` unário < primário que a documentação do GitHub descreve::

    expressao   := ou
    ou          := e ( '||' e )*
    e           := igualdade ( '&&' igualdade )*
    igualdade   := relacional ( ('=='|'!=') relacional )*
    relacional  := unario ( ('<'|'<='|'>'|'>=') unario )*
    unario      := '!' unario | primario
    primario    := literal | '(' expressao ')' | referencia
    referencia  := IDENT ('(' argumentos ')')? membro*
    membro      := '.' IDENT | '.' '*' | '[' expressao ']' | '[' '*' ']'
    argumentos  := (expressao (',' expressao)*)?
    literal     := NUMERO | STRING | 'true' | 'false' | 'null'

Não há operadores aritméticos (``+ - * /``) na linguagem — só o `*` de filtro de objeto
(``github.event.commits.*.author``, RFC informal do GitHub para "todo elemento do array").
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# --------------------------------------------------------------------------------- #
# árvore
# --------------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Literal:
    """``42``, ``3.14``, ``'texto'``, ``true``, ``false``, ``null``."""

    value: bool | int | float | str | None


@dataclass(frozen=True)
class ContextRoot:
    """Identificador solto que INICIA uma cadeia de acesso: ``github``, ``matrix``,
    ``env``, ``secrets``… — ou o nome de uma função quando seguido de ``(``, caso em
    que quem o produz é :class:`Call`, não este nó."""

    name: str


@dataclass(frozen=True)
class Member:
    """Acesso a propriedade de ``obj``: ponto (``name`` fixo) ou colchete (``key``,
    uma expressão computada) — ``github.event.issue.title`` e
    ``github['event']['issue']['title']`` produzem a MESMA árvore, porque colchete com
    string literal normaliza para o mesmo `name` do ponto (ver :func:`_normaliza_membro`).
    ``wildcard=True`` é o filtro de objeto ``.*``/``[*]`` — não tem `name` nem `key`.
    """

    obj: Node
    name: str | None = None
    key: Node | None = None
    wildcard: bool = False

    def __post_init__(self) -> None:
        formas = sum(x is not None for x in (self.name, self.key)) + int(self.wildcard)
        if formas != 1:
            raise ValueError("Member precisa de exatamente uma forma: name, key OU wildcard")


@dataclass(frozen=True)
class Call:
    """Chamada de função: ``contains(a, b)``, ``format('{0}', x)``, ``success()``."""

    name: str
    args: tuple[Node, ...]


@dataclass(frozen=True)
class UnaryOp:
    """A ÚNICA operação unária da linguagem: negação lógica (``!``)."""

    op: str
    operand: Node


@dataclass(frozen=True)
class BinaryOp:
    """``==`` ``!=`` ``<`` ``<=`` ``>`` ``>=`` ``&&`` ``||`` — nesta ordem de precedência
    crescente (``&&``/``||`` avaliam por último)."""

    op: str
    left: Node
    right: Node


Node = Literal | ContextRoot | Member | Call | UnaryOp | BinaryOp


def context_path(node: Node) -> str | None:
    """Achata uma cadeia de :class:`Member`/:class:`ContextRoot` sem wildcard/computado
    de volta para ``"github.event.issue.title"`` — o formato que os detectores hoje
    comparam contra ``_UNTRUSTED``. Retorna ``None`` para qualquer nó que não seja uma
    cadeia PURA de acesso por nome (uma :class:`Call`, um filtro ``.*``, um índice
    computado por expressão) — esses não têm path fixo para comparar."""
    partes: list[str] = []
    atual = node
    while isinstance(atual, Member):
        if atual.wildcard or atual.name is None:
            return None
        partes.append(atual.name)
        atual = atual.obj
    if not isinstance(atual, ContextRoot):
        return None
    partes.append(atual.name)
    return ".".join(reversed(partes))


# --------------------------------------------------------------------------------- #
# léxico
# --------------------------------------------------------------------------------- #


class ExpressionSyntaxError(ValueError):
    """Expressão malformada — posição (0-based) preservada em ``pos``."""

    def __init__(self, message: str, pos: int) -> None:
        super().__init__(f"{message} (posição {pos})")
        self.pos = pos


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    pos: int
    value: bool | int | float | str | None = None


# Uma alternativa por grupo nomeado; ordem importa só entre prefixos ambíguos
# (`<=`/`<`, `>=`/`>`, `==`/nada) — os operadores de 2 caracteres vêm primeiro.
_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
    | (?P<string>'(?:[^']|'')*')
    | (?P<andand>&&)
    | (?P<oror>\|\|)
    | (?P<eq>==)
    | (?P<ne>!=)
    | (?P<le><=)
    | (?P<ge>>=)
    | (?P<lt><)
    | (?P<gt>>)
    | (?P<bang>!)
    | (?P<dot>\.)
    | (?P<star>\*)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<lbracket>\[)
    | (?P<rbracket>\])
    | (?P<comma>,)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_-]*)
    """,
    re.VERBOSE,
)

_OPERADORES = frozenset({"andand", "oror", "eq", "ne", "le", "ge", "lt", "gt"})
_TEXTO_DO_OP = {
    "andand": "&&",
    "oror": "||",
    "eq": "==",
    "ne": "!=",
    "le": "<=",
    "ge": ">=",
    "lt": "<",
    "gt": ">",
}


def _tokenize(texto: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    fim = len(texto)
    while pos < fim:
        m = _TOKEN_RE.match(texto, pos)
        if m is None:
            raise ExpressionSyntaxError(f"caractere inesperado {texto[pos]!r}", pos)
        kind = m.lastgroup
        assert kind is not None
        trecho = m.group()
        pos = m.end()
        if kind == "ws":
            continue
        if kind == "number":
            valor: bool | int | float | str | None = (
                float(trecho) if "." in trecho or "e" in trecho.lower() else int(trecho)
            )
            tokens.append(_Token("number", trecho, m.start(), valor))
        elif kind == "string":
            # Aspas simples de fora removidas; `''` interno é a aspa simples ESCAPADA
            # (sintaxe da linguagem de expressão do GitHub, não Python) — não é fim de
            # string seguido de outra string colada.
            tokens.append(_Token("string", trecho, m.start(), trecho[1:-1].replace("''", "'")))
        elif kind == "ident":
            baixo = trecho.lower()
            if baixo == "true":
                tokens.append(_Token("bool", trecho, m.start(), True))
            elif baixo == "false":
                tokens.append(_Token("bool", trecho, m.start(), False))
            elif baixo == "null":
                tokens.append(_Token("null", trecho, m.start(), None))
            else:
                tokens.append(_Token("ident", trecho, m.start()))
        elif kind in _OPERADORES:
            tokens.append(_Token("op", _TEXTO_DO_OP[kind], m.start()))
        else:
            tokens.append(_Token(kind, trecho, m.start()))
    tokens.append(_Token("eof", "", fim))
    return tokens


# --------------------------------------------------------------------------------- #
# parser (descida recursiva)
# --------------------------------------------------------------------------------- #


#: Teto de aninhamento (parênteses, chamada dentro de chamada, `!` repetido). Uma
#: expressão de workflow legítima não passa de poucos níveis; sem o teto, um
#: `${{ ((((((((...))))))) }}` hostil (o arquivo de workflow é entrada de terceiro,
#: numa PR de fork) estoura a pilha do Python com `RecursionError` — não
#: `ExpressionSyntaxError` — derrubando quem chama `parse()` com uma exceção que não
#: está documentada para acontecer. Mesmo padrão do `MAX_JSON_DEPTH` do Chaveiro.
_MAX_PROFUNDIDADE = 64


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._i = 0
        self._profundidade = 0

    def _peek(self) -> _Token:
        return self._tokens[self._i]

    def _advance(self) -> _Token:
        tok = self._tokens[self._i]
        if tok.kind != "eof":
            self._i += 1
        return tok

    def _expect(self, kind: str, texto: str | None = None) -> _Token:
        tok = self._peek()
        if tok.kind != kind or (texto is not None and tok.text != texto):
            esperado = texto or kind
            raise ExpressionSyntaxError(
                f"esperava {esperado!r}, encontrei {tok.text or '<fim>'!r}", tok.pos
            )
        return self._advance()

    def parse(self) -> Node:
        node = self._or()
        fim = self._peek()
        if fim.kind != "eof":
            raise ExpressionSyntaxError(f"sobrou {fim.text!r} depois da expressão", fim.pos)
        return node

    def _binaria_esquerda(self, proximo: Callable[[_Parser], Node], *ops: str) -> Node:
        node = proximo(self)
        while self._peek().kind == "op" and self._peek().text in ops:
            op = self._advance().text
            node = BinaryOp(op=op, left=node, right=proximo(self))
        return node

    def _or(self) -> Node:
        return self._binaria_esquerda(_Parser._and, "||")

    def _and(self) -> Node:
        return self._binaria_esquerda(_Parser._igualdade, "&&")

    def _igualdade(self) -> Node:
        return self._binaria_esquerda(_Parser._relacional, "==", "!=")

    def _relacional(self) -> Node:
        return self._binaria_esquerda(_Parser._unario, "<", "<=", ">", ">=")

    def _unario(self) -> Node:
        self._profundidade += 1
        if self._profundidade > _MAX_PROFUNDIDADE:
            tok = self._peek()
            raise ExpressionSyntaxError(
                f"aninhamento além do teto ({_MAX_PROFUNDIDADE} níveis)", tok.pos
            )
        try:
            if self._peek().kind == "bang":
                self._advance()
                return UnaryOp(op="!", operand=self._unario())
            return self._primario()
        finally:
            self._profundidade -= 1

    def _primario(self) -> Node:
        tok = self._peek()
        if tok.kind == "number":
            self._advance()
            return Literal(value=tok.value)
        if tok.kind == "string":
            self._advance()
            return Literal(value=tok.value)
        if tok.kind == "bool":
            self._advance()
            return Literal(value=tok.value)
        if tok.kind == "null":
            self._advance()
            return Literal(value=None)
        if tok.kind == "lparen":
            self._advance()
            node = self._or()
            self._expect("rparen")
            return node
        if tok.kind == "ident":
            return self._referencia()
        raise ExpressionSyntaxError(f"token inesperado {tok.text or '<fim>'!r}", tok.pos)

    def _referencia(self) -> Node:
        nome = self._advance()  # ident
        node: Node
        if self._peek().kind == "lparen":
            self._advance()
            args = self._argumentos()
            self._expect("rparen")
            node = Call(name=nome.text, args=tuple(args))
        else:
            node = ContextRoot(name=nome.text)
        return self._membros(node)

    def _argumentos(self) -> list[Node]:
        if self._peek().kind == "rparen":
            return []
        args = [self._or()]
        while self._peek().kind == "comma":
            self._advance()
            args.append(self._or())
        return args

    def _membros(self, node: Node) -> Node:
        while True:
            tok = self._peek()
            if tok.kind == "dot":
                self._advance()
                if self._peek().kind == "star":
                    self._advance()
                    node = Member(obj=node, wildcard=True)
                    continue
                prop = self._expect("ident")
                node = Member(obj=node, name=prop.text)
                continue
            if tok.kind == "lbracket":
                self._advance()
                if self._peek().kind == "star":
                    self._advance()
                    self._expect("rbracket")
                    node = Member(obj=node, wildcard=True)
                    continue
                indice = self._or()
                self._expect("rbracket")
                node = _normaliza_membro(node, indice)
                continue
            return node


def _normaliza_membro(obj: Node, indice: Node) -> Member:
    """``x['nome']`` vira ``Member(obj=x, name='nome')`` — a MESMA árvore de ``x.nome``.
    Só string literal normaliza; ``x[i]`` com `i` computado vira `key=i` (não dá pra
    achatar em `context_path` sem saber o valor de `i` em tempo de execução)."""
    if isinstance(indice, Literal) and isinstance(indice.value, str):
        return Member(obj=obj, name=indice.value)
    return Member(obj=obj, key=indice)


def parse(texto: str) -> Node:
    """Parseia o CONTEÚDO de uma expressão — sem os delimitadores ``${{``/``}}`` (quem
    os remove é o chamador; ver `detectors._EXPR`, grupo 1). Levanta
    :class:`ExpressionSyntaxError` para sintaxe inválida — nunca retorna `None` nem
    engole o erro, porque uma expressão que não parseia e é tratada como "sem contexto
    perigoso" seria um falso-negativo silencioso."""
    return _Parser(_tokenize(texto)).parse()
