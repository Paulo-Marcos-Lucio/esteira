"""Gramática de expressão do GitHub Actions (``${{ ... }}``).

Por que existe: `_untrusted_hit` (`checks/detectors.py`) decide se um contexto
não-confiável aparece numa expressão casando uma SUBSTRING sobre o texto
inteiro. Isso confunde um literal de string com um acesso real — a substring
``'github.event.issue.title'``, dentro de aspas como argumento de
``format('{0}', 'github.event.issue.title')``, bate a mesma substring que o
acesso de verdade bateria, porque não existe distinção sintática entre os
dois sem uma árvore de parse. Este módulo é essa árvore: tokeniza e parseia
GitHub Actions Expressions (literais, acesso a contexto por ``.``/``[]``,
chamada de função, operadores unário/binário, incluindo o idioma
``a || b``) e expõe `contextos()` — os caminhos de contexto REALMENTE
referenciados, nunca os que aparecem, por acidente, dentro do texto de um
literal.

Escopo deste item (ES-04a): só o módulo — tokenizar/parse/contextos/
classificar/sempre_verdadeira. Consumi-lo em `check_script_injection` (para
que o literal dentro de `format()` pare de disparar) é ES-04c, item
separado; migrar a tabela de contextos não-confiáveis para o formato
"ATACANTE" é ES-04b. Uma expressão fora desta gramática (sintaxe que ela não
cobre) levanta `ExprError` — o comportamento esperado por quem for escrever
o fallback textual (ES-04b): "não parseou" é um resultado válido, não um bug
deste módulo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

# Ordem importa: operadores de 2 caracteres ANTES dos de 1, senão '&&' tokenizaria
# como dois '&' desconhecidos. '-?' no número aceita o literal negativo (a gramática
# do GitHub Actions não tem operador unário de subtração — o sinal é parte do literal).
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<op>==|!=|<=|>=|&&|\|\||[!<>])
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<lbracket>\[)
  | (?P<rbracket>\])
  | (?P<dot>\.)
  | (?P<comma>,)
  | (?P<id>[A-Za-z_][A-Za-z0-9_-]*)
    """,
    re.VERBOSE,
)


class ExprError(ValueError):
    """A expressão não parseia — sintaxe fora desta gramática (posição em `pos`)."""

    def __init__(self, mensagem: str, pos: int) -> None:
        super().__init__(f"{mensagem} (posição {pos})")
        self.pos = pos


@dataclass(frozen=True)
class Token:
    tipo: str  # "str" | "num" | "id" | "op" | "lparen" | "rparen" | "lbracket" | "rbracket" | "dot" | "comma"
    valor: str
    pos: int


def tokenizar(fonte: str) -> list[Token]:
    """Quebra `fonte` (o CONTEÚDO de um `${{ ... }}`, sem os delimitadores) em tokens.

    Levanta `ExprError` no primeiro caractere que não casa nenhum token — não tenta
    recuperar nem pular lixo: uma expressão malformada é "não parseou", não "parseou
    parcialmente".
    """
    tokens: list[Token] = []
    pos = 0
    while pos < len(fonte):
        m = _TOKEN_RE.match(fonte, pos)
        if m is None:
            raise ExprError(f"caractere inesperado {fonte[pos]!r}", pos)
        pos = m.end()
        tipo = m.lastgroup
        assert tipo is not None  # _TOKEN_RE só casa com um grupo nomeado, nunca vazio
        if tipo == "ws":
            continue
        tokens.append(Token(tipo, m.group(), m.start()))
    return tokens


# ---------------------------------------------------------------------------
# Árvore de parse
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Literal:
    """Um valor literal: string, número, booleano ou `null`."""

    valor: str | float | bool | None


@dataclass(frozen=True)
class Contexto:
    """Acesso a contexto por caminho — ex.: `github.event.issue.title`.

    `caminho` guarda os segmentos NA FORMA ORIGINAL (preserva maiúsculas); quem
    precisar comparar contra uma tabela de contextos não-confiáveis usa
    `contextos()`, que normaliza para minúsculo — a mesma convenção já usada por
    `_untrusted_hit` em `checks/detectors.py`.
    """

    caminho: tuple[str, ...]


@dataclass(frozen=True)
class Chamada:
    """Chamada de função — ex.: `contains(a, b)`, `toJSON(github.event)`."""

    nome: str
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class UnOp:
    """Operador unário — só `!` (negação) existe na gramática."""

    op: str
    operando: Expr


@dataclass(frozen=True)
class BinOp:
    """Operador binário: comparação (`==`/`!=`/`<`/`<=`/`>`/`>=`) ou lógico (`&&`/`||`)."""

    op: str
    esquerda: Expr
    direita: Expr


Expr = Literal | Contexto | Chamada | UnOp | BinOp

_CMP_OPS = ("==", "!=", "<=", ">=", "<", ">")
_BOOL_LITERAL = {"true": True, "false": False}


class _Parser:
    """Descida recursiva clássica, precedência crescente: `||` < `&&` < comparação <
    `!` unário < primário. É a mesma ordem de precedência documentada pelo GitHub
    Actions para GitHub Actions Expressions."""

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._i = 0

    def _pico(self) -> Token | None:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _consome(self) -> Token:
        tok = self._tokens[self._i]
        self._i += 1
        return tok

    def _fim_ou_erro(self, mensagem: str) -> Token:
        tok = self._pico()
        if tok is None:
            pos = self._tokens[-1].pos + len(self._tokens[-1].valor) if self._tokens else 0
            raise ExprError(mensagem, pos)
        return tok

    def parse(self) -> Expr:
        expr = self._ou()
        sobra = self._pico()
        if sobra is not None:
            raise ExprError(f"token inesperado {sobra.valor!r} após o fim da expressão", sobra.pos)
        return expr

    def _ou(self) -> Expr:
        esquerda = self._e()
        while (tok := self._pico()) is not None and tok.valor == "||":
            self._consome()
            esquerda = BinOp("||", esquerda, self._e())
        return esquerda

    def _e(self) -> Expr:
        esquerda = self._comparacao()
        while (tok := self._pico()) is not None and tok.valor == "&&":
            self._consome()
            esquerda = BinOp("&&", esquerda, self._comparacao())
        return esquerda

    def _comparacao(self) -> Expr:
        esquerda = self._unario()
        while (tok := self._pico()) is not None and tok.valor in _CMP_OPS:
            op = self._consome().valor
            esquerda = BinOp(op, esquerda, self._unario())
        return esquerda

    def _unario(self) -> Expr:
        tok = self._pico()
        if tok is not None and tok.valor == "!":
            self._consome()
            return UnOp("!", self._unario())
        return self._primario()

    def _primario(self) -> Expr:
        tok = self._fim_ou_erro("expressão incompleta")
        if tok.tipo == "lparen":
            self._consome()
            interna = self._ou()
            fechamento = self._fim_ou_erro("'(' sem o ')' correspondente")
            if fechamento.tipo != "rparen":
                raise ExprError("esperava ')'", fechamento.pos)
            self._consome()
            return interna
        if tok.tipo == "str":
            self._consome()
            return Literal(tok.valor[1:-1].replace("''", "'"))
        if tok.tipo == "num":
            self._consome()
            return Literal(float(tok.valor))
        if tok.tipo == "id":
            return self._identificador_ou_chamada()
        raise ExprError(f"token inesperado {tok.valor!r}", tok.pos)

    def _identificador_ou_chamada(self) -> Expr:
        primeiro = self._consome()
        baixo = primeiro.valor.lower()
        prox = self._pico()
        # Chamada: identificador diretamente seguido de '(' — nunca precedido de '.',
        # porque a gramática do GitHub Actions não tem métodos, só funções livres.
        if prox is not None and prox.tipo == "lparen":
            self._consome()
            args = self._lista_de_args()
            return Chamada(primeiro.valor, args)
        if baixo in _BOOL_LITERAL:
            return Literal(_BOOL_LITERAL[baixo])
        if baixo == "null":
            return Literal(None)
        caminho = [primeiro.valor]
        while True:
            prox = self._pico()
            if prox is not None and prox.tipo == "dot":
                self._consome()
                nome = self._fim_ou_erro("'.' sem nome de propriedade depois")
                if nome.tipo != "id":
                    raise ExprError("esperava um nome de propriedade após '.'", nome.pos)
                self._consome()
                caminho.append(nome.valor)
                continue
            if prox is not None and prox.tipo == "lbracket":
                self._consome()
                chave = self._fim_ou_erro("'[' sem o conteúdo esperado")
                # Só índice/chave LITERAL (string ou número): o caminho de contexto
                # precisa ser estático para `contextos()` enxergá-lo. Uma chave
                # dinâmica (ex.: `obj[steps.x.outputs.y]`) está fora desta gramática —
                # ExprError, não um palpite sobre o que ela resolveria em runtime.
                if chave.tipo == "str":
                    caminho.append(chave.valor[1:-1].replace("''", "'"))
                elif chave.tipo == "num":
                    caminho.append(chave.valor)
                else:
                    raise ExprError("'[...]' só aceita um literal (string ou número)", chave.pos)
                self._consome()
                fechamento = self._fim_ou_erro("'[' sem o ']' correspondente")
                if fechamento.tipo != "rbracket":
                    raise ExprError("esperava ']'", fechamento.pos)
                self._consome()
                continue
            break
        return Contexto(tuple(caminho))

    def _lista_de_args(self) -> tuple[Expr, ...]:
        tok = self._fim_ou_erro("'(' sem o ')' correspondente")
        if tok.tipo == "rparen":
            self._consome()
            return ()
        args = [self._ou()]
        while True:
            tok = self._fim_ou_erro("',' ou ')' esperado")
            if tok.tipo == "comma":
                self._consome()
                args.append(self._ou())
                continue
            if tok.tipo == "rparen":
                self._consome()
                return tuple(args)
            raise ExprError("esperava ',' ou ')'", tok.pos)


def parse(fonte: str) -> Expr:
    """Parseia `fonte` (o conteúdo de um `${{ ... }}`) numa árvore `Expr`.

    Levanta `ExprError` quando `fonte` usa sintaxe fora desta gramática.
    """
    return _Parser(tokenizar(fonte)).parse()


def contextos(expr: Expr) -> set[str]:
    """Os caminhos de contexto REALMENTE referenciados em `expr` (ex.:
    ``{"github.event.issue.title"}``) — nunca os que aparecem apenas dentro do
    texto de um `Literal` de string. Caminhos normalizados em minúsculo, a mesma
    convenção de `_untrusted_hit` em `checks/detectors.py`.
    """
    achados: set[str] = set()

    def _andar(no: Expr) -> None:
        if isinstance(no, Contexto):
            achados.add(".".join(no.caminho).lower())
        elif isinstance(no, Chamada):
            for arg in no.args:
                _andar(arg)
        elif isinstance(no, UnOp):
            _andar(no.operando)
        elif isinstance(no, BinOp):
            _andar(no.esquerda)
            _andar(no.direita)
        # Literal: folha — nada a percorrer.

    _andar(expr)
    return achados


def classificar(expr: Expr) -> str:
    """O tipo do nó de TOPO de `expr`: ``"literal"`` | ``"acesso"`` | ``"chamada"`` |
    ``"operador"``. Não desce na árvore — é o discriminador rápido para quem precisa
    decidir, no nó raiz, se uma expressão é "só um literal" antes de olhar o resto.
    """
    if isinstance(expr, Literal):
        return "literal"
    if isinstance(expr, Contexto):
        return "acesso"
    if isinstance(expr, Chamada):
        return "chamada"
    return "operador"  # UnOp | BinOp


def sempre_verdadeira(expr: Expr) -> bool:
    """`expr` está PROVADA sempre-verdadeira? Prova conservadora, de propósito
    estreito para não arriscar falso-positivo (mesmo critério já aplicado à checagem
    `unsound-condition` existente em `checks/hardening_extra.py`, que esta função
    generaliza só no que a árvore de parse consegue provar sem ambiguidade):

      - o literal `true`;
      - autocomparação `X == X` — igualdade ESTRUTURAL da árvore (não textual: um
        `X` dinâmico dos dois lados ainda é verdadeiro por reflexividade, e
        `(X) == (X)`/`X==X` com espaçamento diferente têm a MESMA árvore);
      - a álgebra booleana de `||`/`&&` sobre subexpressões já provadas — o idioma
        `a || b`: se `a` já está provada sempre-verdadeira, `a || b` também está,
        com curto-circuito, não importa o que `b` seja; `a && b` só quando AMBAS
        estão provadas.

    Não tenta provar tautologia geral (ex.: De Morgan, `!(!a)`) — um falso negativo
    aqui é seguro (a checagem que consumir isto simplesmente não dispara); um falso
    positivo não seria.
    """
    if isinstance(expr, Literal):
        return expr.valor is True
    if isinstance(expr, BinOp):
        if expr.op == "==" and expr.esquerda == expr.direita:
            return True
        if expr.op == "||":
            return sempre_verdadeira(expr.esquerda) or sempre_verdadeira(expr.direita)
        if expr.op == "&&":
            return sempre_verdadeira(expr.esquerda) and sempre_verdadeira(expr.direita)
        return False
    return False
