"""Higiene de material publicado (Classes A e H): e-mail público + posicionamento honesto.

Duas invariantes que fecham a porta antes de qualquer push — ambas travam a CLASSE varrendo a
árvore, não um arquivo escolhido a dedo:

* **Classe H — e-mail de contato.** O contato de clientes da suíte é ``contatopml26@gmail.com``.
  O e-mail pessoal NUNCA pode aparecer em arquivo versionado — é a classe de vazamento que a
  auditoria cruzada pegou no Pro de outra ferramenta. Se o pessoal reaparecer num README, num
  badge ou no código, o CI reprova.
* **Classe A — posicionamento honesto do README público.** A edição Pro da Esteira tem detecção
  EXCLUSIVA (o confirmador de ação comprometida ``--online``, consulta *read-only* a OSV/GHSA)
  que não está no ``main``. Enquanto isso for verdade, o README público NÃO pode afirmar em
  absoluto que "não há motor escondido" / "a mesma engine, sem uma linha a mais" — seria promessa
  falsa ao cliente. A rodada anterior corrigiu o TEXTO; este teste TRAVA a classe: se a frase
  absolutista reaparecer num README público, o CI reprova.
"""

from __future__ import annotations

from pathlib import Path

# Montado em pedaços para o próprio guard não casar a si mesmo na varredura.
_PESSOAL = "pmlsp23" + "@gmail.com"
_PUBLICO = "contatopml26@gmail.com"
_RAIZ = Path(__file__).resolve().parent.parent
_EXTS = {".md", ".py", ".toml", ".svg", ".yml", ".yaml", ".json", ".txt", ".cfg"}
_IGNORAR = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}


def _arquivos_de_texto() -> list[Path]:
    saida: list[Path] = []
    for caminho in _RAIZ.rglob("*"):
        if any(parte in _IGNORAR for parte in caminho.parts):
            continue
        if caminho.is_file() and caminho.suffix.lower() in _EXTS:
            saida.append(caminho)
    return saida


def test_email_pessoal_nunca_em_arquivo_versionado() -> None:
    """Classe H: o e-mail pessoal não sobrevive em nenhum arquivo de texto versionado."""
    ofensores = [
        str(c.relative_to(_RAIZ))
        for c in _arquivos_de_texto()
        if _PESSOAL in c.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not ofensores, f"e-mail pessoal vazou em: {ofensores}; use {_PUBLICO}"


_FRASES_ABSOLUTISTAS_PROIBIDAS = [
    "sem uma linha a mais",
    "não há motor",
    "nao ha motor",
    "nem checagem que só nasce",
    "nem checagem que so nasce",
    "a mesma engine",
    "engine idêntica",
    "engine identica",
    "no resto da suíte a engine pública é a mesma",
    "nenhuma capacidade escondida",
]
_READMES_PUBLICOS = ("README.md", "README.en.md")


def test_readme_publico_nao_afirma_engine_identica() -> None:
    """Classe A: nenhum README público afirma absolutismo de 'engine idêntica' enquanto o Pro
    tem o confirmador ``--online`` exclusivo, ausente do ``main``."""
    ofensores: list[str] = []
    for nome in _READMES_PUBLICOS:
        caminho = _RAIZ / nome
        if not caminho.is_file():
            continue
        texto = caminho.read_text(encoding="utf-8", errors="ignore").lower()
        for frase in _FRASES_ABSOLUTISTAS_PROIBIDAS:
            if frase.lower() in texto:
                ofensores.append(f"{nome}: {frase!r}")
    assert not ofensores, (
        "README público afirma absolutismo de 'engine idêntica' enquanto o Pro tem "
        f"detecção exclusiva: {ofensores}"
    )
