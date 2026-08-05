"""Proveniência do relatório: contra QUAL código, com QUAIS regras, e íntegro em relação a si.

Um relatório de segurança que não amarra os três eixos não é reauditável. Seis meses depois,
diante de um achado que sumiu, ninguém consegue distinguir "o cliente corrigiu o pipeline" de
"a regra passou a ignorar aquele caso" — e a segunda hipótese é a que interessa a quem audita
o auditor. Por isso o envelope carrega:

- ``commit``          — o commit do código AUDITADO (não o da ferramenta: o que se questiona é
                        se o achado existia naquele estado do repositório);
- ``ruleset_hash``    — impressão digital do catálogo que julgou esse código;
- ``artifact_sha256`` — o próprio relatório, para detectar edição posterior à entrega.

``commit`` é ``null`` quando não há repositório git (tarball, imagem de contêiner, diretório
exportado). ``null`` é a resposta honesta: preencher com "unknown" ou com o commit da máquina
que rodou seria pior que o silêncio, porque parece informação.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

_SHA_COMPLETO = re.compile(r"^[0-9a-f]{40}$")
# Versão do esquema de serialização do catálogo. Entra no material do hash para que uma
# mudança na FORMA de calcular (campo novo, ordem diferente) não seja confundida com uma
# mudança nas REGRAS — os dois casos movem o hash, e só o segundo é notícia.
_RULESET_SCHEMA = "esteira-ruleset/1"


def commit(root: Path | str | None = None) -> str | None:
    """SHA do commit do código auditado: ``ESTEIRA_COMMIT`` → ``git rev-parse HEAD`` → ``None``.

    A variável de ambiente vem primeiro porque no CI o checkout costuma ser *detached*/*shallow*
    e o runner já sabe o SHA verdadeiro (``github.sha``) — deixar o git responder ali daria o
    commit de merge sintético do PR, que não existe em lugar nenhum depois.

    Nunca levanta: git ausente, diretório sem ``.git``, repositório sem nenhum commit e binário
    travado (timeout) são todos ``None``. Uma varredura não pode falhar por causa do carimbo.
    """
    # O override do ambiente passa pelo MESMO filtro de 40-hex que o git rev-parse:
    # um valor malformado (typo, variável errada herdada do CI) não pode contaminar
    # silenciosamente a proveniência — é justamente o "algo que parece informação" que
    # o docstring deste módulo diz ser pior que o silêncio. Inválido → cai para o git.
    do_ambiente = os.environ.get("ESTEIRA_COMMIT", "").strip().lower()
    if do_ambiente and _SHA_COMPLETO.match(do_ambiente):
        return do_ambiente
    diretorio = Path(root) if root is not None else Path.cwd()
    if diretorio.is_file():
        diretorio = diretorio.parent
    try:
        saida = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(diretorio),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if saida.returncode != 0:
        return None
    sha = saida.stdout.strip().lower()
    return sha if _SHA_COMPLETO.match(sha) else None


def ruleset_hash() -> str:
    """SHA-256 do catálogo inteiro: id, título, severidade, recomendação, OWASP e CWE.

    Inclui a RECOMENDAÇÃO de propósito. Ela é texto entregue ao cliente: se a orientação de
    remediação muda, o relatório mudou de conteúdo e o destinatário tem direito de perceber
    pelo hash, mesmo que a detecção seja idêntica.
    """
    from esteira.checks.catalog import CATALOG, OWASP_EDITION

    material = {
        "schema": _RULESET_SCHEMA,
        "owasp_edition": OWASP_EDITION,
        "rules": [
            {
                "id": meta.id,
                "title": meta.title,
                "severity": meta.severity.value,
                "recommendation": meta.recommendation,
                "owasp": meta.owasp,
                "cwe": meta.cwe,
            }
            for meta in sorted(CATALOG.values(), key=lambda m: m.id)
        ],
    }
    return canonical_sha256(material)


def artifact_sha256(document: dict[str, Any]) -> str:
    """Auto-hash do relatório, calculado com o próprio campo zerado.

    Receita para o destinatário conferir (publicada no README): pegue o JSON entregue, ponha
    ``null`` em ``artifact_sha256``, serialize com ``sort_keys=True``, ``ensure_ascii=False`` e
    separadores ``(",", ":")``, e tire o SHA-256 do UTF-8. Um hash que o outro lado não sabe
    recalcular não é integridade, é enfeite.

    No SARIF o campo mora em ``runs[0].properties``, não na raiz: lá o renderizador chama
    ``canonical_sha256`` direto sobre o objeto ``run`` com o campo ainda em ``null``, o que dá
    exatamente a mesma receita aplicada ao run.
    """
    return canonical_sha256({**document, "artifact_sha256": None})


def canonical_sha256(obj: Any) -> str:
    """SHA-256 da serialização canônica — a única forma estável de hashear um dicionário."""
    texto = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()
