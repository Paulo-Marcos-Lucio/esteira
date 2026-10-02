"""Contrapartida pública da E13: a classe trust policy OIDC — o insumo não está no repositório.

Um workflow com `permissions: id-token: write` e um `uses: aws-actions/configure-aws-
credentials`/`google-github-actions/auth`/`azure/login` só mostra a INTENÇÃO de pedir um token de
federação de identidade (OIDC). Quem de fato decide se esse token vira credencial é a trust
policy configurada do lado do provedor de nuvem (o `sub`/`aud` da IAM role na AWS, a condição de
atributo do Workload Identity Pool no GCP, o federated credential no Entra ID) — uma configuração
que mora fora do Git, fora do alcance de uma ferramenta que só lê `.github/**`. Nenhuma checagem
do catálogo pode confirmar ou refutar, a partir do YAML, se aquela trust policy está restrita
corretamente (por `ref:`/`environment:`) ou aberta demais (qualquer branch, `repo:*`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from esteira.checks.engine import scan
from esteira.report.json_report import KNOWN_GAPS, to_document

# Workflow legítimo que pede um token OIDC e o troca por uma credencial AWS — a forma mais comum
# do padrão. Pinado por SHA e com permissions mínimas: nenhuma checagem do catálogo tem motivo
# para disparar aqui, e é exatamente esse silêncio que o known_gap precisa declarar.
OIDC_WORKFLOW = """\
name: deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: us-east-1
      - name: deploy
        run: aws s3 sync ./dist s3://meu-bucket
"""


@pytest.fixture
def oidc_repo(tmp_path: Path) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(OIDC_WORKFLOW, encoding="utf-8")
    return tmp_path


def test_known_gaps_sai_no_bloco_coverage(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "oidc-trust-policy-out-of-repo" in ids


def test_known_gaps_traz_o_detalhe_em_texto(safe_repo: Path) -> None:
    cov = to_document(scan(safe_repo))["coverage"]
    gap = next(g for g in cov["known_gaps"] if g["id"] == "oidc-trust-policy-out-of-repo")
    assert "sub" in gap["detail"] or "aud" in gap["detail"]
    assert "id-token" in gap["detail"]


def test_workflow_oidc_legitimo_e_pinado_nao_dispara_achado_que_alegue_cobrir_trust_policy(
    oidc_repo: Path,
) -> None:
    # Um workflow com id-token + configure-aws-credentials, pinado e com permissions mínimas, é
    # exatamente o caso que passa limpo hoje — o silêncio que o gap precisa declarar como "não
    # avaliado", não como "confirmado seguro".
    resultado = scan(oidc_repo)
    assert resultado.max_severity() is None


def test_mesmo_num_workflow_que_usa_oidc_o_gap_continua_declarado(oidc_repo: Path) -> None:
    cov = to_document(scan(oidc_repo))["coverage"]
    ids = {gap["id"] for gap in cov["known_gaps"]}
    assert "oidc-trust-policy-out-of-repo" in ids


def test_known_gaps_e_constante_independente_do_recorte(safe_repo: Path) -> None:
    completo = to_document(scan(safe_repo))["coverage"]["known_gaps"]
    recortado = to_document(scan(safe_repo, only={"script-injection"}))["coverage"]["known_gaps"]
    assert completo == recortado == [dict(gap) for gap in KNOWN_GAPS]
