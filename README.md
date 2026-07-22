<div align="center">

# ⚙️ Esteira

### Auditor de segurança para a sua **esteira de CI/CD** — foco em GitHub Actions.

*Encontra os erros que transformam um pipeline em porta de entrada: **script injection** por contexto não-confiável, **actions não fixadas por SHA**, **`pull_request_target`** fazendo checkout de código de PR, **permissões amplas** do `GITHUB_TOKEN` e segredos vazando em log. Saída em console, JSON e **SARIF** (aba Security do GitHub).*

[![CI](https://github.com/Paulo-Marcos-Lucio/esteira/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/esteira/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP-A08%2FA03-000000.svg)](https://owasp.org/Top10/)

</div>

---

## 📌 Por que auditar o pipeline

O CI roda com **segredos** e um **token com permissão de escrita** no repositório. Um erro de configuração ali não derruba um site — entrega as chaves do reino. Os padrões mais explorados:

- **Script injection**: `run: echo "${{ github.event.issue.title }}"` — o título de uma issue (controlado por qualquer um) vira comando de shell.
- **Supply chain**: `uses: acme/action@v1` — a tag pode ser movida para código malicioso a qualquer momento. Fixar por SHA congela o que roda.
- **`pull_request_target`** + checkout do PR: executa **código não-confiável** com segredos e token de escrita.
- **`permissions: write-all`**: dá ao workflow (e a toda action de terceiro dentro dele) poder que ele não precisa.

O Esteira encontra esses padrões e explica a correção — com número de linha e mapeamento OWASP/CWE.

---

## 🔎 O que ele verifica

| Checagem | Risco | Severidade | OWASP / CWE |
| --- | --- | --- | --- |
| `script-injection` | Contexto não-confiável (`github.event.*`, `head_ref`) no `run` | 🔴 Crítica | A03 · CWE-94 |
| `pull-request-target-checkout` | checkout de código de PR em `pull_request_target` | 🔴 Crítica | A08 · CWE-94 |
| `unpinned-action-thirdparty` | Action de terceiros por tag, não por SHA | 🟠 Alta | A08 · CWE-1357 |
| `broad-permissions` | `write-all` / escopos de escrita globais | 🟠 Alta | A01 · CWE-732 |
| `secret-in-run` | Segredo impresso em `echo`/`printf` | 🟠 Alta | A09 · CWE-532 |
| `curl-pipe-shell` | `curl \| bash` — código da rede sem verificação | 🟡 Média | A08 · CWE-494 |
| `self-hosted-runner` | Runner self-hosted (risco em repo público) | 🟡 Média | A08 · CWE-668 |
| `dangerous-trigger` | `pull_request_target` / `workflow_run` | 🟡 Média | A08 · CWE-269 |
| `unpinned-action-firstparty` | Action oficial por tag | 🔵 Baixa | A08 · CWE-1357 |
| `missing-permissions` | Sem bloco `permissions` explícito | 🔵 Baixa | A01 · CWE-732 |

---

## 🚀 Instalação

```bash
git clone https://github.com/Paulo-Marcos-Lucio/esteira.git
cd esteira
pip install .        # ou: pip install -e ".[dev]"
```

---

## 🧑‍💻 Uso

```bash
# audita os workflows do repositório atual (.github/workflows)
esteira scan .

# em JSON, falhando o pipeline em achados High+
esteira scan . -f json --fail-on high

# SARIF para a aba Security do GitHub
esteira scan . -f sarif -o esteira.sarif

# aponta direto para um arquivo
esteira scan .github/workflows/deploy.yml

# lista as checagens
esteira rules
```

### No próprio GitHub Actions

```yaml
- run: pip install esteira
- run: esteira scan . --fail-on high -f sarif -o esteira.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: esteira.sarif
```

---

## 🏗️ Arquitetura

```
src/esteira/
├── core/        # modelos + loader (descoberta de workflows, parse YAML)
├── checks/      # catálogo declarativo, detectores (por linha + estruturais), motor
├── report/      # console (rich), json, sarif
└── cli.py       # interface typer
```

Detecção **estrutural**: quando o YAML parseia, as checagens iteram a árvore já parseada (`jobs → steps → run/uses/with`). Assim, `${{ }}` dentro de `env:` ou de um comentário não é confundido com shell, os *plain scalars* de `run:` são cobertos por inteiro, a indireção por `env` (inclusive encadeada) é resolvida e a notação por colchete (`github['event']['issue']['title']`) é normalizada antes do match. Só quando o arquivo **não** parseia é que cai para um melhor-esforço por linha — e o próprio erro de sintaxe vira um achado `invalid-yaml` de severidade alta (**fail-closed**: um arquivo não-analisado não passa o CI escondido atrás de um erro). O loader trata o clássico *gotcha* do YAML 1.1 (`on:` → booleano `true`) e a varredura é blindada por arquivo: nenhuma exceção de parse derruba a análise dos demais.

---

## ⚖️ Uso ético

Ferramenta **defensiva**, para auditar pipelines que você mantém ou tem autorização para revisar. Os achados são apontados com a correção — o objetivo é endurecer, não explorar.

---

## 🚧 Limitações conhecidas

Análise estática não substitui revisão humana, e a Esteira é honesta sobre o que **não** cobre hoje:

- **Exfiltração de segredo por rede** (`curl -d "t=${{ secrets.X }}" host`) não é marcada: enviar um token a um host legítimo (`Authorization: Bearer`) é uso normal, e flagar geraria falso-positivo demais. Apenas `echo`/`printf` de segredo — que vaza no log — é apontado.
- **`with.args`/`entrypoint` de actions `docker://`** não são inspecionados; os sinks de execução varridos são `run:` e o `script:` do `actions/github-script`.
- **Precisão de linha** em achados de permissão a nível de *job* aponta para o primeiro bloco `permissions:` do arquivo (o texto do finding diz qual job).
- **Cobertura de runner** limita-se a labels literais e `matrix` resolvível estaticamente; um `runs-on` de expressão dinâmica não-resolvível não é classificado.

Contribuições que fechem esses gaps (com testes de regressão) são bem-vindas.

---

## 🧭 Roadmap

- [ ] Suporte a monorepo (varrer múltiplos `.github/workflows`).
- [ ] Checagem de `GITHUB_TOKEN` passado a actions de terceiros.
- [ ] Detector dedicado de exfiltração de segredo (com alowlist de hosts).
- [ ] Regras para GitLab CI e Azure Pipelines.
- [ ] Auto-fix sugerido (env indirection para script injection).

---

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">
<sub>Parte da suíte AppSec — junto do <a href="https://github.com/Paulo-Marcos-Lucio/sentinela">Sentinela</a>, <a href="https://github.com/Paulo-Marcos-Lucio/guardiao">Guardião</a> e <a href="https://github.com/Paulo-Marcos-Lucio/chaveiro">Chaveiro</a>.</sub>
</div>
