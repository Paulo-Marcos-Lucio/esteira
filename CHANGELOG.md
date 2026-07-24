# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

- Suporte a **monorepo** na descoberta de workflows: `iter_workflow_files` agora varre
  recursivamente e encontra todo `.github/workflows/` sob o caminho apontado — o do
  repositório e o de cada subprojeto — em vez de apenas o do nível superior. Diretórios de
  dependência vendorada (`node_modules`, `vendor`, `site-packages`, …) e caches/VCS ocultos
  (exceto `.github`) são podados, para não auditar o CI de uma dependência como se fosse o do
  repositório. Um monorepo sem workflow no topo, que antes não era varrido, passa a ser.
- Checagem `secret-to-thirdparty-action`: sinaliza `${{ secrets.* }}` / `${{ github.token }}`
  (inclusive o `GITHUB_TOKEN`) passado via `with:` a uma action de **terceiros** fixada por
  tag/branch — uma tag movida para código malicioso recebe o segredo. Reusa o classificador de
  owner/pinagem já existente: action oficial (`actions/*`, `github/*`) ou terceiro fixado por
  SHA não gera alarme (uso normal / código congelado). Complementa `unpinned-action-thirdparty`.

## [0.1.0] — 2026-07-21

### Adicionado

- Descoberta de workflows e parse YAML (com tratamento do `on:` → `true` do YAML 1.1).
- 10 checagens híbridas (por linha + estruturais): script injection, `pull_request_target`
  + checkout de PR, actions não fixadas por SHA (1ª e 3ª parte), permissões amplas/ausentes,
  segredo em log, `curl|bash`, runner self-hosted e gatilhos privilegiados.
- Renderizadores console, JSON e SARIF 2.1.0.
- CLI `esteira` (`scan`, `rules`); testes com workflows vulnerável e endurecido;
  mypy strict; CI com actions fixadas por SHA e auto-scan.
