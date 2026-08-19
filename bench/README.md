# Corpus de referência da Esteira

Corpus rotulado, versionado, com script de avaliação. Existe por um motivo:
**número de detecção sem corpus público não é métrica, é lembrança.**

## Como reproduzir

```bash
pip install -e ".[dev]"
python bench/avaliar.py        # sai 1 se houver falso-positivo ou falso-negativo
```

A bateria também roda dentro do `pytest` (`tests/test_bench.py`), então quem afrouxar uma
detecção coberta aqui quebra o CI antes do merge — corpus que ninguém roda apodrece em silêncio.

## O que tem aqui

| | Quantidade | O que é |
|---|---|---|
| `positivos/` | 19 arquivos · **22 achados rotulados** | Um workflow por checagem do catálogo, endurecido em todo o resto para isolar o defeito. Inclui as duas faces do `secret-in-run` (impressão no stdout · export para `$GITHUB_ENV`) e o corpo de comentário entregue a um agente de IA (`ai-agent-write-injection`) |
| `negativos/` | 6 arquivos · **9 linhas-armadilha** | Workflow endurecido (SHA-pin + `permissions`), guarda de segredo `[ -n … ] \|\| echo`, instalação de segredo em disco e por `--password-stdin`, supressão inline justificada, `container` por digest, `${{ matrix.* }}` via `env:` e o mesmo agente de IA acima só com `contents: read` |
| `manifest.json` | 31 entradas | Rótulo de verdade: arquivo, linha, `eh_achado`, `regra`, e a `nota` que justifica a adjudicação |

O casamento exige a **regra certa**, não só a linha certa: um achado na linha esperada com o id
errado conta como falso-positivo *e* como falso-negativo. É a regra que vai para a aba Security
e para o relatório do cliente.

## Medição de referência

Medido em 2026-08-04, Python 3.12.8, Windows 11:

| Versão | Recall | IC95% (Wilson) | Falso-positivo | Precisão |
|---|---|---|---|---|
| `0047ffb` (antes desta auditoria) | **18/19 = 95%** | [75% ; 99%] | 2 | 90% |
| `audit/pendencias` (P2-03 aplicado) | **19/19 = 100%** | [83% ; 100%] | 0 | 100% |

A diferença é exatamente o defeito adjudicado em campo no fork `iac-scanner`: o `secret-in-run`
disparava em `[ -n "${{ secrets.X }}" ] || { echo "…não configurado"; }` — onde o `echo` imprime
o **nome** da variável — e ficava calado no `echo "K=${{ secrets.X }}" >> $GITHUB_ENV` da linha
seguinte, que é onde há risco.

## O que este corpus **não** é

- **Não é campo.** Os workflows foram escritos por quem escreveu a ferramenta. `100%` aqui mede
  *cobertura do catálogo contra casos canônicos*, **não** acurácia contra pipelines arbitrários
  de produção. O intervalo de Wilson `[83% ; 100%]` é a parte honesta do número: com n=19, a
  amostra não sustenta três algarismos, e um corpus autoral não sustenta nem o primeiro como
  previsão de campo.
- **Não é amostra independente.** Onde há medição de campo real, ela vale mais: os números de
  campo estão no `CHANGELOG.md` e nas mensagens de commit, com o repositório e a linha.
- **Não cobre variação de forma.** Há **um** caso canônico por regra. `script-injection` tem
  dezenas de sinks e contextos; aqui há um. Regra coberta ≠ regra completa.
- **Não cobre o que a ferramenta assume não cobrir.** Nada aqui exercita propagação de taint por
  `steps.*.outputs`/`needs.*.outputs`, `$GITHUB_OUTPUT`, `with.args` de `docker://`, nem
  exfiltração de segredo por rede. São limites declarados no README principal, não achados
  escondidos — e um corpus que não os inclui **não os mede**.
- **Não valida severidade.** O `avaliar.py` casa arquivo, linha e regra. Quem trava severidade é
  o meta-teste `test_severidade_de_toda_checagem_esta_fixada`.

## Regra da casa

Quem alterar detecção **roda esta bateria antes e depois** e registra os dois números no
`CHANGELOG.md`. Recall que sobe às custas de falso-positivo não é melhoria — é troca, e a troca
precisa estar visível.

> Os arquivos daqui **não** entram na varredura do próprio repositório: `esteira scan .` só
> descobre `.github/workflows/` e `action.yml`/`action.yaml`. Verificado — o `self-scan` do CI
> continua vendo 1 arquivo e 0 achados com o `bench/` no lugar.
