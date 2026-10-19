# BENCHMARK — Esteira x zizmor x actionlint x octoscan x poutine

Comparação lado a lado contra o corpus rotulado de `bench/` — o mesmo que `bench/avaliar.py` mede para a própria Esteira. Gerado por `bench/comparar_concorrentes.py`; **não edite este arquivo à mão**, ele é republicado pelo script.

**Convite explícito à contestação:** o casamento entre a regra da Esteira e a regra equivalente de cada concorrente está em `bench/equivalencias.json`, não decidida na hora por este script. Se você acha que um `—` deveria ser um `✅` (ou vice-versa), abra uma issue ou um PR mudando aquele arquivo — a tabela abaixo é reprodutível com um comando (ver `bench/comparar_concorrentes.py`), então qualquer divergência é verificável, não uma questão de confiança.

## Versões fixadas

- **zizmor**: `1.31.1`
- **actionlint**: `v1.7.12`
- **octoscan**: `v0.1.7`
- **poutine**: `v1.1.6`

## Positivos — a Esteira e cada concorrente encontram o achado rotulado?

| Arquivo:linha | Regra (Esteira) | Esteira | zizmor | actionlint | octoscan | poutine |
|---|---|---|---|---|---|---|
| `script-injection.yml:10` | `script-injection` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `pr-target-checkout.yml:12` | `pull-request-target-checkout` | ✅ | · | · | ✅ | · |
| `pr-target-checkout.yml:2` | `dangerous-trigger` | ✅ | ✅ | · | · | · |
| `unpinned-thirdparty.yml:11` | `unpinned-action-thirdparty` | ✅ | ✅ | · | · | · |
| `broad-permissions.yml:5` | `broad-permissions` | ✅ | ❌ | · | · | · |
| `secret-no-log.yml:11` | `secret-in-run` | ✅ | · | · | ❌ | · |
| `secret-github-env.yml:11` | `secret-in-run` | ✅ | · | · | ✅ | · |
| `curl-pipe-shell.yml:11` | `curl-pipe-shell` | ✅ | · | · | · | ✅ |
| `self-hosted-runner.yml:9` | `self-hosted-runner` | ✅ | · | · | ✅ | · |
| `dangerous-trigger.yml:2` | `dangerous-trigger` | ✅ | ✅ | · | · | · |
| `unpinned-firstparty.yml:11` | `unpinned-action-firstparty` | ✅ | ✅ | · | · | · |
| `unpinned-reusable.yml:9` | `unpinned-reusable-workflow` | ✅ | ✅ | · | · | · |
| `missing-permissions.yml:1` | `missing-permissions` | ✅ | ❌ | · | · | · |
| `secrets-inherit.yml:10` | `secrets-inherit` | ✅ | ✅ | · | · | · |
| `secret-to-thirdparty.yml:13` | `secret-to-thirdparty-action` | ✅ | · | · | · | · |
| `secret-to-thirdparty.yml:11` | `unpinned-action-thirdparty` | ✅ | ✅ | · | · | · |
| `unpinned-container.yml:10` | `unpinned-container-image` | ✅ | · | · | · | · |
| `checkout-credentials.yml:11` | `checkout-credentials-in-artifact` | ✅ | ✅ | · | ❌ | · |
| `invalid-yaml.yml:1` | `invalid-yaml` | ✅ | · | ✅ | · | · |
| `insecure-commands.yml:10` | `insecure-commands` | ✅ | ✅ | · | ✅ | · |
| `compromised-action.yml:7` | `known-compromised-action` | ✅ | · | · | · | · |
| `ai-rule-of-two.yml:8` | `ai-agent-rule-of-two` | ✅ | · | · | · | · |
| `ai-untrusted-input.yml:8` | `ai-agent-untrusted-input` | ✅ | · | · | · | · |
| `cache-poisoning.yml:8` | `cache-poisoning` | ✅ | · | · | · | · |
| `falsifiable-actor.yml:5` | `falsifiable-actor-condition` | ✅ | ✅ | · | ✅ | · |

`✅` = achou o mesmo achado (mesma regra equivalente, arquivo e linha dentro da tolerância de ±1). `❌` = tem checagem equivalente mapeada e não achou. `·` = nenhum concorrente tem checagem equivalente declarada em `equivalencias.json` (não é falha do concorrente em algo que ele não se propõe a medir).

## Negativos — alguém dispara na linha-armadilha que não deveria?

| Arquivo:linha | Esteira | zizmor | actionlint | octoscan | poutine |
|---|---|---|---|---|---|
| `endurecido.yml:15` | — | — | — | — | — |
| `guarda-de-segredo.yml:12` | — | — | — | — | — |
| `guarda-de-segredo.yml:13` | — | — | — | — | — |
| `instala-segredo-em-disco.yml:12` | — | — | — | — | — |
| `instala-segredo-em-disco.yml:13` | — | — | — | — | — |
| `supressao-legitima.yml:15` | — | ⚠️ FP | — | — | ⚠️ FP |
| `matriz-e-container-fixados.yml:12` | — | — | — | — | — |
| `matriz-e-container-fixados.yml:22` | — | — | — | — | — |

`⚠️ FP` = disparou na linha que o corpus rotula como armadilha legítima (falso-positivo). `—` = não disparou ali (correto). `·` = a ferramenta não rodou nesta corrida (ver "Versões fixadas").

## Resumo

| Ferramenta | Recall (achou / rotulado) | Falso-positivo (de 8 armadilhas) | Cobertura declarada (regras com equivalente mapeado) |
|---|---|---|---|
| esteira | 25/25 | 0/8 | 25/25 (é a própria ferramenta medida) |
| zizmor | 11/25 | 1/8 | 11/22 |
| actionlint | 2/25 | 0/8 | 2/22 |
| octoscan | 6/25 | 0/8 | 7/22 |
| poutine | 2/25 | 1/8 | 2/22 |

## O que este benchmark não é

- **Não é medição de campo.** Mesma ressalva de `bench/README.md`: o corpus é autoral, pequeno (25 achados positivos, 8 armadilhas negativas) e mede cobertura contra casos canônicos, não acurácia contra pipelines arbitrários de produção.
- **Não mede com token de API.** `zizmor` e `octoscan` têm checagens que consultam a API do GitHub (commit-impostor, repo-jacking); elas ficam desligadas aqui porque exigiriam um token válido para serem reprodutíveis, e sem ele falham ou retornam resultado diferente a cada corrida. Um token válido pode mudar os números acima para zizmor e octoscan — não para actionlint nem poutine, que não têm esse tipo de checagem.
- **Não equivale regras por nome, só por comportamento observado.** Um `✅` significa que a ferramenta disparou uma checagem que `bench/equivalencias.json` declara equivalente — não que as duas regras tenham o mesmo nome ou a mesma descrição. Onde uma checagem parecida existe mas mede outra coisa (ex.: "autor verificado" não é "fixado por SHA"), o arquivo de equivalências diz isso explicitamente em vez de inflar a cobertura do concorrente.

