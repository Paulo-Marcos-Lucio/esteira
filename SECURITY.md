<p align="center"><a href="SECURITY.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/esteira/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Política de Segurança

Reporte vulnerabilidades **de forma privada** para **contatopml26@gmail.com** (assunto com prefixo `[security]`). Dê um prazo razoável para correção antes de divulgar.

## Escopo

O Esteira é uma ferramenta **defensiva** e **estática**: ela lê arquivos de workflow do GitHub Actions e aponta configurações inseguras para que sejam corrigidas. Ela **não** executa o workflow, não faz requisição de rede, não autentica em lugar nenhum e não modifica o repositório auditado — a correção é *sugerida* no relatório, nunca aplicada.

Interessa como vulnerabilidade deste projeto, entre outros:

- **Falso negativo**: um workflow comprovadamente vulnerável que a ferramenta reporta como limpo.
- **Falso positivo** que reprova um pipeline correto.
- **Negação de serviço da própria ferramenta**: entrada (um arquivo de workflow) que faça a varredura travar ou consumir memória sem limite — o modelo de ameaça inclui rodar em CI sobre arquivos que um PR de terceiro pode modificar.
- **Vazamento no relatório**: segredo do alvo saindo em JSON/SARIF/console além do necessário para identificar o achado.

## Enquadramento legal (Brasil)

Auditar pipeline de terceiro **sem autorização por escrito** é crime no Brasil. A ferramenta é estática e local — ela não toca no ambiente do alvo —, mas o material que você usar como entrada (workflows, logs, artefatos) precisa ser obtido licitamente.

- **Lei 12.737/2012** (Carolina Dieckmann) e **Lei 14.155/2021**: invasão de dispositivo informático alheio, com penas agravadas quando há obtenção de conteúdo de comunicações privadas, segredos comerciais ou controle remoto.
- **Lei 12.965/2014** (Marco Civil da Internet): guarda e sigilo de registros e de comunicações privadas.
- **Lei 13.709/2018** (LGPD): se o relatório contiver dado pessoal, você é agente de tratamento e responde por ele.

Use o Esteira em pipelines que você mantém ou tem **autorização formal, com escopo e período definidos**, para revisar. Guarde essa autorização.

## Modelo de ameaças da suíte

Como a suíte AppSec se defende de um alvo hostil — e o que ainda não está fechado — está documentado em [`modelo-de-ameacas.md`](https://github.com/Paulo-Marcos-Lucio/sentinela/blob/main/docs/modelo-de-ameacas.md), no repositório da [Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela): é ela quem tem superfície de rede (fala HTTP com o alvo escolhido pelo operador). O Esteira lê arquivo de workflow local — não recebe resposta de rede arbitrária —, mas compartilha a mesma classe de ameaça de negação de serviço por entrada hostil (ver **Escopo** acima): o arquivo de workflow pode vir de um PR de terceiro.
