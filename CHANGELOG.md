# Changelog

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

- **Nova checagem `insecure-commands`** (HIGH · A05:2025 Injection · CWE-94): detecta
  `ACTIONS_ALLOW_UNSECURE_COMMANDS` definido no `env` do workflow, de um job ou de um step. A variável
  reativa os comandos de workflow legados `set-env`/`add-path` via stdout (CVE-2020-15228) — com ela ligada,
  qualquer saída controlada por atacante injeta variável de ambiente ou entrada de PATH e escala para RCE.
  Fecha um item de paridade que zizmor, octoscan, Checkov e KICS já cobrem. Anomaly-only (um workflow saudável
  nunca a define), com caso positivo, severidade fixada e linha no README travados pelos meta-testes.

### Adicionado

- **Corpus rotulado em `bench/`** — 17 workflows positivos (19 achados rotulados, cobrindo as 16 de
  16 regras do catálogo) e 5 negativos com 8 linhas-armadilha, com `manifest.json` adjudicado à mão
  e `avaliar.py` que imprime recall/precisão com intervalo de Wilson. Regra da casa: quem altera
  detecção roda a bateria antes e depois e registra os dois números aqui. Medição de referência
  (2026-08-04, Python 3.12.8): `0047ffb` **18/19 recall (IC95% [75% ; 99%]), 2 falso-positivos,
  precisão 90%** → após o P2-03 **19/19 (IC95% [83% ; 100%]), 0 falso-positivo, precisão 100%**.
  O número é de corpus autoral e mede cobertura do catálogo, não acurácia de campo — o que ele
  **não** cobre está declarado em `bench/README.md`.
- **Proveniência no envelope do relatório** — `commit` (do repositório **auditado**: `ESTEIRA_COMMIT`
  → `git rev-parse HEAD` → `null`), `ruleset_hash` (SHA-256 do catálogo) e `artifact_sha256`
  (auto-hash, com a receita de conferência publicada no README), no JSON e no `runs[0].properties`
  do SARIF. Sem eles, um achado que some na entrega seguinte é indistinguível de uma regra afrouxada.

### Segurança

- **Redação de credencial na evidência.** Cinco pontos dos detectores copiavam até 120 caracteres
  **crus** da linha do workflow para `evidence`. Como `secret-in-run` existe justamente para achar
  linha com segredo, uma linha com `AKIA…`/`ghp_…`/`sk_live_…` embutido ia inteira para o JSON
  entregue ao cliente e para o `snippet` do SARIF, que sobe para o Code Scanning. Toda credencial de
  formato conhecido passa a sair mascarada nas pontas, e a redação roda **antes** do truncamento —
  na ordem inversa, um segredo começando no caractere 110 saía com 10 caracteres crus. Não há regra
  de entropia genérica de propósito: ela mastigaria o SHA de 40 hex do pin de action, que é a
  evidência principal de `unpinned-action-*`. *Limite assumido:* credencial de formato desconhecido
  (senha solta, token interno) não é redigida.

- **ReDoS exponencial em `curl-pipe-shell` (a ferramenta era o DoS do pipeline que ela audita).**
  O padrão de wrappers (`sudo`/`env`/`time`/…) tinha quantificador aninhado ilimitado e ambíguo:
  a mesma palavra podia ser consumida pela repetição interna ou iniciar uma iteração da externa.
  Medido: uma linha `run:` de 129 caracteres travava a varredura por **7,1 s**, com crescimento de
  ~14× a cada 19 caracteres — ou seja, ~160 caracteres num PR de fork consumiam o runner até o
  timeout do job. Com as duas repetições limitadas, a mesma entrada leva **0,000016 s**. Um teste
  cronometrado trava a regressão. *Contrapartida honesta:* `curl | bash` com mais de três wrappers
  encadeados deixa de ser detectado — está registrado em "Limitações conhecidas" do README.
- **Custo quadrático no reconhecedor de `${{ … }}`.** Um `${{` sem fechamento fazia o motor varrer
  o resto do texto a cada abertura: 200 KB levavam **130 s** (o teste anterior usava 8 KB, passava
  em 0,25 s e não pegava nada). Agora, 0,005 s.
- **Injeção de marcação do `rich` pelo alvo.** Um workflow com um job chamado `[/]` derrubava o
  relatório com `MarkupError` **depois** de a varredura ter encontrado os achados — supressão de
  detecção a custo zero para quem controla o arquivo auditado — e `[bold green]` num campo externo
  permitia forjar texto colorido dentro do relatório entregue ao cliente. Todo campo de origem
  externa passa a ser renderizado como texto literal.

### Corrigido

- **`secret-in-run` acusava o `echo` errado e não via o export para `$GITHUB_ENV`.** Bastava
  "existe `echo` na linha" + "existe `${{ secrets }}` na linha" para disparar, ainda que em
  **comandos diferentes**. Medido no fork `iac-scanner`: os 2 achados da regra eram da forma
  `[ -n "${{ secrets.X }}" ] || { echo "::warning::não configurado"; exit 0; }`, em que o `echo`
  imprime o **nome** da variável e nunca o valor — 0/2 de precisão. E a linha seguinte,
  `echo "K=${{ secrets.X }}" >> $GITHUB_ENV`, ficava calada por uma calibração que acertou a
  premissa (o `>>` grava em arquivo, e o GitHub mascara segredo no log) e errou a conclusão: o
  segredo passa a existir no ambiente de **todos os steps seguintes**, inclusive actions de
  terceiros. Depois: **3/3**, com texto próprio e severidade Média para o caso `$GITHUB_ENV`. A
  recomendação do catálogo perdeu a palavra "log" — ela é colada ao detalhe na mensagem do SARIF,
  e afirmar "vaza no log" ao lado de um detalhe que diz o contrário se contradiz na mesma frase.
  `$GITHUB_OUTPUT` **não** foi incluído: a propagação é análoga, mas não foi adjudicada em campo.
- **`owasp_edition` grafado como `owasp-edition` no SARIF.** O campo documentado (e emitido no JSON)
  é `owasp_edition`; dentro das `rules` do SARIF ele saía com hífen, num *property bag* que o SARIF
  não valida — quem lia a chave documentada levava `KeyError`. Corrigida a grafia e passou a ser
  emitido também no nível do `run`.
- **Falso-negativo de `script-injection`: cego a `inputs.*` / `github.event.inputs.*`.** A tupla de
  contextos não-confiáveis não incluía os inputs do workflow, então `run: echo "${{ inputs.x }}"` (a
  porta de um reusable workflow, alcançável pelo caller) e a grafia legada `github.event.inputs.*`
  passavam batidos. Agora são reconhecidos, com **severidade calibrada pelo gatilho** — sinal suave,
  nunca filtro: `workflow_call` (input vem do caller) = **HIGH**, só `workflow_dispatch` (disparar
  exige acesso de escrita) = **LOW**, gatilho indeterminado = **MEDIUM**; os eventos de texto livre
  (issue/PR/comentário) seguem **CRITICAL**. A discriminação por lookbehind evita o falso-positivo:
  um campo JSON `.inputs.` (acesso após `.`) e um identificador como `inputs_json` **não** casam.
  Provado em campo: a `deploy.yml` da Bússola (input cru num `if [ … ]`) que saía limpa agora
  aparece como LOW, sem tocar nenhum outro achado.
- **Falso-negativo de `secret-to-thirdparty-action`: só olhava `with:`, não o `env:`.** Uma action
  de terceiros por tag recebendo `${{ secrets.* }}` / `${{ github.token }}` pelo **env efetivo** do
  step (workflow + job + step) — que a action lê em `process.env` — não gerava o achado escalado. É
  o padrão canônico do `gitleaks-action` (`GITHUB_TOKEN` via `env:`). Agora varre os dois caminhos e
  emite um único achado por step (`with:` tem prioridade de redação). Provado em campo: o gitleaks da
  Bússola (`pipeline.yaml`, `ci.yml`) passa a ser flagrado como **HIGH**, sem novo falso-positivo.
- **Falso-negativo em `${{ … }}`: N expressões viravam UMA.** O `}}` era consumível como conteúdo,
  então a expressão se estendia até a última do texto. Três injeções no mesmo bloco `run:` chegavam
  como um único achado — dois desapareciam — e a evidência saía como um bloco multi-linha.
- **Dois falsos-negativos em `secret-in-run`.** `echo "==> publicando ${{ secrets.X }}"` (o `>`
  estava *dentro* da string ecoada) e `echo "${{ secrets.X }}" 2>/dev/null` (redirecionar o *stderr*
  não impede o segredo de sair no stdout) eram tratados como gravação segura em arquivo. Os dois são
  idiomas banais de script de deploy: o cliente recebia "pipeline limpo" com o token no log público.
  Os negativos canônicos (`printf … > id_deploy`, `echo … >> "$GITHUB_ENV"`, `--password-stdin`)
  continuam sem alarme.
- **`script-injection` apontava para a linha errada — inclusive para a própria mitigação.** O achado
  era ancorado só pela expressão, então a mesma expressão usada *corretamente* num bloco `env:`
  anterior roubava a localização. Agora a âncora é o comando inteiro, com cursor: o achado CRÍTICO
  aponta para o `run:` vulnerável, e N achados distintos ocupam N linhas distintas (sem isso, o Code
  Scanning fundia todos num alerta só).
- **Supressão inline vazava entre achados.** Um `# esteira: ignore` no `permissions:` do workflow
  apagava também os `broad-permissions` de **cada job**, que ninguém suprimiu. Cada bloco passa a ser
  ancorado na sua própria linha (mesma correção aplicada a `self-hosted-runner`).
- **Caminhos absolutos no SARIF.** O Code Scanning do GitHub exige URI relativa à raiz do
  repositório: com caminho absoluto ele **aceita** o documento e descarta os resultados, sem erro
  visível. Os caminhos passam a ser relativos à raiz da varredura — o que conserta de uma vez o
  SARIF, o JSON e a coluna "Local" do console.
- **`_UNTRUSTED` não cobria `head.repo.description` nem `head.repo.homepage`**, dois campos de texto
  livre da lista oficial do GitHub que o autor do fork controla integralmente.
- **`curl | bash` escapava no caminho de fallback**: na linha crua, o prefixo `- run: ` tirava o
  comando da posição de comando exigida pelo padrão.

### Adicionado

- **Checagem `checkout-credentials-in-artifact`** (classe *artipacked*): `actions/checkout` grava a
  credencial em `.git/config` (`persist-credentials` é `true` por padrão) e, se um step seguinte
  publica a raiz do workspace (`upload-artifact` com `path: .` ou sem `path`), o `.git` — e o token —
  vão dentro do artefato. Exige os **dois** lados de propósito: o checkout padrão sozinho é o de 99%
  dos workflows e alarmar nele seria ruído.
- **Composite actions passam a ser descobertas.** O suporte a `runs.steps` já existia nos detectores
  e era inalcançável: o loader só olhava `.github/workflows/`, então `action.yml` só era analisado se
  o usuário apontasse a CLI direto para o arquivo. Agora `action.yml`/`action.yaml` entram na
  varredura do repositório (com a mesma poda de dependência vendorada).
- **Plano de ação no relatório de console**: os três piores achados com a `fix_suggestion` concreta.
  A correção sugerida era o ativo mais valioso da ferramenta e só existia no JSON/SARIF — não na
  saída que 100% dos usuários veem primeiro.
- **`partialFingerprints` no SARIF** (`esteiraFindingId/v1`), deliberadamente **sem** o número da
  linha: reindentar o workflow não fecha nem reabre o alerta no Code Scanning.
- **`helpUri`** por regra (página do CWE) e a **evidência** dentro de `region.snippet` — ela existia
  no JSON e era descartada no SARIF.
- **`--fail-on info`**: `Severity.INFO` existia no modelo e era inalcançável pelo portão.
- **Meta-testes de catálogo**: toda checagem precisa ter um caso positivo que a faça disparar, uma
  severidade fixada em teste, rótulo OWASP da edição declarada e uma linha na tabela do README com a
  severidade certa. Checagem nova nasce vermelha até ter as quatro coisas.
- **Portão de cobertura** (`--cov-fail-under`) no `pyproject.toml`: o `--cov` só imprimia um número
  que ninguém lia. `.github/dependabot.yml` para os SHAs pinados não congelarem para sempre.
- **Enquadramento legal brasileiro** no `SECURITY.md`, com o escopo do que conta como
  vulnerabilidade desta ferramenta.

### Alterado

- **BREAKING — contrato JSON.** O documento passa a declarar `"schema": "suite-appsec/1"` e
  `"owasp_edition"`; a chave do identificador do achado passa de `check` para **`id`** (alinhada com
  as outras ferramentas da suíte, que usavam `rule`/`check`); cada achado ganha `severity_rank`; e
  `summary.by_severity` traz **sempre as cinco chaves**, inclusive zeradas — antes, `.by_severity.high`
  estourava `KeyError` quando a varredura vinha limpa.
- **BREAKING — rótulos OWASP migrados para a edição 2025** (a suíte inteira fala 2025). O ano é
  declarado no cabeçalho da coluna e no campo `owasp_edition`. A edição importa: `A03` é *Software
  Supply Chain Failures* em 2025 e era *Injection* em 2021. Principais reclassificações:
  `script-injection` A03:2021 → **A05:2025**; `unpinned-*`/`curl-pipe-shell`/`secrets-inherit`/
  `secret-to-thirdparty-action` A08:2021 → **A03:2025**; `pull-request-target-checkout`/
  `self-hosted-runner`/`dangerous-trigger` → **A08:2025**; `secret-in-run` → **A09:2025**.
  *Ressalva honesta:* o dado não estava **errado** (cada rótulo sempre carregou o próprio ano);
  estava **incoerente** entre as ferramentas da suíte.
- **BREAKING — caminho que existe mas não tem workflow agora sai com código 0**, não 2: o aviso vai
  para o stderr. O caso realmente perigoso — caminho digitado errado — passa a ser barrado pelo
  Click com exit 2 (`exists=True`), que é onde o verde falso eterno de fato morava. Um subprojeto de
  monorepo sem CI não pode reprovar o build de quem roda `esteira scan services/api`.
- **README**: a tabela passa a documentar as **16** checagens (documentava 11, e com a severidade de
  `dangerous-trigger` errada), com tabela de códigos de saída e dos defaults de `--fail-on` da suíte.
  Os defaults **não** são uniformes de propósito — o Guardião usa `medium` porque um scanner de
  segredo deve ter gatilho mais sensível que um de cabeçalho.
- **README — seção Pro corrigida (overclaim removido).** O texto prometia um "catálogo estendido" na
  versão Pro que **não existe**: a engine da Pro é a **mesma** deste repositório, com as mesmas 16
  checagens. A seção passa a dizer com todas as letras que a diferença é **serviço** (auditoria da
  organização/monorepo, adjudicação de achados e **correção aplicada via PR** — SHA-pinning,
  permissões mínimas, isolamento de `pull_request_target`), não código. Corrigido também o rótulo da
  evidência de cadeia de suprimentos: **A03:2025** (era citado como A08). Adicionada a seção
  "O que foi medido" com os números reproduzíveis pela suíte (16/16 na severidade certa, zero
  falso-positivo no workflow que pina por SHA, ReDoS do `curl | bash` de 7,1 s → < 0,01 s com teste
  cronometrado).
- **Instalação: `pip install esteira` foi removido de toda a documentação.** Medido no PyPI: o nome
  `esteira` é de **outra pessoa** (um servidor de automação, release única de 2021) e aquele pacote
  nem instala o comando `esteira` — a receita do README puxava código de terceiro para dentro do CI
  do cliente. A instrução correta é `pip install git+https://github.com/Paulo-Marcos-Lucio/esteira.git`
  (em CI, fixada por SHA). Um teste falha se a instrução do PyPI voltar, e outro roda a receita de CI
  publicada no README pelo próprio Esteira.
- Severidade exibida no console em PT-BR (`CRÍTICA`/`ALTA`/…); o identificador em inglês continua no
  JSON/SARIF.
- **Código morto removido**: a guarda `wf.data is None` de `check_self_hosted`, inalcançável porque
  `run_all` já retorna pelo caminho de fallback antes de chamá-la.

### Corrigido (rodadas anteriores)

- **Falso-positivo em `secret-in-run`:** gravar um segredo em arquivo — `printf '%s' "${{ secrets.KEY }}"
  > id_deploy`, `echo "${{ secrets.X }}" >> "$GITHUB_ENV"` — é o padrão canônico e seguro de
  instalar/exportar um segredo e **não** vaza para o log da Action; deixou de ser marcado. O alarme
  segue válido para `echo`/`printf` de segredo **sem** redirecionamento (stdout → log). A distinção
  entre `> arquivo` e duplicação de descritor (`2>&1`, `>&2`) é feita explicitamente. Corrige um
  falso-positivo comum em workflows de deploy reais (instalar chave SSH via `printf … > id_deploy`).

### Adicionado (rodadas anteriores)

- **Correção sugerida (env indirection)** em cada achado de `script-injection`: o finding passa
  a carregar uma `fix_suggestion` concreta — mover a expressão `${{ … }}` não-confiável para um
  bloco `env:` e referenciá-la como `"$VAR"` no `run:` (ou `process.env.VAR` quando o sink é o
  `script:` do `actions/github-script`). O nome da variável é derivado do último segmento do
  contexto (`github.event.issue.title` → `TITLE`). Aparece nos relatórios JSON (campo
  `fix_suggestion`) e SARIF (na mensagem). É **enriquecimento da recomendação**, não uma nova
  detecção nem reescrita do YAML: a ferramenta sugere o padrão, sem afirmar que aplicá-lo torna
  o workflow seguro. As demais checagens seguem com `fix_suggestion` nulo.
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
