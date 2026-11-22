# SAST multi-strumento, DAST e PT agentico su macchina esterna

Estensione aggiuntiva della PoC. Non modifica `appsec-pipeline.yml`: la dimostrazione A/B/C esistente resta valida.

## Cosa aggiunge

| Dove gira | Componente | Esito su GitHub |
|---|---|---|
| GitHub Actions | Workflow `sast-multi.yml`: CodeQL, Semgrep, Gitleaks, Trivy | Un check per strumento, più il check `SAST AGGREGATO` |
| Macchina interna | Agente `dast_external_agent.py`: ZAP | Stato `DAST ESTERNO (ZAP)` |
| Macchina interna | Lo stesso agente: Strix | Stato `PT AGENTICO (STRIX)` |

Ordine: `SAST AGGREGATO` superato → DAST esterno → PT agentico. Ogni stadio fallito ferma i successivi, che vengono
segnati come "non eseguito".

## Stato delle verifiche

| Elemento | Verificato | Come |
|---|---|---|
| Gate aggregato su CodeQL e Semgrep | Sì | Unit test su report reali: scenario A score 77 con 1 bloccante, scenario C score 97 |
| Gate aggregato su Gitleaks e Trivy | Parziale | Unit test su report sintetici, costruiti dal formato documentato |
| Baseline di Semgrep sul repository con le estensioni | Sì, in parte | Semgrep reale con le regole pubbliche (non il pacchetto `p/default` usato su GitHub): score 91, margine di 1 punto |
| Workflow `sast-multi.yml` | Parziale | Sintassi YAML e controlli strutturali; **mai eseguito su GitHub Actions** |
| Stadio PT dell'agente | Parziale | Unit test; prova reale con clone del repository, copia del commit e un comando finto al posto di Strix; **mai eseguito con Strix reale** |
| Opzioni, codici di uscita e file di Strix | Sì | Lettura del sorgente di Strix 1.7.1 |
| Chiamate reali all'API di GitHub | No | Non raggiungibile dall'ambiente di sviluppo |

La prima esecuzione su GitHub è quindi una misura: gli score reali di Gitleaks e Trivy sul codice attuale non sono noti.

## SAST multi-strumento

### Strumenti

| Check | Strumento | Cosa cerca |
|---|---|---|
| `S1 SAST - CodeQL` | CodeQL | Vulnerabilità nel codice JavaScript e TypeScript |
| `S2 SAST - Semgrep` | Semgrep, regole `p/default` | Pattern insicuri nel codice e nei file di configurazione |
| `S3 SECRETS - Gitleaks` | Gitleaks | Credenziali in tutta la storia del repository |
| `S4 SCA-IAC - Trivy` | Trivy | Librerie vulnerabili e configurazioni insicure (Dockerfile, Compose) |

Il check di uno strumento è rosso solo se la scansione non si completa. Il giudizio sui finding è del check
`SAST AGGREGATO`.

### Policy del gate

- `score = 100 − somma dei pesi`: Critical 40, High 20, Medium 3, Low 1.
- Superato solo con score maggiore di 90 e nessun finding High o Critical.
- Severità: dal valore numerico `security-severity` quando c'è; altrimenti dal livello del report (`error` High,
  `warning` Medium, `note` Low). Una credenziale trovata da Gitleaks è sempre High.
- Un conteggio per regola e per file: la stessa regola ripetuta nello stesso file vale una volta.
- La stessa vulnerabilità segnalata da due strumenti (stesso file, stesso CWE, righe distanti al più 5) vale una volta.
- I risultati non di sicurezza sono informativi: peso 0. I finding non bloccanti a confidenza bassa non sono conteggiati.
- Il gate è INVALID (codice 3), mai superato, se: manca il report di uno strumento; il job di uno strumento non è
  riuscito, anche se ha lasciato un report; un report dichiara un'esecuzione non riuscita; un risultato cita una
  regola non dichiarata.
- Un finding soppresso nel codice con il commento dello strumento (per esempio `nosemgrep`) non è conteggiato, ma
  compare sempre nel riepilogo, nella tabella "Soppressi nel codice": chi approva la pull request deve verificarlo.
- Un finding di livello `error` blocca anche a confidenza bassa. Se è un falso positivo rivisto, si sopprime nel
  codice con la motivazione; l'agente ne contiene uno, sull'esecuzione dei comandi.

### Dove leggere l'esito

| Dove | Cosa |
|---|---|
| Pagina del run, riepilogo del job `SAST AGGREGATO` | Tabella per strumento e tabella dei finding conteggiati |
| Artifact `sast-aggregato-evidence` | Tutti i SARIF e `reports/sast-multi-gate.json` |
| Scheda Security → Code scanning | Alert di Semgrep, Gitleaks e Trivy, filtrabili per strumento |

### Prova in locale

```bash
python3 scripts/sast_multi_gate.py --sarif-dir <cartella con i .sarif> --expect codeql,semgrep
```

`--expect` è obbligatoria. `--job-result` serve solo nel workflow.

### Se lo scenario corretto non supera il gate

Leggi la tabella dei finding nel riepilogo e correggi quelli segnalati. La baseline misurata con Semgrep è 91: tre
finding Medium da 3 punti (action per tag in `appsec-pipeline.yml`, action per tag in `enterprise-flow-demo.yml`,
permessi `0o777` sulla cartella dei report nell'agente). Basta un altro finding per scendere sotto soglia. Casi
probabili sul codice attuale:

- Gitleaks sulla password dimostrativa di `compose.test.yml`: è un falso positivo documentabile con un commento
  `gitleaks:allow` sulla riga, oppure con il file `.gitleaksignore`.
- Semgrep sulle action referenziate per tag in `appsec-pipeline.yml`: vale 3 punti (score massimo 97) e si
  toglie solo fissando quelle action a un commit, cioè modificando la pipeline esistente. È una tua scelta.
- Trivy sul `Dockerfile`: la tabella indica la regola e la riga.

Limite di Trivy: su `main` non c'è `package-lock.json`, quindi le librerie npm non vengono analizzate. Oggi Trivy
copre solo le configurazioni; per le librerie serve il lockfile, che cambia la build dell'immagine.

Non è previsto un file di eccezioni: un finding si corregge oppure si esclude con il meccanismo dello strumento.

## Agente esterno: DAST e PT agentico

### Attesa del SAST

```bash
python3 scripts/dast_external_agent.py --repo <owner>/<repo> \
  --require-check "01 SAST - CodeQL and High gate" \
  --require-check "SAST AGGREGATO"
```

Il DAST parte solo quando entrambi i check sono superati. Se uno fallisce, lo stato del DAST diventa fallito con la
dicitura "non eseguito" e il nome del check.

### PT agentico con Strix

Strix esegue attacchi reali e invia a un modello linguistico il codice o le risposte dell'applicazione. Prima di
abilitarlo servono:

- l'autorizzazione scritta a testare il bersaglio, che deve essere un ambiente di test;
- Docker e Python 3.12 sulla macchina (Strix esegue i propri strumenti in un container);
- una macchina o una rete dedicata al PT: il container di Strix ha privilegi di rete e gira dentro la rete interna;
- un modello configurato: `STRIX_LLM`, `LLM_API_KEY` e, per un modello locale che non fa uscire dati dalla rete,
  `LLM_API_BASE`.

Avvio su un'applicazione già attiva in ambiente di test (test a scatola chiusa):

```bash
export GH_TOKEN=<token della macchina>
export STRIX_LLM=<provider/modello>
python3 scripts/dast_external_agent.py --repo <owner>/<repo> \
  --branch <branch-di-test> \
  --target-url https://<indirizzo-app-di-test> \
  --zap-cmd /usr/local/bin/zap \
  --pentest-cmd strix --pentest-authorized
```

| Opzione | Effetto |
|---|---|
| `--pentest-cmd strix` | Abilita lo stadio PT; senza, l'agente non esegue Strix e non scrive lo stato del PT |
| `--pentest-authorized` | Dichiarazione obbligatoria: senza, l'agente non parte |
| `--pentest-mode quick` | Profondità: `quick` (predefinito), `standard`, `deep` |
| `--pentest-budget 5` | Spesa massima per esecuzione verso il modello, in dollari |
| `--pentest-timeout 60` | Minuti massimi per esecuzione |

Comportamento:

| Situazione | Stato `PT AGENTICO (STRIX)` |
|---|---|
| DAST esterno non ancora concluso | Nessuno: l'agente attende |
| DAST esterno fallito o in errore | `failure`, "PT agentico non eseguito" |
| Strix completato, score oltre 90 e nessun High o Critical | `success` |
| Strix completato, score fino a 90 oppure un High o Critical | `failure` |
| Strix interrotto, tempo scaduto, budget esaurito, risultati assenti o illeggibili | `error` |
| DAST esterno superato in simulazione (`[SIMULATO]`) e PT reale abilitato | `failure`, "PT agentico non eseguito" |

L'esito vale solo se Strix dichiara la scansione completata (`status: completed` nel suo `run.json`): Strix termina
senza errore anche a budget esaurito, e quel caso diventa `error`. Uno stato `error` è definitivo per quel commit: per
riprovare serve un nuovo commit.

Bersaglio: con `--target-url` è l'indirizzo indicato. Senza, Strix analizza il sorgente del commit (scatola aperta):
l'applicazione costruita dall'agente è pubblicata solo su `127.0.0.1` e non è raggiungibile dal container di Strix.
L'analisi avviene su una copia temporanea del commit, eliminata a fine esecuzione: Strix può scrivere nella cartella
che riceve, e così nulla entra nelle build successive.

Report sulla macchina, in `~/appsec-dast-agent/reports/<commit>/`: `pentest-gate.json` (score ed esito) e
`pentest/strix_runs/<run>/` (report completo di Strix).

Sicurezza:

- Il token di GitHub non viene passato a Strix: l'agente lo toglie dall'ambiente del processo.
- La telemetria di Strix è disattivata (`STRIX_TELEMETRY=0`), salvo che tu imposti la variabile.
- Lo stadio è disattivato per impostazione predefinita.
- Allo scadere del tempo massimo Strix riceve prima il segnale di chiusura, poi viene terminato dopo 30 secondi.
- L'esito non è ripetibile: due esecuzioni sullo stesso commit possono dare finding diversi.

Rischi che restano:

- Il codice di una pull request può contenere istruzioni rivolte al modello, per esempio per fargli tacere un finding.
  Le pull request da fork sono ignorate; quelle dei collaboratori no.
- Con `--target-url` gli attacchi colpiscono l'ambiente indicato, che non è legato al commit in esame.
- Non c'è un tetto di spesa predefinito: indica `--pentest-budget`.
- Un PT lungo occupa l'agente e ritarda il DAST delle altre pull request.

### Prova senza eseguire nulla

```bash
python3 scripts/dast_external_agent.py --repo <owner>/<repo> --pentest-cmd strix --dry-run --once
```

## Caricamento nel repository

Un push diretto su `main` è rifiutato dal ruleset: serve una pull request.

```bash
cd ~/appsec-unified-pipeline-lab
git switch main
git pull --ff-only origin main
git switch -c feature/sast-multi-dast-pt
unzip -o ~/Downloads/AppSec_SAST_MULTI_DAST_PT_ADDON.zip -d .
python3 -m unittest discover -s tests -p 'test_*.py'
git add .github/workflows/sast-multi.yml scripts tests docs
git commit -m "feat: add multi-tool SAST gate and agentic pentest stage"
git push -u origin feature/sast-multi-dast-pt
```

L'archivio sostituisce `AppSec_DAST_ESTERNO_ADDON.zip`: contiene la versione aggiornata dell'agente, dei suoi test e
della sua guida.

## Attivazione dei check nel ruleset

Aggiungere un check ai controlli obbligatori solo dopo averlo visto verde almeno una volta:

1. `SAST AGGREGATO`, dopo un run verde sul codice corretto.
2. `DAST ESTERNO (ZAP)`, dopo la prima scansione riuscita dalla macchina.
3. `PT AGENTICO (STRIX)`, dopo il primo PT riuscito.

Un check obbligatorio che nessuno scrive lascia il merge bloccato senza errori visibili: vale a macchina spenta e a
token scaduto.

## Limiti

- Nessun file di eccezioni o di rischi accettati.
- Strumenti per altri linguaggi (Psalm per PHP, Bandit, gosec) non inclusi: il gate li accetterebbe, perché legge
  qualunque SARIF, ma vanno aggiunti come job.
- CodeQL viene eseguito due volte, una per workflow.
- Il PT a scatola chiusa sull'applicazione costruita dal commit non è disponibile.
- `demo_pipeline.py` non conosce i check nuovi: finché non sono obbligatori nel ruleset, la dimostrazione non cambia.
