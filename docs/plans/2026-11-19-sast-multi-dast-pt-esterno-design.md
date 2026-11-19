# SAST multi-strumento, DAST e PT agentico su macchina esterna — Design

**SP:** 13 SP-Umano / 3 SP-Augmented
**Livello:** Alta (funzione nuova, integrazione di strumenti esterni, ambito sicurezza)
**Data:** 19 novembre 2026
**Repository:** `pentester2378/appsec-unified-pipeline-lab` (PoC personale, pubblico)

## 1. Contesto

La PoC oggi esegue un solo strumento SAST (CodeQL su JavaScript/TypeScript) nella pipeline
`.github/workflows/appsec-pipeline.yml`, e un agente esterno (`scripts/dast_external_agent.py`, opzione C) che dalla
macchina interna interroga GitHub, esegue ZAP e scrive lo stato `DAST ESTERNO (ZAP)` sul commit.

Richiesta: estendere il processo a più strumenti SAST e usare la macchina esterna sia per il DAST sia per il
penetration test agentico. Vincolo vigente: la pipeline esistente non si modifica; ogni novità è un file aggiuntivo.

Fatti verificati il 19 novembre 2026, usati come base del design:

| Fatto | Come è stato verificato |
|---|---|
| Il SARIF di Semgrep OSS 1.186.0 non contiene `security-severity`; il livello è in `defaultConfiguration.level` della regola e il risultato non ha `level` | Esecuzione reale di Semgrep sul codice di `main` e sullo scenario A |
| `scripts/sast_gate.py` ignora i risultati senza `security-severity`: con quel gate ogni finding di Semgrep sarebbe invisibile | Lettura del codice |
| Sullo scenario A Semgrep segnala la SQL injection a `src/app.js:40` (CWE-89, livello `error`); CodeQL la segnala a `src/app.js:41` (CWE-89, `security-severity` 8.8) | Esecuzione reale di Semgrep; artifact `sast-evidence` del 12 novembre |
| Sul codice di `main` Semgrep produce 9 risultati: 6 ripetizioni di una regola `warning` sul file del workflow, 3 `note` | Esecuzione reale |
| Strix 1.7.1 in modalità `-n` termina con 0 (nessun finding sopra soglia), 2 (finding, ma anche errore d'uso della riga di comando), 1 (errore). Termina con 0 anche a budget esaurito, a limite di richieste persistente o senza chiusura della scansione: in quei casi `run.json` riporta `status` diverso da `completed` | Lettura del sorgente, commit `8db295a`; punto corretto dalla review |
| Strix scrive in `strix_runs/<run>/` rispetto alla cartella corrente, con nome del run generato; `run.json` esiste dall'avvio (`status: running`); `vulnerabilities.json` esiste solo se ci sono o ci sono stati finding; ogni finding ha `id`, `title`, `severity` (`critical`, `high`, `medium`, `low`, `info`, `none`) | Lettura del sorgente |
| Strix monta in scrittura le cartelle locali date come bersaglio; la telemetria è attiva per impostazione predefinita (`STRIX_TELEMETRY`); gestisce SIGTERM; richiede Python 3.12 | Lettura del sorgente |
| Strix riscrive i bersagli `localhost` verso `host.docker.internal` e richiede Docker | Lettura del sorgente |

Non verificabili in questa sessione (registri e download bloccati): esecuzione di Gitleaks, Trivy, Strix, e del
workflow su GitHub Actions.

## 2. Obiettivo

1. Un workflow separato esegue CodeQL, Semgrep, Gitleaks e Trivy, con un check per strumento e un gate aggregato
   `SAST AGGREGATO` che applica un'unica policy a tutti i report.
2. L'agente esterno attende più check, e dopo il DAST superato esegue il PT agentico con Strix scrivendo un secondo
   stato `PT AGENTICO (STRIX)`.

## 3. Option Zero

Secret scanning e Dependabot sono impostazioni del repository, gratuite su repository pubblico, e coprono credenziali e
librerie senza codice. Non bastano: non producono un esito unico per pull request né uno score, e non coprono Semgrep
e l'infrastruttura come codice. Restano attivabili in aggiunta. Per il PT non esiste alternativa di sola configurazione.

## 4. Requisiti funzionali

| Id | Requisito |
|---|---|
| RF1 | Un workflow nuovo `sast-multi.yml` esegue un job per strumento (CodeQL, Semgrep, Gitleaks, Trivy). Ogni job pubblica il proprio SARIF come artifact. Il job è rosso solo se la scansione non si completa, non quando trova finding. |
| RF2 | Il job `SAST AGGREGATO` legge tutti i SARIF e produce un esito unico: PASS solo con score maggiore di 90 e nessun finding bloccante. Codici di uscita 0 PASS, 2 FAIL, 3 INVALID. |
| RF3 | La severità di un risultato si ricava nell'ordine: `security-severity` della regola; profilo dello strumento; livello SARIF del risultato o della regola; in assenza di tutto, `warning`. |
| RF4 | L'esito è INVALID, mai PASS, se: manca il report di uno strumento atteso; non c'è alcun SARIF; il job di uno strumento non è `success`; un report dichiara un'esecuzione non riuscita; un risultato non ha `ruleId` o cita una regola non dichiarata. L'elenco degli strumenti attesi è obbligatorio. |
| RF5 | La stessa vulnerabilità segnalata da due strumenti diversi conta una sola volta. |
| RF6 | Il riepilogo riporta, per ogni strumento, risultati letti, finding conteggiati, bloccanti e informativi, in JSON e in Markdown nel riepilogo del job. |
| RF7 | Semgrep, Gitleaks e Trivy caricano il SARIF in Code Scanning con una categoria propria; un errore di caricamento non altera l'esito del gate. |
| RF8 | L'opzione `--require-check` dell'agente è ripetibile: il DAST parte solo quando tutti i check indicati sono superati. |
| RF9 | Con `--pentest-cmd` l'agente, dopo un DAST esterno superato, esegue Strix e scrive lo stato `PT AGENTICO (STRIX)`: `success`, `failure` o `error`. Se il DAST non è superato scrive `failure` con la dicitura "non eseguito". |
| RF10 | Il PT è disattivato per impostazione predefinita e richiede la dichiarazione esplicita `--pentest-authorized`. |
| RF11 | L'esito del PT usa la stessa formula di score sui finding di Strix. L'esecuzione vale solo se `run.json` riporta `status: completed` ed esiste una sola cartella di risultati creata da quella esecuzione; ogni altro caso, compreso il tempo massimo superato, produce `error`, mai `success`. |
| RF13 | Nell'analisi a scatola aperta Strix lavora su una copia usa e getta del commit, verificata sullo SHA ed eliminata a fine esecuzione: nulla di ciò che Strix scrive entra nelle build successive. |
| RF14 | Il token di GitHub non viene passato a Strix; la telemetria di Strix è disattivata salvo scelta esplicita dell'operatore; un PT reale non parte su un DAST simulato. |
| RF12 | `appsec-pipeline.yml`, `scripts/sast_gate.py`, `scripts/dast_gate.py`, `src/`, `Dockerfile`, `compose.test.yml` restano invariati; i test esistenti restano verdi. |

## 5. Requisiti non funzionali

- Solo libreria standard Python; compatibile con Python 3.9.
- Nel workflow nuovo si usano solo action di `actions/*` e `github/codeql-action`, fissate all'identificativo del
  commit; gli strumenti di terze parti girano come immagini Docker a versione fissata.
- Nessuna credenziale nel repository. Il report di Gitleaks è prodotto con `--redact`: il segreto non finisce
  nell'artifact né in Code Scanning.
- L'agente resta un file unico, senza dipendenze, con le sole connessioni in uscita.
- I test sono ermetici (niente rete, Docker o Strix): il job 01 della pipeline esistente esegue tutti i
  `tests/test_*.py` e un test rosso fermerebbe DAST e gate 03.

## 6. Approcci valutati

| Approccio | Descrizione | Pro | Contro |
|---|---|---|---|
| A. Estendere la pipeline esistente | Nuovi job dentro `appsec-pipeline.yml` | Un solo workflow | Viola il vincolo "non toccare la pipeline"; rischio di rompere la dimostrazione A/B/C |
| B. Workflow separato con gate aggregato proprio | File nuovi; gate Python che normalizza i SARIF | Pipeline intatta; policy unica e testabile; check per strumento | Codice di normalizzazione da mantenere; CodeQL eseguito due volte |
| C. Orchestratore di terze parti (MegaLinter, DefectDojo) | Uno strumento esegue e aggrega gli scanner | Poco codice | Action di terze parti, spesso non ammesse in azienda; nessuno score con la formula concordata; servizio in più da gestire |

**Scelta: B.** È l'unico che rispetta il vincolo e mantiene lo score concordato.

Per il PT: stadio nello stesso agente (scelto: un solo servizio, una sola credenziale, ordine garantito dopo il DAST);
scartati un secondo agente separato (due servizi e due token per lo stesso compito) e il job Strix su GitHub Actions
(i runner di GitHub non raggiungono applicazioni interne).

## 7. Architettura

### 7.1 Workflow `sast-multi.yml`

Avvio su `pull_request` verso `main` e manuale. Job:

| Job | Strumento | Esecuzione | Artifact |
|---|---|---|---|
| `S1 SAST - CodeQL` | CodeQL | `codeql-action` con `upload: never` | `sast-multi-codeql` |
| `S2 SAST - Semgrep` | Semgrep | immagine `semgrep/semgrep`, `--config p/default` | `sast-multi-semgrep` |
| `S3 SECRETS - Gitleaks` | Gitleaks | immagine `ghcr.io/gitleaks/gitleaks`, storia completa, `--redact` | `sast-multi-gitleaks` |
| `S4 SCA-IAC - Trivy` | Trivy | immagine `aquasec/trivy`, `fs --scanners vuln,misconfig` | `sast-multi-trivy` |
| `SAST AGGREGATO` | gate | `needs` i quattro, `if: always()` | `sast-multi-evidence` |

CodeQL gira anche qui, con `upload: never`: il gate valuta report dello stesso run senza dipendere dall'altro workflow,
e in Code Scanning non compaiono analisi doppie.

### 7.2 Gate `scripts/sast_multi_gate.py`

1. Legge ogni `*.sarif` sotto la cartella indicata; identifica lo strumento dal nome del driver.
2. Verifica che ogni strumento atteso (`--expect`) abbia almeno un run.
3. Normalizza ogni risultato: strumento, regola, file, riga, severità, rilevanza di sicurezza, confidenza, CWE.
4. Raggruppa in unità di conteggio, elimina i duplicati tra strumenti, calcola score ed esito.
5. Scrive il riepilogo JSON e Markdown.

### 7.3 Agente esterno

Per ogni commit candidato l'agente legge una volta gli stati e tratta due stadi indipendenti:

1. **DAST**, invariato, preceduto dall'attesa di tutti i check indicati.
2. **PT**, solo con `--pentest-cmd`: parte quando lo stato DAST è `success` e lo stato PT non è definitivo.

Bersaglio del PT: con `--target-url` l'indirizzo indicato (test a scatola chiusa); altrimenti la cartella del sorgente
scaricato al commit (analisi a scatola aperta nel sandbox di Strix). Motivo: nella modalità che costruisce
l'applicazione, la porta è pubblicata solo su `127.0.0.1` e non è raggiungibile dal sandbox Docker di Strix.

## 8. Policy

**Score.** `score = max(0, 100 − somma dei pesi)`; pesi Critical 40, High 20, Medium 3, Low 1, Info 0. PASS se e solo
se `score > 90` e nessun bloccante. Bloccanti: High e Critical. Sono i valori già in uso nell'agente DAST.

**Severità (RF3).**

| Fonte | Regola |
|---|---|
| `security-severity` | ≥ 9.0 Critical; ≥ 7.0 High; ≥ 4.0 Medium; > 0 Low; 0 Info. Valore non numerico: INVALID |
| Profilo dello strumento | Gitleaks: ogni risultato è High (una credenziale nel codice blocca) |
| Livello SARIF | `error` High; `warning` Medium; `note` Low; `none` Info; assente: `warning` |

**Regola del risultato.** La regola si cerca per `ruleId` nel driver e nelle estensioni del run (CodeQL dichiara le
regole nelle estensioni). Un risultato senza `ruleId` o con regola non dichiarata rende il report INVALID, come nel
gate esistente: senza la regola non si conoscono severità ed etichette.

**Soppressioni.** Un risultato che il report marca come soppresso (`suppressions`, per esempio un commento
`nosemgrep` rivisto), salvo soppressioni respinte o in revisione, non è conteggiato ma è sempre elencato nel riepilogo,
con severità, file e riga: la soppressione va verificata in revisione della pull request.

**Rilevanza di sicurezza.** Un risultato è di sicurezza se ha `security-severity`, oppure una etichetta `security` o
un CWE, oppure proviene da uno strumento che produce solo finding di sicurezza (Gitleaks, Trivy). Gli altri sono
informativi: elencati, peso 0, mai bloccanti. È il comportamento del gate esistente verso i risultati non di sicurezza.

**Confidenza.** Un finding non bloccante a confidenza bassa (etichetta `LOW CONFIDENCE` di Semgrep, `precision: low`
di CodeQL) non è conteggiato. I bloccanti valgono a qualunque confidenza: si valutano prima dell'esclusione.

**Unità di conteggio.** Un conteggio per regola e per file: sei ripetizioni della stessa regola nello stesso file
valgono una volta.

**Duplicati tra strumenti (RF5).** Due unità di strumenti diversi sono la stessa vulnerabilità se hanno lo stesso
file, almeno un CWE in comune e righe distanti al più 5. L'unità risultante prende la severità più alta e l'elenco
degli strumenti.

**PT (RF11).** Ogni finding di Strix conta una volta con la sua `severity`; `none` vale Info; una severità sconosciuta
rende il report non valido.

Esiti attesi sui dati di prova:

| Caso | Dati | Score | Esito |
|---|---|---|---|
| Scenario A | CodeQL reale + Semgrep reale, Gitleaks e Trivy senza finding | 77 | FAIL, 1 bloccante (SQL injection unita da due strumenti) |
| Scenario C | CodeQL senza risultati + Semgrep reale | 97 | PASS |
| C + Trivy Low e Medium | sintetico | 93 | PASS |
| C + Trivy High | sintetico | 77 | FAIL, 1 bloccante |
| C + credenziale Gitleaks | sintetico | 77 | FAIL, 1 bloccante |
| Trivy assente tra i report | — | — | INVALID |

## 9. Componenti e interfacce

| File | Stato | Interfaccia |
|---|---|---|
| `.github/workflows/sast-multi.yml` | Nuovo | Job e nomi del §7.1 |
| `scripts/sast_multi_gate.py` | Nuovo | `load_runs(path) -> list`; `normalize(runs) -> list`; `evaluate(results, tools, expected=()) -> dict`; `check_job_results(entries, expected)`; `to_markdown(summary) -> str`; `main(argv=None) -> int`. Opzioni: `--sarif-dir`, `--expect` (obbligatoria), `--job-result STRUMENTO=ESITO` (ripetibile), `--summary`, `--markdown` |
| `scripts/dast_external_agent.py` | Modificato rispetto all'estensione DAST; nuovo per `main` se quella non è ancora caricata | `PT_CONTEXT`; `GitHub.set_status(sha, state, description, context=CONTEXT)`; `stage_statuses(gh, sha) -> dict`; `stage_states(gh, sha) -> dict`; `required_checks_state(gh, sha, names) -> (stato, nome)`, con il check fallito che prevale su quello in corso; `evaluate_pentest(findings) -> dict`; `run_pentest(candidate, cfg, run=run_cmd) -> dict`; `simulate_pentest`; `process_pentest(gh, candidate, cfg, pentest=run_pentest) -> str`; `poll_once(gh, cfg, scan, pentest) -> list` di `(sha, stato)`, con gli stati del PT prefissati da `pt-`; `parse_args(argv)`. `needs_scan` e `required_check_state` restano; `cfg["require_check"]` accetta stringa o lista. Opzioni nuove: `--pentest-cmd` (nome o percorso del comando), `--pentest-authorized`, `--pentest-mode` (`quick`, `standard`, `deep`; predefinito `quick`), `--pentest-budget` (USD, maggiore di 0), `--pentest-timeout` (minuti, predefinito 60); `--require-check` ripetibile. Comando eseguito: `<cmd> -n -t <bersaglio> --scan-mode <mode>`, più `--scope-mode full` a scatola aperta e `--max-budget-usd <n>` se indicato |
| `tests/test_sast_multi_gate.py` | Nuovo | Test del gate |
| `tests/test_sast_multi_workflow.py` | Nuovo | Controlli strutturali sul workflow, solo libreria standard |
| `tests/test_dast_external_agent.py` | Modificato | Test aggiunti per check multipli e PT; i 34 esistenti restano validi; il finto GitHub dei test accetta il contesto dello stato |
| `tests/fixtures/sast-multi/` | Nuovo | SARIF reali ridotti (CodeQL, Semgrep) e sintetici (Gitleaks, Trivy) |
| `docs/SAST_MULTI_DAST_PT.md` | Nuovo | Guida operativa |

Riepilogo del gate: `gate`, `status`, `score`, `threshold`, `counts`, `blocking`, `tools`, `findings`,
`merged_duplicates`, `excluded_low_confidence`, `informational`.

Riepilogo del PT (`pentest-gate.json`): `gate`, `tool`, `status`, `score`, `threshold`, `counts`, `blocking`,
`findings`, `target`, `mode`, `commit`, `run_dir`.

## 10. Gestione degli errori

| Situazione | Comportamento |
|---|---|
| SARIF non JSON, versione diversa da 2.1.0, run senza driver | Gate INVALID, codice 3 |
| Risultato senza `ruleId` o con regola non dichiarata | Gate INVALID, codice 3 |
| Regola dichiarata senza livello e senza `security-severity` | Livello `warning` |
| Job di uno strumento non `success`, oppure `executionSuccessful: false` nel report | Gate INVALID, codice 3 |
| `security-severity` fuori dall'intervallo 0–10 | Gate INVALID, codice 3 |
| Strix termina con codice diverso da 0 e 2, supera il tempo massimo (SIGTERM, poi SIGKILL dopo 30 secondi), non crea esattamente una cartella di risultati, oppure `run.json` manca, è illeggibile o ha `status` diverso da `completed` | Stato `error` |
| Copia del sorgente su un commit diverso da quello atteso | Stato `error`; Strix non viene eseguito |
| DAST esterno con dicitura `[SIMULATO]` e PT reale abilitato | Stato PT `failure`, "non eseguito" |
| DAST esterno in `error` | Stato PT `failure`, "non eseguito" |
| PT in `error` | Definitivo per quel commit: nessun nuovo tentativo automatico |
| Codice 2 senza `vulnerabilities.json`, o file non valido | Stato `error` |
| `--pentest-cmd` senza `--pentest-authorized` | L'agente non parte e spiega il motivo |
| Errore dell'API di GitHub durante un giro | Giro saltato, come oggi |

## 11. Test e criteri di accettazione

| Id | Criterio | Verifica |
|---|---|---|
| CA1 | Scenario A: score 77, 1 bloccante con strumenti `codeql` e `semgrep`, codice 2 | Unit test su SARIF reali |
| CA2 | Scenario C: score 97, PASS, codice 0 | Unit test su SARIF reali |
| CA3 | Il finding di Semgrep senza `security-severity` e con livello `error` è High | Unit test |
| CA4 | Sei ripetizioni della stessa regola nello stesso file contano una volta | Unit test |
| CA5 | Credenziale di Gitleaks: High bloccante | Unit test, dato sintetico |
| CA6 | Strumento atteso assente: codice 3; cartella senza SARIF: codice 3 | Unit test |
| CA7 | Score 91 PASS; score 90 FAIL con `blocking` vuoto | Unit test |
| CA8 | Risultato non di sicurezza: peso 0; finding Low a confidenza bassa: escluso; High a confidenza bassa: bloccante | Unit test |
| CA9 | Stesso file e stesso CWE a 6 righe di distanza: due unità distinte | Unit test |
| CA10 | `security-severity` non numerica: codice 3 | Unit test |
| CA11 | Nel workflow nuovo ogni `uses:` è di `actions/` o `github/` ed è fissato a un commit di 40 cifre esadecimali; l'elenco `--expect` coincide con i quattro job degli strumenti | Unit test |
| CA12 | Due `--require-check`: il DAST parte solo con entrambi superati; uno fallito produce "non eseguito" | Unit test |
| CA13 | DAST `success` e PT abilitato: Strix viene eseguito; nessun finding dà `success` con score 100 | Unit test con comando simulato |
| CA14 | Un finding High di Strix dà `failure`; DAST `failure` dà PT `failure` "non eseguito" senza eseguire Strix | Unit test |
| CA15 | Strix con codice 1, o senza cartella del run, o con codice 2 senza `vulnerabilities.json`: stato `error` | Unit test |
| CA16 | `--pentest-cmd` senza `--pentest-authorized`: l'agente termina con errore prima di ogni chiamata | Unit test |
| CA17 | Senza `--pentest-cmd` l'agente non esegue Strix e non scrive lo stato PT | Unit test |
| CA18 | Suite completa del repository con le estensioni: tutti i test verdi; `appsec-pipeline.yml` identico a `main` | Esecuzione |
| CA19 | Workflow eseguito su GitHub: i quattro check di strumento verdi; `SAST AGGREGATO` rosso sullo scenario A con la SQL injection tra i bloccanti; job 01 della pipeline esistente verde | Verifica reale, a cura dell'utente |
| CA20 | PT eseguito sulla macchina con Strix reale: stato `PT AGENTICO (STRIX)` scritto sul commit con score e numero di finding | Verifica reale, a cura dell'utente |
| CA21 | Codice 0 di Strix con `status` `stopped`, `running`, `failed` o `interrupted`, o `run.json` illeggibile: stato `error` | Unit test |
| CA22 | Risultati di un'esecuzione precedente nella cartella dello stadio: non riletti | Unit test |
| CA23 | Scatola aperta: Strix riceve la copia del commit, non l'albero condiviso; la copia è eliminata anche in caso di errore; SHA diverso: Strix non parte | Unit test; prova reale con git e comando finto |
| CA24 | Risultato senza `ruleId` o con regola non dichiarata: codice 3; regole dichiarate nelle estensioni trovate | Unit test |
| CA25 | Job di uno strumento non `success`, esito assente o `executionSuccessful: false`: codice 3 anche con report presente; senza `--expect`: codice 3 | Unit test |
| CA26 | `GH_TOKEN` e `GITHUB_TOKEN` assenti dall'ambiente di Strix; `STRIX_TELEMETRY` a `0` salvo valore dell'operatore | Unit test |
| CA27 | Tempo massimo: il comando riceve SIGTERM prima di SIGKILL | Unit test con processo reale |
| CA28 | DAST `[SIMULATO]` superato e PT reale abilitato: PT "non eseguito" | Unit test |
| CA29 | Riepilogo con una riga per strumento in JSON e Markdown (RF6); caricamento in Code Scanning con `continue-on-error` (RF7); `--redact` e immagini a versione fissata | Unit test |
| CA30 | Severità: profilo dello strumento prima del livello SARIF; regola senza livello vale `warning`; risultati soppressi non conteggiati ma elencati, soppressioni respinte ignorate; `none` di Strix vale Info | Unit test |
| CA31 | Semgrep reale sull'intero repository con le due estensioni applicate, CodeQL, Gitleaks e Trivy senza finding: score 91, PASS, una soppressione rivista elencata | Esecuzione del 19 novembre 2026 |

## 12. Rischi

| Rischio | Mitigazione |
|---|---|
| Baseline non misurata: Gitleaks o Trivy possono trovare finding sul codice attuale e far fallire lo scenario C | `SAST AGGREGATO` si rende obbligatorio nel ruleset solo dopo un run verde; il riepilogo elenca ogni finding conteggiato |
| Le regole `p/default` scaricate su GitHub differiscono da quelle usate qui per le fixture | I test verificano la normalizzazione, non l'elenco delle regole; gli score reali vanno letti dal primo run |
| Struttura SARIF di Gitleaks e Trivy ricostruita dalla documentazione | Fixture dichiarate sintetiche; CA19 chiude il punto |
| Strix esegue attacchi reali e invia dati a un modello linguistico | Disattivato per default; `--pentest-authorized`; la guida richiede ambiente di test e indica il modello locale |
| Esito del PT non ripetibile | Blocco solo su High e Critical; score e report salvati per ogni esecuzione |
| Montaggio dei volumi Docker con utente diverso (già accaduto con ZAP) | I container di Gitleaks e Trivy girano con l'utente del runner |
| Trivy non analizza le librerie npm: su `main` manca `package-lock.json` | Dichiarato nella guida: oggi Trivy copre solo le configurazioni; il lockfile cambierebbe la build esistente |
| Il Medium di Semgrep su `appsec-pipeline.yml` non è correggibile senza toccare la pipeline: score massimo 97 | Dichiarato nella guida; la correzione è una scelta dell'utente |
| Gitleaks legge tutta la storia: una credenziale storica blocca finché non è gestita | `.gitleaksignore`, meccanismo dello strumento |
| Il sandbox di Strix ha privilegi di rete e gira su una macchina interna | Rischio residuo: la guida chiede una macchina o una rete dedicata al PT |
| Il codice di una pull request può contenere istruzioni per il modello (prompt injection) | Pull request da fork ignorate; token di GitHub non passato a Strix; rischio residuo dichiarato |
| Con `--target-url` gli attacchi colpiscono un ambiente condiviso, non legato al commit | `--pentest-authorized`; la guida chiede un ambiente di test dedicato |
| Nessun tetto di spesa predefinito verso il modello | `--pentest-budget`; con budget esaurito lo stato è `error`, non `success` |
| Un PT lungo occupa l'unico ciclo dell'agente e ritarda il DAST delle altre pull request | Predefinito `quick`; `--pentest-timeout` |

## 13. Fuori ambito

- Eccezioni e rischi accettati (file di baseline); strumenti per altri linguaggi (Psalm, Bandit, gosec).
- PT a scatola chiusa sull'applicazione costruita dal commit; apertura di ticket Jira; modifica di `demo_pipeline.py`.
- Replica sull'account aziendale.

## 14. Configurazione manuale

1. Dopo il primo run verde: aggiungere `SAST AGGREGATO` ai check obbligatori del ruleset.
2. Sulla macchina: Docker, Python 3.12, Strix, variabili `STRIX_LLM`, `LLM_API_KEY` ed eventuale `LLM_API_BASE`.
   Avvio dell'agente con `--require-check "01 SAST - CodeQL and High gate" --require-check "SAST AGGREGATO"
   --pentest-cmd strix --pentest-authorized`: senza queste opzioni la catena SAST → DAST → PT non è collegata.
3. Dopo il primo PT riuscito: aggiungere `PT AGENTICO (STRIX)` ai check obbligatori.

## 15. Esito della review indipendente

Review del 19 novembre 2026: verdetto BLOCCATO, cinque BLOCK, tutti corretti in questo documento e nel codice. Gli
score attesi del §8 sono stati ricalcolati dal revisore con uno script indipendente e confermati.

| BLOCK | Problema | Correzione |
|---|---|---|
| 1 | PT `success` su esecuzione non completata: Strix termina con 0 anche a budget esaurito | L'esito vale solo con `run.json` in stato `completed` (RF11, CA21) |
| 2 | Cartella del run non univoca; il codice 2 non significa solo "finding" | Cartella dello stadio per commit, svuotata prima di ogni esecuzione; richiesta esattamente una cartella (RF11, CA22) |
| 3 | Sorgente del PT condiviso e scrivibile da Strix | Copia usa e getta del commit, verificata ed eliminata (RF13, CA23) |
| 4 | Risultato senza regola dichiarata declassato a informativo | INVALID, come nel gate esistente (RF4, CA24) |
| 5 | Job di strumento fallito con report parziale presente | Esito dei job passato al gate; INVALID se non `success` (RF4, CA25) |

WARN recepiti: stima portata a 13 SP; `--scope-mode full`; telemetria disattivata; SIGTERM prima di SIGKILL; PT reale
non eseguito su DAST simulato; `--expect` obbligatoria; intervallo di `security-severity`; criteri di accettazione per
RF1, RF3, RF6, RF7; rischi del PT e limite di Trivy dichiarati. Modifica successiva alla review: le soppressioni nel codice sono rispettate ed elencate, invece che conteggiate. Motivo,
emerso dall'analisi reale con Semgrep dei file dell'estensione: una regola di sola verifica (livello `error`, confidenza
bassa) segnala l'esecuzione di comandi dell'agente; senza soppressioni un falso positivo rivisto bloccherebbe per sempre.
La regola "High blocca a qualunque confidenza" resta.

WARN non recepiti: immagini Docker fissate per digest
(i registri non sono raggiungibili da questa sessione: restano a versione), tetto di spesa predefinito, limitazione di
Gitleaks ai soli commit della pull request.
