# SAST multi-strumento, DAST e PT agentico su macchina esterna — Piano implementativo

**Goal:** aggiungere alla PoC, senza modificare la pipeline esistente, un workflow SAST con quattro strumenti e gate
aggregato, e all'agente esterno l'attesa di più check e lo stadio di PT agentico con Strix.
**Design doc:** `docs/plans/2026-11-19-sast-multi-dast-pt-esterno-design.md` (review indipendente: cinque BLOCK corretti, §15)
**Esecuzione:** nella sessione corrente, con test scritti prima del codice (`siae-tdd`). Consegna come estensione da
caricare con pull request: questa sessione non ha accesso in scrittura al repository.

## Vincoli Globali

- Solo libreria standard Python; compatibile con Python 3.9 (design §5).
- Codici di uscita del gate: 0 PASS, 2 FAIL, 3 INVALID; 2 ogni volta che `status` è FAIL, anche con `blocking` vuoto.
- Policy: soglia 90; pesi critical 40, high 20, medium 3, low 1, info 0; bloccanti critical e high. PASS se e solo se
  `score > 90` e nessun bloccante (design §8).
- Tolleranza di riga per i duplicati tra strumenti: 5 (design §8).
- Nomi esatti: job `S1 SAST - CodeQL`, `S2 SAST - Semgrep`, `S3 SECRETS - Gitleaks`, `S4 SCA-IAC - Trivy`,
  `SAST AGGREGATO`; stati `DAST ESTERNO (ZAP)` e `PT AGENTICO (STRIX)` (design §7).
- Non cambiano `.github/workflows/appsec-pipeline.yml`, `scripts/sast_gate.py`, `scripts/dast_gate.py`,
  `scripts/set_scenario.py`, `src/`, `Dockerfile`, `compose.test.yml` (RF12).
- Ogni script espone `main(argv=None) -> int`: i test verificano il codice di uscita senza avviare processi.
- Nel workflow nuovo ogni `uses:` è di `actions/` o `github/` ed è fissato a un commit (design §5).
- Nessuna credenziale nel repository; Gitleaks sempre con `--redact`.
- Mai un esito positivo su dati mancanti, incompleti o illeggibili (RF4, RF11).
- Comando dei test: `python3 -m unittest discover -s tests -p 'test_*.py' -v`.

## Review Focus

- SARIF con un risultato privo di `ruleId` o con regola non dichiarata → INVALID con codice 3, mai declassato a
  informativo: test in task-01.
- Job di uno strumento fallito che ha comunque caricato un report parziale → INVALID: test in task-01 e task-02.
- Strix che termina con codice 0 a scansione non completata (budget esaurito) → stato `error`: test in task-04.
- Risultato con `uri` assoluto o con prefisso `file://` → percorso normalizzato, così il confronto tra strumenti
  funziona: test in task-01.
- Due file SARIF dello stesso strumento nella stessa cartella → entrambi letti, conteggi sommati: test in task-01.
- `vulnerabilities.json` di Strix che non è una lista, o con un finding senza `severity` → stato `error`, mai
  `success`: test in task-04.
- Agente riavviato con DAST già `success` e PT rimasto `pending` → il PT viene ripreso senza rieseguire il DAST: test
  in task-04.

## Indice Task

| # | Task | File | Stato |
|---|------|------|-------|
| 1 | Gate SAST aggregato | `task-01-gate-sast-aggregato.md` | [DONE] |
| 2 | Workflow SAST multi-strumento | `task-02-workflow-sast-multi.md` | [DONE] |
| 3 | Agente: attesa di più check | `task-03-agente-check-multipli.md` | [DONE] |
| 4 | Agente: stadio PT agentico | `task-04-agente-pt-agentico.md` | [DONE] |
| 5 | Documentazione e pacchetto | `task-05-documentazione.md` | [DONE] |
| 6 | Verifica reale su GitHub e sulla macchina | `task-06-verifica-reale.md` | [PENDING] |

## Copertura del design

- RF2, RF3, RF4, RF5, RF6, CA1–CA10, CA24, CA25, CA29, CA30: task-01.
- RF1, RF7, CA11: task-02; CA19: task-06.
- RF8, CA12: task-03.
- RF9, RF10, RF11, RF13, RF14, CA13–CA17, CA21–CA23, CA26–CA28: task-04; CA20: task-06.
- RF12, CA18: verifica finale di ogni task e task-05.

## Dipendenze

task-02 usa le opzioni del gate di task-01. task-04 usa `stage_states` e `set_status(..., context=)` introdotti in
task-03. task-05 segue tutti. task-06 richiede il caricamento nel repository e la macchina: è a cura dell'utente.
