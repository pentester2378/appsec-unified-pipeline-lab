# Task 04 — Agente: stadio PT agentico

**Obiettivo:** dopo un DAST esterno superato l'agente esegue Strix e scrive lo stato `PT AGENTICO (STRIX)`.
**Requisiti:** RF9, RF10, RF11, CA13–CA17; design §7.3, §8, §10.
**Dipendenze:** task-03 (`stage_states`, `set_status(..., context=)`, `PT_CONTEXT`).
**Complessità:** Alta
**Rischio:** sicurezza

## Interfacce

- Produce, in `scripts/dast_external_agent.py`:
  - `evaluate_pentest(findings) -> dict` con `gate` (`pt-agentico`), `tool` (`strix`), `status`, `score`, `threshold`,
    `counts`, `blocking`, `findings`; `ValueError` se `findings` non è una lista, se un elemento non è un oggetto o se
    la severità manca o è sconosciuta (`none` vale `info`).
  - `run_pentest(candidate, cfg, run=run_cmd) -> dict`: esegue
    `<pentest_cmd> -n -t <bersaglio> --scan-mode <mode>`, più `--scope-mode full` a scatola aperta e
    `--max-budget-usd <n>` se indicato, nella cartella `reports/<sha>/pentest/`; `ScanError` nei casi del design §10.
  - `pentest_source_copy(candidate, cfg, copy, run)`: copia del commit con `git worktree`, verificata sullo SHA.
  - `read_strix_run(runs_dir, returncode) -> (cartella, finding)`: richiede `run.json` in stato `completed`.
  - `process_pentest(gh, candidate, cfg, pentest=run_pentest) -> str`: stato scritto.
- Consuma: `prepare_source` per il bersaglio a scatola aperta; `stage_states`; `set_status(..., context=PT_CONTEXT)`.

## File

- Modifica: `tests/test_dast_external_agent.py` — test aggiunti prima del codice.
- Modifica: `scripts/dast_external_agent.py`.

## Modifiche

1. Opzioni: `--pentest-cmd`, `--pentest-authorized`, `--pentest-mode` (`quick`, `standard`, `deep`; predefinito
   `quick`), `--pentest-budget` (USD, maggiore di 0), `--pentest-timeout` (minuti, predefinito 60).
2. Senza `--pentest-authorized` (fuori da `--dry-run` e `--simulate`) l'agente termina con errore prima di ogni chiamata.
3. `poll_once`: una sola lettura degli stati per commit; stadio DAST come oggi; stadio PT se abilitato e non definitivo.
   DAST `success` → PT; DAST `failure` o `error` → PT `failure` "non eseguito"; DAST non definitivo → attesa.
4. Prima di eseguire Strix la cartella `strix_runs` dello stadio viene svuotata; dopo, deve esistere un solo run il
   cui `run.json` ha `status: completed`. Ambiente di Strix senza i token di GitHub e con `STRIX_TELEMETRY=0`.
5. Codice 0 o 2: esecuzione completata, i finding si leggono da `vulnerabilities.json` (assente con codice 0: nessun
   finding; assente con codice 2: errore). Ogni altro codice: errore.
6. `--simulate`: Strix non viene eseguito, esito senza finding con dicitura `[SIMULATO]`.
7. `--dry-run`: l'agente scrive solo nel log cosa farebbe.
8. Un DAST con dicitura `[SIMULATO]` non autorizza un PT reale. `run_cmd` invia SIGTERM prima di SIGKILL.
9. Test: CA13–CA17, CA21–CA23, CA26–CA28 e le righe del Review Focus assegnate a questo task.

## Verifica

- Esegui: `python3 -m unittest tests.test_dast_external_agent -v`.
- Esito atteso: tutti verdi. L'esecuzione con Strix reale è in task-06.
