# Task 01 — Gate SAST aggregato

**Obiettivo:** uno script legge i SARIF di più strumenti e produce score, bloccanti ed esito unico.
**Requisiti:** RF2–RF6, CA1–CA10; design §7.2, §8, §10.
**Dipendenze:** nessuna.
**Complessità:** Media
**Rischio:** sicurezza

## Interfacce

- Produce, in `scripts/sast_multi_gate.py`:
  - `load_runs(path) -> list` di `(file, run)`; `ValueError` se non ci sono SARIF, se un file non è SARIF 2.1.0 o se un
    run non ha `tool.driver`.
  - `tool_name(run) -> str`: nome normalizzato (`codeql`, `semgrep`, `gitleaks`, `trivy`, oppure la prima parola del
    nome del driver in minuscolo).
  - `normalize(runs) -> list` di dizionari `tool`, `rule`, `path`, `line`, `severity`, `security`, `low_confidence`,
    `cwes`, `title`.
  - `evaluate(results, tools, expected=()) -> dict` con le chiavi del riepilogo (design §9); `ValueError` se uno
    strumento atteso manca.
  - `to_markdown(summary) -> str`.
  - `check_job_results(entries, expected)`: `ValueError` se uno strumento atteso non ha esito `success`.
  - `main(argv=None) -> int`; opzioni `--sarif-dir` (obbligatoria), `--expect` (obbligatoria, elenco separato da
    virgole), `--job-result STRUMENTO=ESITO` (ripetibile), `--summary` (predefinito
    `reports/sast-multi-gate.json`), `--markdown` (facoltativa).
- Consuma: nulla dagli altri task.

## File

- Crea: `tests/fixtures/sast-multi/*.sarif` — CodeQL e Semgrep reali ridotti; Gitleaks e Trivy sintetici.
- Crea: `tests/test_sast_multi_gate.py` — test nuovi, scritti prima dello script.
- Crea: `scripts/sast_multi_gate.py`.

## Modifiche

1. Severità nell'ordine del design §8: `security-severity`, profilo dello strumento, livello SARIF, `warning`.
2. Rilevanza di sicurezza e confidenza come da design §8; i bloccanti si valutano prima dell'esclusione per confidenza.
3. Unità di conteggio per `(strumento, regola, file)`; unione tra strumenti diversi con stesso file, CWE in comune e
   righe entro 5.
4. Riepilogo JSON e Markdown; righe `::error file=…,line=…::` per ogni bloccante.
5. Risultato senza `ruleId` o con regola non dichiarata, `executionSuccessful: false`, `security-severity` fuori da
   0–10: `ValueError`.
6. Test: CA1–CA10, CA24, CA25, CA29, CA30 e le righe del Review Focus assegnate a questo task.

## Verifica

- Esegui: `python3 -m unittest tests.test_sast_multi_gate -v`.
- Esito atteso: tutti verdi; scenario A 77 con un bloccante `codeql+semgrep`; scenario C 97.
