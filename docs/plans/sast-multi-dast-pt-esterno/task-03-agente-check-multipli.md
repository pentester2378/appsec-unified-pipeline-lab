# Task 03 — Agente: attesa di più check

**Obiettivo:** il DAST esterno parte solo quando tutti i check indicati sono superati.
**Requisiti:** RF8, CA12; design §7.3.
**Dipendenze:** nessuna.
**Complessità:** Bassa

## Interfacce

- Produce, in `scripts/dast_external_agent.py`:
  - `required_checks_state(gh, sha, names) -> (stato, nome)`: `("success", None)` se tutti superati; la conclusione
    negativa e il nome del primo check non superato (prevale su un check in corso); altrimenti `("pending", nome)`.
  - `stage_statuses(gh, sha) -> dict` con lo stato completo più recente per contesto.
  - `stage_states(gh, sha) -> dict` con lo stato più recente di `CONTEXT` e `PT_CONTEXT` (chiavi assenti se lo stato
    non esiste).
  - `GitHub.set_status(sha, state, description, context=CONTEXT)`.
  - `PT_CONTEXT = "PT AGENTICO (STRIX)"`.
- Conserva: `required_check_state(gh, sha, name)`, `needs_scan(gh, sha)`; `cfg["require_check"]` accetta una stringa
  o una lista.

## File

- Modifica: `tests/test_dast_external_agent.py` — test aggiunti prima del codice.
- Modifica: `scripts/dast_external_agent.py`.

## Modifiche

1. `--require-check` con `action="append"`.
2. `poll_once` usa `required_checks_state`; messaggi di log e descrizione dello stato nominano il check non superato.
3. Test: due check entrambi superati → scansione; uno in corso → attesa; uno fallito → `failure` "non eseguito".

## Verifica

- Esegui: `python3 -m unittest tests.test_dast_external_agent -v`.
- Esito atteso: i 34 test esistenti e quelli nuovi verdi.
