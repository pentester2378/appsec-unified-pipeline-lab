# Task 05 — Documentazione e pacchetto

**Obiettivo:** guida operativa e archivio dell'estensione.
**Requisiti:** RF12, CA18; design §14.
**Dipendenze:** task-01, task-02, task-03, task-04.
**Complessità:** Bassa

## File

- Crea: `docs/SAST_MULTI_DAST_PT.md` — strumenti, policy, lettura del riepilogo, avvio dell'agente con PT, limiti.
- Modifica: `docs/DAST_ESTERNO_OPZIONE_C.md` — opzioni nuove e rinvio alla guida.

## Modifiche

1. Guida con i comandi di caricamento tramite pull request e l'ordine di attivazione dei check nel ruleset.
2. Elenco esplicito di ciò che non è stato verificato in esecuzione reale.

## Verifica

- Esegui la suite completa su una copia di `main` con le estensioni applicate; confronta
  `.github/workflows/appsec-pipeline.yml` con `origin/main`.
- Esito atteso: tutti i test verdi; nessuna differenza nel file della pipeline.
