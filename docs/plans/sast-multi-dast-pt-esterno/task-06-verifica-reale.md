# Task 06 — Verifica reale su GitHub e sulla macchina

**Obiettivo:** chiudere CA19 e CA20, non verificabili nella sessione di sviluppo.
**Requisiti:** CA19, CA20.
**Dipendenze:** task-05; caricamento nel repository; macchina con Docker e Strix.
**Complessità:** Media

## Modifiche

1. Pull request con l'estensione: osservare i cinque check e leggere score e finding dal riepilogo del job.
2. Se lo scenario C non supera il gate: correggere i finding segnalati prima di rendere il check obbligatorio.
3. Sulla macchina: `--dry-run --once`, poi una esecuzione reale con `--pentest-cmd` su una pull request di prova.

## Verifica

- Esito atteso: `SAST AGGREGATO` verde sullo scenario C e rosso sullo scenario A; stato `PT AGENTICO (STRIX)` scritto
  sul commit con score e numero di finding.
