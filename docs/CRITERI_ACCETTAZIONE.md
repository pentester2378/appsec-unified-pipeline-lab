# Matrice di accettazione PoC — da compilare dopo i run GitHub reali

| Scenario | SHA | CodeQL / gate | Docker | ZAP / gate | Gate finale | Evidenza |
|---|---|---|---|---|---|---|
| A: SQL concatenata | ... | Atteso FAIL | Atteso skipped | Atteso skipped | Atteso FAIL | URL run e SARIF |
| B: SQL parametrizzata, CSP OFF | ... | Atteso PASS | Atteso PASS | Atteso FAIL 10038-1 | Atteso FAIL | URL run e zap.html |
| C: SQL parametrizzata, CSP ON | ... | Atteso PASS | Atteso PASS | Atteso PASS | Atteso PASS | URL run e artifacts |

**Per considerare la PoC completata** servono esecuzioni reali dei tre commit su GitHub Actions e la verifica dell'enforcement del Ruleset su main. Un singolo job verde non soddisfa il criterio di accettazione.

## Per il pilot aziendale

Non aggiungere direttamente l'applicazione dimostrativa ai repository di prodotto. Prima definisci:
- Repository pilota reale e permessi GitHub Code Security / Rulesets.
- Adattatore build/runtime per il linguaggio e il tipo di applicazione (Node.js, Java, .NET, Python...).
- Immagini Docker versionate con digest e dipendenze lockate.
- Scansione ZAP autenticata per web/API e policy rischio approvata.
- Staging isolato o runner dedicato che non esegua codice PR non attendibile su infrastruttura privilegiata.
- Versionamento SHA/digest tra SAST, runtime DAST e artefatto rilasciato.
- Jira, owner, triage, deduplicazione, retest e scadenze delle eccezioni.
