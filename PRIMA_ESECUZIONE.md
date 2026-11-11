# PRIMA ESECUZIONE — istruzioni rapide

## Cosa devi ottenere

Una sola PR in `appsec-unified-pipeline-lab` con tre commit progressivi:

1. **A** SQL Injection → CodeQL SAST gate rosso → Docker/ZAP saltati.
2. **B** SQL riparata, CSP disattivata → SAST verde → Docker avviato → ZAP DAST gate rosso.
3. **C** SQL e CSP corretti → SAST verde → Docker + ZAP verde → gate finale verde.

I risultati sono da verificare con **run GitHub reali**.

## Primo passo

1. Scarica lo ZIP e estrailo.
2. Crea su GitHub un repository **pubblico personale** `appsec-unified-pipeline-lab` senza README iniziale. Non usare credenziali né codice aziendale.
3. Dal terminale nella directory estratta:

```bash
git init
git branch -M main
git add .
git commit -m 'Initial unified AppSec PoC'
git remote add origin https://github.com/<OWNER>/appsec-unified-pipeline-lab.git
git push -u origin main
```

4. GitHub → repository → **Actions** → `AppSec Unified - SAST then Docker then DAST` → `Run workflow` su `main`.
5. Apri il run. Se fallisce, manda uno screenshot dell'**esatto step rosso**. Se è verde, configura il Ruleset prima della PR A.

## Passaggio successivo (dopo primo workflow verde)

**Settings → Rules → Rulesets → New branch ruleset**: Active; target `main`; Require pull request; Require status checks to pass → `03 APPSEC UNIFIED GATE`; Block force pushes.

Poi esegui:

```bash
git checkout -b test/three-security-gates
python3 scripts/set_scenario.py a
git add src/app.js compose.test.yml
git commit -m 'TEST A - intentionally unsafe SQL'
git push -u origin test/three-security-gates
```

GitHub → **Pull requests → Compare & pull request** con base `main` e compare `test/three-security-gates`.

Per le prove B e C, sullo stesso branch:

```bash
python3 scripts/set_scenario.py b
git add src/app.js compose.test.yml
git commit -m 'TEST B - fix SQL; disable CSP'
git push

python3 scripts/set_scenario.py c
git add src/app.js compose.test.yml
git commit -m 'TEST C - enable CSP'
git push
```

**Non eseguire B e C prima che la scansione A/B sia terminata**: i commit successivi possono annullare le esecuzioni precedenti (concurrency cancel-in-progress).

## Limiti della verifica presente

Qui abbiamo verificato sintassi JavaScript, YAML, Bash e test unitari dei due gate. **Non** abbiamo potuto eseguire Docker o scaricare le dipendenze npm, quindi non affermiamo che la pipeline sia già risultata verde su GitHub. La prima esecuzione reale ci permetterà di correggere eventuali differenze del runner/CodeQL/ZAP.
