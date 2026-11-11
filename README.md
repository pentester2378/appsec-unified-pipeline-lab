# AppSec Unified Pipeline Lab — CodeQL → Docker → ZAP

Una **sola applicazione** (Express + PostgreSQL) viene verificata in sequenza con **CodeQL SAST**, costruita con **Docker** e scansionata da **OWASP ZAP DAST**. Tutto avviene nel medesimo workflow GitHub Actions, sul medesimo commit della PR.

> **Stato:** i gate Python, i comandi di selezione scenario, gli unit test Node e la sintassi YAML sono stati verificati localmente. **La build Docker, l'analisi CodeQL reale e la scansione ZAP reale non sono state eseguite in questo ambiente** (Docker e accesso al registro npm assenti). Le prove A/B/C sono risultati **attesi** da validare su GitHub.

## Architettura

```text
PR → [01 CodeQL + policy su SARIF]
   │ se PASS
   ↓
[02 Build Docker Node+PostgreSQL → health/test → ZAP Baseline → DAST policy]
   │ se PASS
   ↓
[03 APPSEC UNIFIED GATE: SUCCESS]
   └─ GitHub branch Ruleset: require status check to pass
```

Quando SAST fallisce, DAST è `skipped`; l'ultimo job `03 APPSEC UNIFIED GATE` fallisce comunque perché `if: always()` e verifica esplicitamente i risultati dei due job. Il successo tecnico di `CodeQL Analyze` **non** equivale automaticamente a SAST PASS: `scripts/sast_gate.py` legge il SARIF della stessa esecuzione e blocca alert di sicurezza con CVSS >= 7.0.

## Contenuti del progetto

```text
src/app.js                       API HTTP, query SQL parametrizzata, rate limiting, CSP
src/server.js                    avvio su :3000 dopo connessione database
database/init.sql               seed PostgreSQL
compose.test.yml                app+DB isolati, toggle CSP per lo scenario B
Dockerfile                      immagine applicativa Node.js 22
.github/workflows/appsec-pipeline.yml  workflow Github Actions
scripts/sast_gate.py            CodeQL SARIF => PASS/FAIL
scripts/dast_gate.py            ZAP traditional JSON => PASS/FAIL
scripts/set_scenario.py         genera i commit A, B, C
scripts/test_*                  unit test gate
```

## 1. Crea un repository nuovo, NON modificare le due PoC storiche

Consiglio: `appsec-unified-pipeline-lab` **pubblico e personale**, con codice esclusivamente fittizio. Se l'azienda ha Code Security abilitato e un'autorizzazione a fare prove, puoi in seguito replicarlo su un repository aziendale pilota. I repository privati personali possono non consentire CodeQL Code Scanning senza licenza.

1. GitHub → `+` → **New repository** → nome `appsec-unified-pipeline-lab`.
2. Scegli **Public**, usa solo il codice didattico e non spuntare README/.gitignore/licenza (sono già nel kit).
3. Estrai l'archivio ZIP sul PC in una cartella; apri il terminale **dentro** `appsec-unified-pipeline-lab`.
4. Inserisci il tuo URL reale al posto di `<OWNER>`:

```bash
git init
git branch -M main
git add .
git commit -m 'Initial unified SAST Docker DAST PoC'
git remote add origin https://github.com/<OWNER>/appsec-unified-pipeline-lab.git
git push -u origin main
```

Se preferisci il browser, puoi usare un **GitHub Codespace** su un repo inizializzato e copiare i file nella struttura prevista; il caricamento dello ZIP come unico file **non** crea automaticamente la struttura del progetto.

## 2. Primo run: verifica la pipeline con codice corretto (scenario C)

Il progetto è già predisposto nello scenario C: SQL parametrizzato e `ENABLE_CSP: 'true'`.

- Repository → **Actions** → `AppSec Unified - SAST then Docker then DAST` → **Run workflow** sul branch `main`.
- Attendi gli esiti: **01 SAST** poi **02 DAST** poi **03 APPSEC UNIFIED GATE**.
- Verifica gli artifact `sast-evidence`, `dast-evidence`, in particolare `zap.html` / `zap.json`, `sast-gate.json`, `dast-gate.json`.
- Se DAST è `skipped`, controlla il job SAST (SARIF, permissions, licenza). Non cercare il problema nei container.
- La prima esecuzione reale serve a verificare che l'ambiente hosted abbia tutti i prerequisiti. **Non è stata eseguita durante la creazione del kit.**

### Niente duplicazione CodeQL

Il workflow include **CodeQL Advanced Setup** (`init@v4` e `analyze@v4`). Su un nuovo repo non abilitare contemporaneamente il Default Setup come secondo scanner. Se CodeQL Default Setup fosse già attivo, concorda e configura la transizione ad Advanced Setup.

## 3. Aggiungi la protezione su `main`

Dopo che il primo run ha creato i check:

1. **Settings → Rules → Rulesets → New branch ruleset**.
2. Nome `AppSec-Unified-Gate` e stato **Active**.
3. Target: **Include default branch** (`main`).
4. Attiva **Require a pull request before merging**.
5. Attiva **Require status checks to pass** e cerca il check **`03 APPSEC UNIFIED GATE`**; selezionalo. Se non lo vedi, verifica il run su `main` e i permessi.
6. Attiva **Block force pushes**. Per il pilota, bypass list vuota se le policy dell'organizzazione lo consentono.
7. Salva. Se disponibile e consentito, aggiungi anche **Require code scanning results → CodeQL → High or higher** come seconda protezione nativa. Non sostituisce il check end-to-end.

Per impostazione, il job `03 APPSEC UNIFIED GATE` fallisce se SAST o DAST falliscono **o vengono saltati**. È il check che dimostra il blocco sequenziale del merge.

## 4. Dimostra i tre scenari sulla STESSA Pull Request

Lavora su un unico branch di test: `test/three-security-gates`.

### A — SQL Injection → blocco SAST

```bash
git checkout -b test/three-security-gates
python3 scripts/set_scenario.py a
git add src/app.js compose.test.yml
git commit -m 'TEST A: intentionally vulnerable SQL for SAST gate'
git push -u origin test/three-security-gates
```

Apri la PR verso `main`. Esito atteso: `01 SAST` FAIL (CodeQL `js/sql-injection`), `02 DAST` SKIPPED, `03 APPSEC UNIFIED GATE` FAIL e PR non integrabile. **Non effettuare il merge di questo commit.**

### B — SQL corretto, ma CSP disabilitata → blocco DAST

Nel medesimo branch:

```bash
python3 scripts/set_scenario.py b
git add src/app.js compose.test.yml
git commit -m 'TEST B: fix SQL, deliberately disable CSP on runtime'
git push
```

Esito atteso: SAST PASS → Docker + PostgreSQL avviati → ZAP identifica `10038-1 Content Security Policy (CSP) Header Not Set` → policy DAST FAIL → gate finale FAIL. La regola CSP è Medium nativa: il suo blocco è **una scelta intenzionale della policy didattica**.

### C — SQL e CSP corretti → tutti i gate PASS

Sempre nel medesimo branch:

```bash
python3 scripts/set_scenario.py c
git add src/app.js compose.test.yml
git commit -m 'TEST C: fix CSP; SAST and DAST expected to pass'
git push
```

Esito atteso: CodeQL + SAST gate PASS, Docker runtime pronto, ZAP Baseline report senza alert CSP mancante, DAST gate PASS, check finale `03 APPSEC UNIFIED GATE` PASS. Il pulsante di merge non deve essere usato finché non hai verificato tutto.

### Tabella verifiche

| Test | 01 SAST | 02 Docker + ZAP | 03 Gate finale |
|---|---|---|---|
| A — SQLi | FAIL | SKIPPED | FAIL |
| B — No CSP | PASS | FAIL | FAIL |
| C — Corretto | PASS | PASS | PASS |

**Avvertenza:** gli esiti A/B/C di GitHub nella tabella sono **attesi**, non risultati ancora osservati. Se uno scanner cambia query o regole, correggiamo il laboratorio in base ai log reali. Gli unit test verificano solo la logica dei gate.

## 5. Test locali facoltativi

Per gli unit test senza Docker:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
npm test
```

Per avviare l'intero stack serve Docker Compose e accesso Internet per scaricare le immagini:

```bash
docker compose -p appsec-poc -f compose.test.yml up -d --build --wait
docker run --rm --network appsec-unified-ci curlimages/curl:latest -fsS http://app:3000/health
docker run --rm --network appsec-unified-ci curlimages/curl:latest -fsS http://app:3000/search/fruit
docker compose -p appsec-poc -f compose.test.yml down --volumes
```

Non si espongono porte host: app, database e ZAP restano su una rete Docker dedicata. La password `appsec-demo-only` è fittizia e non va riusata su sistemi aziendali.

## 6. Limiti importanti

- Lo step ZAP usa **Baseline + passive scanning** e uno spider, non Full Active Scan. È una scelta per rendere la prima pipeline riproducibile e sufficientemente rapida. Per DAST approfondito su staging si potrà usare ZAP Automation Framework con contesto autenticato, scansione attiva e limiti operativi.
- Il **DAST Gate** della PoC blocca `10038-1` (CSP mancante) anche se Medium, e tutti gli High+ a confidence Medium+. Non è una policy aziendale generale. Un report vuoto o fuori scope produce errore e non PASS.
- Il **SAST Gate** blocca SARIF con `security-severity` CVSS >=7.0. È un gate ad hoc sulla scansione corrente, non gestisce baseline, false positive e accettazioni di rischio. Il ruleset nativo GitHub può essere configurato separatamente per i nuovi alert nelle PR.
- I risultati dei report non provano la totale assenza di vulnerabilità. GitHub Code Security e permessi aziendali devono essere verificati prima della migrazione.
- Lo step build usa inizialmente `npm install` perché il lockfile reale richiede l'accesso al registro npm. Per rendere la build ripetibile, **genera e committa `package-lock.json`** con `npm install --package-lock-only` prima dell'utilizzo aziendale: il Dockerfile userà automaticamente `npm ci` se il lockfile esiste.
- **Jira / Vulnerability Management non sono ancora collegati**: è la fase successiva dopo la validazione end-to-end della stessa applicazione.
- Il workflow è pensato per PR da branch dello **stesso repository**; i permessi `security-events: write` possono non essere disponibili per PR da fork, specie nei repository privati.

## 7. Se qualcosa non funziona

| Sintomo | Controllo |
|---|---|
| `CodeQL analyze` rosso | Repository CodeQL abilitabile, Actions permissions, Advanced Setup, runtime e log. |
| `SAST GATE INVALID` | Trova `codeql-results/*.sarif` nell'artifact; output di CodeQL mancante o schema diverso. |
| `SAST PASS` ma merge bloccato | Può dipendere da Rulesets aggiuntivi o altri required checks. |
| `02 DAST` SKIPPED | È voluto se `01 SAST` non ha esito success. |
| Docker build fallisce | Prima verifica npm registry e rete del runner, non ZAP. |
| `app:3000` non risponde | `docker compose ... ps` e `docker compose ... logs app db`. |
| ZAP non trova CSP mancante | Verifica risposta `GET /` con HTML, report `zap.json`, rule `10038-1` e configurazione `ENABLE_CSP`. |
| `Permission denied` nei report | ZAP usa UID 1000 nel volume; lo step prepara la cartella con chown. |
| `No supported languages` | Assicurati che `src/app.js` sia nella PR e CodeQL JS/TS sia realmente abilitato. |

### Riferimenti

- GitHub CodeQL Action: https://github.com/github/codeql-action
- Code Scanning SARIF: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- ZAP Baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
- ZAP CSP missing rule 10038-1: https://www.zaproxy.org/docs/alerts/10038-1/
# appsec-unified-pipeline-lab
