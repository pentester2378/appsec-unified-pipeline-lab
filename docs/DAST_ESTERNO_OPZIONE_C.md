# DAST su macchina esterna — opzione C (agente autonomo)

La scansione OWASP ZAP gira su una macchina interna alla rete, non sui runner di GitHub. La macchina non riceve
connessioni: a intervalli chiede a GitHub quali commit attendono il controllo, li scansiona e scrive l'esito sul
commit come stato **`DAST ESTERNO (ZAP)`**. Un ruleset che richiede quello stato blocca il merge finché l'esito non
è positivo.

La pipeline esistente (`.github/workflows/appsec-pipeline.yml`) non viene modificata.

## Come funziona

1. Ogni 30 secondi l'agente legge le pull request aperte verso `main` (oppure la testa di un branch, con `--branch`).
2. Per ogni commit senza esito definitivo scrive lo stato in attesa.
3. Scarica quel commit, avvia l'applicazione con Docker Compose, esegue ZAP Baseline e calcola lo score.
4. Scrive lo stato finale con lo score nella descrizione e salva i report sulla macchina.

| Stato su GitHub | Significato | Effetto sul merge |
|---|---|---|
| In attesa | Scansione in corso, oppure macchina spenta | Bloccato |
| Superato | Score maggiore di 90 e nessun finding bloccante | Consentito |
| Fallito | Score fino a 90, oppure almeno un finding bloccante | Bloccato |
| Errore | Scansione non completata (build, avvio, report assente) | Bloccato |

## Policy applicata

`score = 100 − somma dei pesi`, una volta per regola di alert: Critical 40, High 20, Medium 3, Low 1, Info 0.
Sono bloccanti gli alert High e Critical e la regola `10038-1` (header CSP mancante), a qualunque livello di
confidenza. Gli altri alert contano solo da confidenza Medium in su. I valori sono costanti in cima a
`scripts/dast_external_agent.py`.

## Requisiti della macchina

- `python3`, `git`, `docker` con il plugin `compose`. ZAP può essere quello dell'immagine Docker oppure quello
  installato sulla macchina (opzione `--zap-cmd`); Docker non serve se si usano insieme `--zap-cmd` e `--target-url`.
- Uscita HTTPS verso `api.github.com`, `github.com`, `ghcr.io` e Docker Hub (o un registro interno con le stesse
  immagini). Nessuna porta in ingresso.
- Con un proxy aziendale: variabili `HTTPS_PROXY` e certificato configurati per Python, git e Docker.

## Token

GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.

| Campo | Valore |
|---|---|
| Repository access | Only select repositories → il repository da controllare |
| Commit statuses | Read and write |
| Contents | Read-only, solo se il repository è privato |
| Pull requests | Read-only, solo se il repository è privato |

Il token resta sulla macchina. Chi lo possiede può scrivere uno stato positivo: va trattato come una credenziale.

## Avvio

Prova senza scrivere nulla e senza Docker:

```bash
python3 scripts/dast_external_agent.py --repo <owner>/<repo> --dry-run --once
```

Avvio reale:

```bash
export GH_TOKEN=<token>
python3 scripts/dast_external_agent.py --repo <owner>/<repo>
```

Opzioni principali:

| Opzione | Effetto |
|---|---|
| `--base main` | Controlla le pull request aperte verso quel branch (predefinito) |
| `--branch test` | Controlla invece la testa di un branch, per il DAST dopo il merge |
| `--require-check "01 SAST - CodeQL and High gate"` | Scansiona solo i commit su cui quel check è superato; se è fallito scrive lo stato fallito con la dicitura "non eseguito". Ripetibile: con più opzioni devono essere superati tutti i check indicati |
| `--pentest-cmd strix --pentest-authorized` | Dopo un DAST superato esegue il PT agentico e scrive lo stato `PT AGENTICO (STRIX)`; dettagli in `docs/SAST_MULTI_DAST_PT.md` |
| `--target-url https://app.tst.example` | Scansiona un'applicazione già attiva, senza costruirla sulla macchina |
| `--interval 30` | Secondi tra un controllo e l'altro |
| `--once` | Un solo controllo, poi termina |
| `--work-dir ~/appsec-dast-agent` | Cartella di lavoro; i report finiscono in `reports/<commit>/` |

Per tenerlo sempre attivo, esempio di servizio systemd (`/etc/systemd/system/dast-agent.service`):

```ini
[Unit]
Description=Agente DAST esterno
After=network-online.target docker.service

[Service]
User=<utente>
EnvironmentFile=/etc/dast-agent.env
ExecStart=/usr/bin/python3 /opt/dast-agent/dast_external_agent.py --repo <owner>/<repo>
Restart=always

[Install]
WantedBy=multi-user.target
```

Il file `/etc/dast-agent.env` contiene la riga `GH_TOKEN=...` e va reso leggibile solo a quell'utente.

## ZAP installato sulla macchina (senza l'immagine Docker di ZAP)

Se sulla macchina ZAP è installato direttamente (per esempio ZAP 2.17.0 in `/opt/zaproxy` con il comando `zap`),
l'agente lo usa con l'opzione `--zap-cmd`:

```bash
python3 scripts/dast_external_agent.py --repo owner/nome \
  --require-check "01 SAST - CodeQL and High gate" --zap-cmd /usr/local/bin/zap
```

| Aspetto | Comportamento |
|---|---|
| Tipo di scansione | Solo passiva: spider (1 minuto) e regole passive. Nessun job di scansione attiva |
| Come viene avviato ZAP | `zap -cmd -silent -dir <cartella dati> -autorun <piano>`; il piano è salvato accanto ai report come `zap-plan.yaml` |
| Cartella dati di ZAP | Dedicata all'agente: `zap-home` nella cartella di lavoro, oppure quella indicata con `--zap-home`. Non usa la `~/.ZAP` di altri utenti o di altre attività |
| Applicazione | Con Docker: costruita dal commit e pubblicata solo su `127.0.0.1`, su una porta libera, con un file Compose aggiuntivo nella cartella dell'agente (il repository non viene modificato). Senza Docker: solo con `--target-url` |
| Controllo delle regole | Prima di ogni scansione l'agente verifica che gli add-on `pscanrules` e `commonlib` siano presenti e integri; in caso contrario scrive lo stato di errore |

Il controllo delle regole esiste perché, con gli add-on mancanti o scaricati in modo incompleto, ZAP termina senza
errori e produce un report senza alert.

Punti da verificare alla prima esecuzione reale:

- lo score dipende dalle regole caricate: lo ZAP installato può avere regole diverse dall'immagine Docker
  (per esempio le regole beta e alpha), quindi lo stesso commit può dare uno score diverso;
- la cartella dati dedicata usa gli add-on distribuiti con ZAP; per usare quelli già aggiornati di un altro
  utente si indica la sua cartella con `--zap-home`, a patto che nessun altro ZAP la stia usando.

## Simulazione senza Docker e senza ZAP

Per provare il meccanismo prima di avere la macchina con ZAP, l'agente può girare su qualunque computer con
`python3` e `git`:

```bash
export GH_TOKEN=<token>
python3 scripts/dast_external_agent.py --repo <owner>/<repo> --simulate --require-check "01 SAST - CodeQL and High gate"
```

| Parte | In simulazione |
|---|---|
| Polling delle pull request, attesa del SAST | Reali |
| Download del commit | Reale |
| Avvio dell'applicazione e scansione ZAP | Non eseguiti |
| Report ZAP | Sintetico, marcato `@simulated`: con CSP disattivata nel commit contiene la CSP mancante, altrimenti gli alert del report reale del 12 novembre |
| Score e policy | Reali, applicati al report sintetico |
| Stato scritto su GitHub | Reale, con la dicitura `[SIMULATO]` nella descrizione |

Uno stato simulato positivo sblocca davvero il merge se il ruleset lo richiede: la simulazione serve a mostrare il
flusso, non a proteggere un repository.

## Ordine rispetto al SAST

Senza `--require-check` l'agente scansiona ogni commit appena lo vede, anche se il SAST è fallito. Per rispettare la
sequenza "DAST solo dopo SAST superato" avviarlo con il nome esatto del job SAST:

```bash
python3 scripts/dast_external_agent.py --repo <owner>/<repo> --require-check "01 SAST - CodeQL and High gate"
```

Su un repository privato la lettura dei check richiede al token anche il permesso **Checks: Read-only**.

## Ruleset

Dopo la prima scansione, in **Settings → Rules → Rulesets → AppSec-Unified-Gate → Require status checks to pass →
Add checks** aggiungere `DAST ESTERNO (ZAP)`. Da quel momento ogni pull request verso `main` richiede anche l'esito
della macchina esterna. Farlo solo dopo che l'agente è in funzione: a macchina spenta nessuna pull request è
integrabile.

## Report

Uno stato di GitHub porta solo esito e descrizione, non file. Per ogni commit l'agente salva sulla macchina:

- `zap.json` e `zap.html`: report di ZAP;
- `dast-external-gate.json`: score, conteggi per severità, finding bloccanti.

## Sicurezza

- Le pull request che provengono da un fork vengono ignorate: il loro codice non è mai costruito né eseguito sulla
  macchina.
- Nella modalità predefinita la macchina costruisce ed esegue in container il codice del repository. Con
  `--target-url` esegue solo ZAP contro un'applicazione già rilasciata.
- L'agente non esegue sulla macchina script provenienti dal repository: score e policy sono nel suo codice.
- Uno stato rimasto in attesa dopo uno spegnimento viene ripreso al riavvio.

## Limiti

- ZAP Baseline è una scansione passiva: non esegue test attivi né autenticati.
- Con `--target-url` l'agente non può verificare che l'applicazione in esecuzione corrisponda al commit: quel legame
  va garantito dal processo di rilascio.
- I commit sono scansionati uno alla volta; con più pull request aperte gli esiti arrivano in sequenza.
