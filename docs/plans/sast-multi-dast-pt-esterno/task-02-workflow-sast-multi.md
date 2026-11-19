# Task 02 — Workflow SAST multi-strumento

**Obiettivo:** un workflow separato esegue i quattro strumenti e il gate aggregato.
**Requisiti:** RF1, RF7, CA11; design §7.1.
**Dipendenze:** task-01 (opzioni del gate).
**Complessità:** Media
**Rischio:** sicurezza

## Interfacce

- Consuma: `python3 scripts/sast_multi_gate.py --sarif-dir sarif --expect codeql,semgrep,gitleaks,trivy
  --job-result "<strumento>=<needs.<job>.result>"` per ogni strumento, `--summary reports/sast-multi-gate.json
  --markdown reports/sast-multi-gate.md` (task-01).
- Produce: check `S1 SAST - CodeQL`, `S2 SAST - Semgrep`, `S3 SECRETS - Gitleaks`, `S4 SCA-IAC - Trivy`,
  `SAST AGGREGATO`; artifact `sast-multi-codeql`, `sast-multi-semgrep`, `sast-multi-gitleaks`, `sast-multi-trivy`,
  `sast-aggregato-evidence` (nome diverso dal modello `sast-multi-*` usato per scaricare i report).

## File

- Crea: `.github/workflows/sast-multi.yml`.
- Crea: `tests/test_sast_multi_workflow.py` — controlli sul testo del workflow, senza librerie YAML.

## Modifiche

1. Avvio su `pull_request` verso `main` e `workflow_dispatch`; `concurrency` con annullamento del run precedente.
2. Permessi minimi a livello di workflow (`contents: read`); `security-events: write` solo nei job che caricano SARIF.
3. Action fissate: `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` (v4.4.0),
   `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` (v4.6.2),
   `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093` (v4.3.0),
   `github/codeql-action/*@33d7b85da1a04171e211befe2c739303b9a4c066` (v4.39.3).
4. Immagini a versione fissata: `semgrep/semgrep:1.186.0`, `ghcr.io/gitleaks/gitleaks:v8.30.1`, `aquasec/trivy:0.76.2`.
5. Gitleaks e Trivy con `--user "$(id -u):$(id -g)"` e codice di uscita 0 anche con finding; Gitleaks con `--redact`.
6. Caricamento in Code Scanning con `continue-on-error: true` e categoria per strumento (non per CodeQL).
7. Job del gate con `if: always()`; riepilogo Markdown aggiunto a `$GITHUB_STEP_SUMMARY`; artifact anche se fallisce.
8. Test: CA11; presenza dei cinque nomi di job; nessuna espressione `${{ github.event.* }}` dentro un blocco `run`.

## Verifica

- Esegui: `python3 -m unittest tests.test_sast_multi_workflow -v`; analisi sintattica YAML del file.
- Esito atteso: test verdi; YAML valido. L'esecuzione su GitHub è in task-06.
