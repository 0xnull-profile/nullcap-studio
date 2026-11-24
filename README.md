# NullCap Studio 4.0.1

Analizzatore offline di catture di rete e workspace investigativo. Permette di esaminare comunicazioni osservate in file PCAP e PCAPNG, consultare pacchetti, conversazioni e artefatti e organizzare le evidenze in un'indagine.

## Access / Accesso

[**Launch Web App**](https://0xnull-profile.github.io/nullcap-studio/) — GitHub Pages (after deployment).

**Windows x64 Portable — not yet available / non ancora disponibile.** Planned direct download (activate only after desktop compliance clearance and publication):

`https://github.com/0xnull-profile/nullcap-studio/releases/download/v4.0.1/NullCap-Studio-4.0.1-win-x64.exe`

The Windows executable is unsigned; Windows may display a warning. The desktop release is not authorized yet. / L'eseguibile Windows non e firmato; la distribuzione desktop non e ancora autorizzata.

[Release page](https://github.com/0xnull-profile/nullcap-studio/releases) · [License](LICENSE) · [Verification](VERIFY.md)

## Utilizzo

1. Avviare la versione web tramite GitHub Pages oppure scaricare ed estrarre il pacchetto ZIP standalone dalla release ufficiale quando disponibile, conservando HTML e documenti di licenza insieme, oppure generarlo dai sorgenti come indicato sotto.
2. Verificare l'hash SHA-256 con `SHA256SUMS.txt` del pacchetto.
3. Aprire il file HTML in un browser moderno e importare una cattura PCAP/PCAPNG o un archivio di indagine compatibile.
4. Esportare le evidenze o salvare l'indagine quando necessario.

Non è richiesto un server o una connessione Internet per l'analisi. All'avvio non viene caricata automaticamente alcuna cattura. La versione web richiede una connessione per il caricamento iniziale; per lavorare senza connessione usare il pacchetto HTML locale. La versione desktop non è ancora distribuita. GitHub e il browser possono trattare metadati di accesso; le catture sono elaborate localmente secondo il progetto applicativo.

## Funzionalità

- Homepage con statistiche, protocolli e indicatori di contesto.
- Esplora rete: topologia, timeline, ricerca e filtri.
- Pacchetti, inspector, conversazioni e ricostruzione TCP.
- Bottino: consultazione degli artefatti osservati.
- Forensic Workspace: gestione multi-cattura, annotazioni, dossier e importazione/esportazione delle indagini.

## Ricostruire e verificare

Con Python 3.10 o successivo, dalla root del repository:

```sh
python scripts/build_standalone.py
python scripts/verify_release.py
```

Il file prodotto è `dist/NullCap-Studio-4.0.1.html`. Il verificatore confronta il suo SHA-256 con quello atteso per questa versione. Per controllare un file scaricato:

```sh
python scripts/verify_release.py /percorso/NullCap-Studio-4.0.1.html
```

Su Windows è possibile usare anche `Get-FileHash -Algorithm SHA256 .\NullCap-Studio-4.0.1.html` in PowerShell.

L'hash verifica l'identità dei byte, non garantisce da solo l'autenticità del distributore o la sicurezza del software. Confrontare sempre con il valore ottenuto da una fonte ufficiale attendibile. Il codice HTML distribuito è leggibile e ricostruibile dai sorgenti inclusi.

## Limiti e uso responsabile

Analizzare soltanto acquisizioni che si è autorizzati a trattare. NullCap non è un IDS e gli indicatori non costituiscono da soli prova di un attacco. Limiti documentati: 75.000 pacchetti, 160 MB per file e 75 host contemporanei nel grafo. La ricostruzione TCP non decritta traffico protetto, non esegue riassemblaggio IP frammentato e non verifica checksum. Conservare le catture originali e verificare i risultati rilevanti con strumenti indipendenti.

Le catture e gli archivi possono contenere informazioni sensibili. Consultare [PRIVACY.md](PRIVACY.md) e [SECURITY.md](SECURITY.md). Attribuzioni: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## GitHub Pages

Settings → Pages → Deploy from a branch → `main` → `/docs`. The deployed `docs/index.html` is byte-identical to the standalone release. Verify with `python scripts/verify_release.py docs/index.html`. Keep the accompanying notices in `docs/` synchronized with the root. Do not publish the private repository or desktop binary until cleared.

## Verification in CI
The public workflow builds the standalone and verifies its SHA-256 without publishing a release.

## License / Licenza

Copyright © 2026 0xnull-profile. Proprietary source-available freeware: free personal, professional and business use; external redistribution and modification of original code require permission, subject to legal and third-party exceptions. Non open source. Uso personale, professionale e aziendale gratuito; modifiche e ridistribuzione esterna riservate salvo eccezioni. Consultare [LICENSE](LICENSE), [COPYRIGHT.md](COPYRIGHT.md), [TRADEMARKS.md](TRADEMARKS.md) e [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
