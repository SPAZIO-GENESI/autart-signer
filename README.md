# authart — firma crittografica dei certificati PDF

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/SPAZIO-GENESI/autart-signer/badge)](https://scorecard.dev/viewer/?uri=github.com/SPAZIO-GENESI/autart-signer)

Servizio di firma del sistema di attestazione opere digitali di Spazio Genesi ETS.
Riceve un PDF e lo restituisce firmato **PAdES B-LT**: firma CMS detached con
certificato PKCS#12, **marca temporale RFC 3161** da TSA con radice in Adobe AATL
(default DigiCert) e informazioni di validazione embedded (LTV: catena TSA + OCSP
nel DSS), così la verifica resta possibile nel tempo anche offline.

Fa parte di una pipeline a tre componenti:
[imgauthweb](https://github.com/SPAZIO-GENESI/imgauthweb) (interfaccia, MIT) →
[imgauth](https://github.com/SPAZIO-GENESI/imgauth) (motore di attestazione, AGPL) →
**authart** (firma).

## Endpoint

| Metodo | Path | Input | Output |
|---|---|---|---|
| `GET` | `/` | — | `Signer OK vX.Y.Z` (health + versione) |
| `POST` | `/sign` | bytes del PDF | PDF firmato PAdES B-LT |

`POST /sign` è autenticato con l'header `X-Sign-Secret` (segreto condiviso col chiamante).

## Configurazione (variabili d'ambiente)

| Variabile | Obbligatoria | Significato |
|---|---|---|
| `P12_BASE64` | sì (o `P12_PATH`) | certificato PKCS#12 codificato base64; decodificato in file temporaneo all'avvio |
| `P12_PASSWORD` | se il p12 è protetto | password del PKCS#12 |
| `SIGN_SECRET` | consigliata | valore atteso nell'header `X-Sign-Secret` |
| `TSA_URL` | no | TSA RFC 3161 (default `http://timestamp.digicert.com`); vuota = nessuna marca |

Fail-open: se TSA/OCSP sono irraggiungibili il PDF viene firmato senza marca
temporale — il servizio non blocca mai l'emissione.

Nessun segreto vive nel repository: certificato e password arrivano solo
dall'ambiente (in produzione: Azure App Settings).

## Esecuzione

```bash
pip install -r requirements.txt
gunicorn --bind=0.0.0.0 --timeout 600 --workers=4 app:app
```

Stack: Python, Flask, [pyhanko](https://github.com/MatthiasValvekens/pyHanko), Gunicorn.
Deploy di riferimento: Azure Web App via GitHub Actions (`.github/workflows/main_sgart.yml`).

## Licenza

Copyright (C) 2026 Spazio Genesi ETS — **GNU AGPL-3.0** (vedi [LICENSE](LICENSE)).

La licenza copre il codice, non il servizio: il certificato di firma e i segreti
sono esclusivamente server-side. Un'istanza indipendente firma con il *proprio*
certificato, non con quello di Spazio Genesi ETS.

> Nota: questo repository riparte da una storia git pulita (giugno 2026); la
> cronologia precedente conteneva materiale di sviluppo non destinato alla
> pubblicazione ed è stata sostituita in blocco.
