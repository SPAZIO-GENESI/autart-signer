from flask import Flask, request, Response, jsonify
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers import PdfSigner
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext
import io
import os
import base64
import tempfile

app = Flask(__name__)

# Versione del signer: sorgente di verità unica (vedi CLAUDE.md › Versioning). Esposta da GET /.
APP_VERSION = "1.3.0"

P12_PASSWORD = os.environ.get("P12_PASSWORD")
SIGN_SECRET  = os.environ.get("SIGN_SECRET")

# TSA RFC 3161 con radice in AATL: la marca temporale risulta attendibile in Adobe
# Reader anche se il certificato firmatario resta self-signed. Vuota = nessun timestamp.
TSA_URL = os.environ.get("TSA_URL", "http://timestamp.digicert.com")

# Credenziali per una TSA che le richieda (le qualificate a lotti quasi sempre lo
# fanno). HTTPTimeStamper accetta già `auth` come tupla basic: qui la si costruisce
# solo se entrambe le variabili sono presenti, così il comportamento di default
# resta identico a prima.
TSA_USER = os.environ.get("TSA_USER")
TSA_PASSWORD = os.environ.get("TSA_PASSWORD")
TSA_AUTH = (TSA_USER, TSA_PASSWORD) if TSA_USER and TSA_PASSWORD else None

# Livello dichiarato della marca temporale. NON è dedotto: è una dichiarazione di
# configurazione, che va messa a "true" SOLO dopo aver verificato sul token reale
# (img-auth-hub/tools/inspect_sig.py) che l'emittente sia iscritto alla EU Trusted
# List e che il token porti i QCStatements ETSI. Al 10/09/2026 la TSA in uso
# (timestamp.digicert.com) è AATL ma NON qualificata eIDAS: resta "false".
TSA_QUALIFIED = os.environ.get("TSA_QUALIFIED", "").strip().lower() in ("1", "true", "yes")

def _tsa_host(url):
    """Host della TSA, per dichiararlo senza esporre eventuali credenziali nell'URL."""
    if not url:
        return None
    without_scheme = url.split("://", 1)[-1]
    return without_scheme.split("/", 1)[0].split("@")[-1]

# Supporta sia P12_BASE64 (priorità, cert inline nell'env) sia P12_PATH (file su disco)
_p12_base64 = os.environ.get("P12_BASE64")
if _p12_base64:
    _tmp = tempfile.NamedTemporaryFile(suffix=".p12", delete=False)
    _tmp.write(base64.b64decode(_p12_base64))
    _tmp.close()
    P12_PATH = _tmp.name
else:
    P12_PATH = os.environ.get("P12_PATH", "certs/signer.p12")

@app.route("/", methods=["GET"])
def health():
    # Formato invariato (testo, "Signer OK vX.Y.Z"): è ciò che /api/status di
    # imgauth e la scheda versioni si aspettano. Lo stato della marca temporale
    # vive su /status, per non cambiare questo contratto.
    return f"Signer OK v{APP_VERSION}"


@app.route("/status", methods=["GET"])
def status():
    """Cosa questo signer è configurato per fare, prima di riceverne la prova.

    Serve a imgauth: il certificato PDF viene composto PRIMA della firma, quindi
    per stampare il livello di marca temporale bisogna saperlo in anticipo. Dopo
    la firma l'esito reale torna negli header di /sign, e chi ha stampato una
    riga diversa la corregge. Nessun segreto qui: solo host e livello dichiarato.
    """
    return jsonify({
        "version": APP_VERSION,
        "timestamp_configured": bool(TSA_URL),
        "timestamp_host": _tsa_host(TSA_URL),
        "timestamp_level": ("qualified" if TSA_QUALIFIED else "recognized") if TSA_URL else "none",
        "timestamp_auth": bool(TSA_AUTH),
    })

@app.route("/sign", methods=["POST"])
def sign():
    if SIGN_SECRET and request.headers.get("X-Sign-Secret") != SIGN_SECRET:
        return Response("Unauthorized", status=401)

    pdf = request.data
    if not pdf:
        return Response("No PDF provided", status=400)

    try:
        signer = signers.SimpleSigner.load_pkcs12(
            P12_PATH,
            passphrase=P12_PASSWORD.encode('utf-8') if P12_PASSWORD else None
        )

        def do_sign(timestamper, with_ltv):
            if with_ltv:
                # PAdES B-LT: embedda catena TSA + info di revoca (OCSP/CRL), così la
                # marca temporale resta verificabile nel tempo anche offline. Il cert
                # firmatario è self-signed: va aggiunto ai trust root per consentire
                # la pre-validazione che l'embedding richiede; soft-fail perché un
                # self-signed non ha endpoint di revoca.
                meta = signers.PdfSignatureMetadata(
                    field_name="Signature1",
                    subfilter=SigSeedSubFilter.PADES,
                    # il cert di produzione ha solo digital_signature (niente
                    # non_repudiation, default di pyhanko per PAdES)
                    signer_key_usage={"digital_signature"},
                    embed_validation_info=True,
                    validation_context=ValidationContext(
                        extra_trust_roots=[signer.signing_cert],
                        allow_fetching=True,
                        revocation_mode="soft-fail",
                    ),
                )
            else:
                meta = signers.PdfSignatureMetadata(field_name="Signature1")
            pdf_signer = PdfSigner(
                signature_meta=meta,
                signer=signer,
                new_field_spec=SigFieldSpec("Signature1"),
                timestamper=timestamper
            )
            # wrappa i bytes in un IncrementalPdfFileWriter (sign_pdf vuole un writer)
            output = io.BytesIO()
            pdf_signer.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf)), output=output)
            return output.getvalue()

        # Esito effettivo della marca temporale, dichiarato al chiamante negli
        # header. Il fail-open resta la politica di emissione (meglio un
        # certificato senza marca che nessun certificato), ma smette di essere
        # muto: chi stampa il certificato deve poter dire il vero su cosa
        # contiene. Vedi P55 §M7.
        timestamp_applied = False

        if TSA_URL:
            try:
                signed_pdf = do_sign(HTTPTimeStamper(TSA_URL, auth=TSA_AUTH), with_ltv=True)
                timestamp_applied = True
            except Exception:
                # fail-open: un disservizio di TSA/OCSP/CRL non deve bloccare l'emissione
                import traceback
                traceback.print_exc()
                signed_pdf = do_sign(None, with_ltv=False)
        else:
            signed_pdf = do_sign(None, with_ltv=False)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response(f"Signing error: {str(e)}", status=500)

    if timestamp_applied:
        level = "qualified" if TSA_QUALIFIED else "recognized"
    else:
        level = "none"

    return Response(signed_pdf, mimetype="application/pdf", headers={
        "X-Sign-Timestamp": "applied" if timestamp_applied else "absent",
        "X-Sign-Timestamp-Level": level,
        "X-Sign-Timestamp-Host": _tsa_host(TSA_URL) or "",
        "X-Sign-Version": APP_VERSION,
    })
