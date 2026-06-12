from flask import Flask, request, Response
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
APP_VERSION = "1.2.0"

P12_PASSWORD = os.environ.get("P12_PASSWORD")
SIGN_SECRET  = os.environ.get("SIGN_SECRET")

# TSA RFC 3161 con radice in AATL: la marca temporale risulta attendibile in Adobe
# Reader anche se il certificato firmatario resta self-signed. Vuota = nessun timestamp.
TSA_URL = os.environ.get("TSA_URL", "http://timestamp.digicert.com")

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
    return f"Signer OK v{APP_VERSION}"

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

        if TSA_URL:
            try:
                signed_pdf = do_sign(HTTPTimeStamper(TSA_URL), with_ltv=True)
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

    return Response(signed_pdf, mimetype="application/pdf")
