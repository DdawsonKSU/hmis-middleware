"""Combined notes + runnable examples

This single file keeps all code from the page in one place.
Each section is separated by a banner comment.

Requirements (install what you need):
  pip install lxml xmlsec flask stripe cryptography

Notes:
- Stripe requires STRIPE_SECRET_KEY in your environment.
- The EHR intake example writes to local files (ehr.db, secret.key).
- xmlsec decryption requires the right keys for the encrypted XML.
"""

# ============================================================
# 1) .NET EncryptedXml decryption options (reference notes)
# ============================================================
# Symmetric keys (AES, etc.)
#   - Create an EncryptedXml instance.
#   - Load the EncryptedData element.
#   - Call DecryptData using the same symmetric key used for encryption.
#   - Replace the encrypted element with the decrypted plaintext.
#
# Asymmetric keys (RSA)
#   - Create an EncryptedXml instance initialized with the XmlDocument.
#   - Map the key name to the RSA private key via AddKeyNameMapping.
#   - Call DecryptDocument.
#   - This automatically decrypts the session key and the content.
#
# X.509 certificates
#   - Load the certificate (with private key) from the local certificate store.
#   - Create an EncryptedXml instance with the document.
#   - Call DecryptDocument to automatically locate and use the corresponding private key.


# ============================================================
# 2) Python: decrypt encrypted XML (XML-Enc) with xmlsec
# ============================================================
from __future__ import annotations

from typing import Optional


def decrypt_xml(
    encrypted_xml_bytes: bytes,
    *,
    rsa_private_key_pem: Optional[str] = None,
    cert_pem: Optional[str] = None,
    symmetric_key_bytes: Optional[bytes] = None,
) -> bytes:
    """Decrypts an XML document encrypted with XML Encryption (xenc:EncryptedData).

    Use ONE of:
      - symmetric_key_bytes (AES key used to encrypt)
      - rsa_private_key_pem (RSA private key to unwrap session key)
      - cert_pem + rsa_private_key_pem (cert helps identify key; private key does decryption)

    Returns the decrypted XML bytes.
    """

    from lxml import etree
    import xmlsec

    parser = etree.XMLParser(remove_blank_text=False)
    doc = etree.fromstring(encrypted_xml_bytes, parser=parser)
    tree = doc.getroottree()

    enc_data = xmlsec.tree.find_node(tree.getroot(), xmlsec.constants.NodeEncryptedData)
    if enc_data is None:
        raise ValueError("No xenc:EncryptedData element found.")

    ctx = xmlsec.EncryptionContext()

    if symmetric_key_bytes is not None:
        key = xmlsec.Key.from_binary_data(xmlsec.constants.KeyDataAes, symmetric_key_bytes)
        ctx.key = key
    else:
        if not rsa_private_key_pem:
            raise ValueError("Provide rsa_private_key_pem if not using symmetric_key_bytes.")

        key = xmlsec.Key.from_file(rsa_private_key_pem, xmlsec.constants.KeyDataFormatPem)
        if cert_pem:
            key.load_cert_from_file(cert_pem, xmlsec.constants.KeyDataFormatPem)
        ctx.key = key

    ctx.decrypt(enc_data)
    return etree.tostring(tree, xml_declaration=True, encoding="UTF-8", pretty_print=True)


# ============================================================
# 3) Simplest credit card “processing” app (beginner): Stripe Checkout + Flask
# ============================================================
# One-time install:
#   pip install flask stripe
# Set your Stripe key (test mode):
#   export STRIPE_SECRET_KEY="sk_test_..."


def run_stripe_checkout_app() -> None:
    import os

    from flask import Flask, jsonify, request
    import stripe

    # Line 5: This app creates a Stripe Checkout payment link

    app = Flask(__name__)
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]

    @app.get("/")
    def home():
        # Line 10: A tiny home page with a Pay button
        return """
        <h1>My First Payment App</h1>
        <button onclick=\"pay()\">Pay $5</button>
        <script>
          async function pay(){
            const res = await fetch('/create-checkout-session', {method:'POST'});
            const data = await res.json();
            window.location = data.checkout_url;
          }
        </script>
        """

    @app.post("/create-checkout-session")
    def create_checkout_session():
        # Line 20: Stripe hosts the card form; you never see card numbers
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "My First Product"},
                        "unit_amount": 500,
                    },
                    "quantity": 1,
                }
            ],
            success_url=request.host_url.rstrip("/") + "/success",
            cancel_url=request.host_url.rstrip("/") + "/cancel",
        )
        # Line 30: Return the URL your browser should go to
        return jsonify({"checkout_url": session.url})

    @app.get("/success")
    def success():
        # Line 35: Stripe sends people here after a successful test payment
        return "Payment successful! (Test mode)"

    @app.get("/cancel")
    def cancel():
        # Line 40: Stripe sends people here if they cancel
        return "Payment canceled."

    # Line 45: Start the local server
    app.run(debug=True, port=5000)


# Stripe test card details (Stripe test mode):
# - Number: 4242 4242 4242 4242
# - Exp: any future date
# - CVC: any


# ============================================================
# 4) Client intake inside an EHR (prototype) + “hide” client info (encrypt at rest)
# ============================================================
# Install:
#   pip install flask cryptography


def run_ehr_intake_app() -> None:
    import os
    import sqlite3

    from flask import Flask, request, redirect
    from cryptography.fernet import Fernet

    # Line 5: Minimal EHR-style intake form with encryption-at-rest

    app = Flask(__name__)
    DB_PATH = "ehr.db"
    KEY_PATH = "secret.key"

    def load_or_create_key():
        # Line 10: This key encrypts/decrypts PHI; protect it like a password
        if os.path.exists(KEY_PATH):
            return open(KEY_PATH, "rb").read()
        key = Fernet.generate_key()
        open(KEY_PATH, "wb").write(key)
        return key
        # Line 15: In real systems, keys should be in a secret manager, not a file

    FERNET = Fernet(load_or_create_key())

    def init_db():
        con = sqlite3.connect(DB_PATH)
        # Line 20: Store only encrypted fields + minimal non-sensitive metadata
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT (datetime('now')),
                name_enc BLOB NOT NULL,
                dob_enc BLOB NOT NULL,
                phone_enc BLOB NOT NULL,
                notes_enc BLOB NOT NULL
            )
            """
        )
        con.commit()
        con.close()
        # Line 30: Database is ready

    def enc(text: str) -> bytes:
        return FERNET.encrypt(text.encode("utf-8"))

    def dec(token: bytes) -> str:
        # Line 35: Decrypt only when needed (this is what “unhides” the data)
        return FERNET.decrypt(token).decode("utf-8")

    @app.get("/")
    def intake_form():
        # Line 40: A basic client intake form
        return """
        <h1>Client Intake (Prototype)</h1>
        <form method="post" action="/submit">
          <label>Full name</label><br>
          <input name="name" required><br><br>

          <label>Date of birth</label><br>
          <input name="dob" placeholder="YYYY-MM-DD" required><br><br>

          <label>Phone</label><br>
          <input name="phone" required><br><br>

          <label>Notes</label><br>
          <textarea name="notes" rows="4" cols="40"></textarea><br><br>

          <button type="submit">Submit intake</button>
        </form>
        <p><a href="/admin/list">Admin: list clients (decrypts)</a></p>
        """

    @app.post("/submit")
    def submit():
        # Line 60: Collect intake data from the form
        name = request.form.get("name", "")
        dob = request.form.get("dob", "")
        phone = request.form.get("phone", "")
        notes = request.form.get("notes", "")

        con = sqlite3.connect(DB_PATH)
        con.execute(
            "INSERT INTO clients (name_enc, dob_enc, phone_enc, notes_enc) VALUES (?, ?, ?, ?)",
            (enc(name), enc(dob), enc(phone), enc(notes)),
        )
        con.commit()
        con.close()
        # Line 75: Data saved encrypted in SQLite
        return redirect("/thanks")

    @app.get("/thanks")
    def thanks():
        # Line 80: Confirmation screen
        return "Thanks — intake submitted."

    @app.get("/admin/list")
    def admin_list():
        # Line 85: This page decrypts and displays PHI (protect with login in real life)
        con = sqlite3.connect(DB_PATH)
        rows = con.execute(
            "SELECT id, created_at, name_enc, dob_enc, phone_enc, notes_enc FROM clients ORDER BY id DESC"
        ).fetchall()
        con.close()

        html = "<h1>Admin Client List (Decrypted)</h1>"
        for (cid, created_at, name_enc, dob_enc, phone_enc, notes_enc) in rows:
            html += f"<h3>Client #{cid} — {created_at}</h3>"
            html += f"<div><b>Name:</b> {dec(name_enc)}</div>"
            html += f"<div><b>DOB:</b> {dec(dob_enc)}</div>"
            html += f"<div><b>Phone:</b> {dec(phone_enc)}</div>"
            html += f"<div><b>Notes:</b> {dec(notes_enc)}</div>"
            html += "<hr>"
        # Line 100: Returning decrypted view (again: should be access-controlled)
        return html

    init_db()
    # Line 105: Run local server
    app.run(debug=True, port=5000)


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    # Choose ONE to run:
    # run_stripe_checkout_app()
    # run_ehr_intake_app()
    pass