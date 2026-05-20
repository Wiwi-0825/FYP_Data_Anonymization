import os
import pandas as pd
import PyPDF2

from flask import Flask, render_template, request, send_file, redirect, session
from werkzeug.utils import secure_filename
from anonymizer import anonymize_text

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.secret_key = "secretkey"

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output_files"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/")
def upload_page():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    if not file or file.filename == "":
        return "No file uploaded"

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    session["filename"] = filename

    return redirect("/select")


@app.route("/select")
def select():
    return render_template("options.html")


@app.route("/process", methods=["POST"])
def process():
    if "consent" not in request.form:
        return "Consent is required before anonymization."

    filename = session.get("filename")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    ext = filename.rsplit(".", 1)[1].lower()

    options = {
        "remove_nric": "nric" in request.form,
        "redact_password": "password" in request.form,
        "mask_emails": "email" in request.form,
        "mask_phones": "phone" in request.form,
        "truncate_ips": "ip" in request.form,
        "pseudonymize": "name" in request.form,
        "hash_ids": "hash" in request.form,
        "generalize_ages": "age" in request.form,
        "remove_secret": "secret" in request.form
    }

    selected_techniques = []

    if "email" in request.form:
        selected_techniques.append("Email Masking")

    if "phone" in request.form:
        selected_techniques.append("Phone Masking")

    if "ip" in request.form:
        selected_techniques.append("IP Truncation")

    if "name" in request.form:
        selected_techniques.append("Name Pseudonymisation")

    if "nric" in request.form:
        selected_techniques.append("NRIC Removal")

    if "password" in request.form:
        selected_techniques.append("Password Redaction")

    if "hash" in request.form:
        selected_techniques.append("Hashing")

    if "age" in request.form:
        selected_techniques.append("Version Generalisation")

    if "secret" in request.form:
        selected_techniques.append("Record Suppression")

    original = ""
    anonymized = ""

    output_filename = "anonymized_" + filename
    output_path = os.path.join(OUTPUT_FOLDER, output_filename)

    if ext == "txt":
        with open(filepath, "r", encoding="utf-8") as f:
            original = f.read()

        anonymized = anonymize_text(original, **options)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(anonymized)

    elif ext == "csv":
        df = pd.read_csv(filepath)
        original = df.to_string()

        df_anon = df.map(lambda x: anonymize_text(str(x), **options))
        anonymized = df_anon.to_string()

        df_anon.to_csv(output_path, index=False)

    elif ext == "xlsx":
        df = pd.read_excel(filepath)
        original = df.to_string()

        df_anon = df.map(lambda x: anonymize_text(str(x), **options))
        anonymized = df_anon.to_string()

        df_anon.to_excel(output_path, index=False)

    elif ext == "pdf":
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)

            for page in reader.pages:
                text = page.extract_text()
                if text:
                    original += text + "\n"

        anonymized = anonymize_text(original, **options)

        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4
        y = height - 50

        for line in anonymized.split("\n"):
            if y < 50:
                c.showPage()
                y = height - 50

            c.drawString(50, y, line[:100])
            y -= 18

        c.save()

    else:
        return "Unsupported file type. Please upload .txt, .csv, .xlsx, or .pdf"

    session["original"] = original
    session["anonymized"] = anonymized
    session["output"] = output_filename
    session["techniques"] = selected_techniques

    session["techniques"] = selected_techniques

    return redirect("/preview")


@app.route("/preview")
def preview():
    return render_template(
    "preview.html",
    original=session.get("original", ""),
    anonymized=session.get("anonymized", ""),
    techniques=session.get("techniques", [])
)
   

@app.route("/getfile")
def getfile():
    file = session.get("output")
    path = os.path.join(OUTPUT_FOLDER, file)

    return send_file(path, as_attachment=True)

@app.route("/reset")
def reset():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)