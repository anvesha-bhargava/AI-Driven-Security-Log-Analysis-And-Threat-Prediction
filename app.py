from flask import Flask, render_template, request, send_file
import pandas as pd
from pathlib import Path
from analyzer import analyze_logs

app = Flask(__name__)
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None
    if request.method == "POST":
        uploaded = request.files.get("logfile")
        if not uploaded or not uploaded.filename:
            error = "Please choose a CSV log file."
        elif not uploaded.filename.lower().endswith(".csv"):
            error = "Upload a .csv file."
        else:
            path = UPLOAD_DIR / "latest_upload.csv"
            uploaded.save(path)
            try:
                df = pd.read_csv(path)
                results = analyze_logs(df)
            except Exception as exc:
                error = f"Could not analyze this file: {exc}"
    return render_template("index.html", results=results, error=error)

if __name__ == "__main__":
    app.run(debug=True)
