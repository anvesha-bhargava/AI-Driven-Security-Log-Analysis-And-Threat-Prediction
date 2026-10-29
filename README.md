# AI-Driven Security Log Analysis and Threat Prediction

Academic prototype using Python, Flask, pandas and scikit-learn.

## What it currently demonstrates
- Upload a CSV file containing security events.
- Validate required columns and parse timestamps.
- Aggregate events by source IP.
- Count failed/successful logins and distinct usernames.
- Apply simple rule-based alerts and a demonstration Random Forest classifier.
- Display a risk indicator and summary in a browser.

## Important limitation
The included ML model is trained on small synthetic demonstration examples. Its output is **not a validated threat prediction**, and its results must not be represented as real-world accuracy. For a stronger project, train/evaluate on a documented public dataset, split data into train/test sets, and report precision, recall, F1-score and confusion matrix. The current risk score is a heuristic, not a calibrated probability.

## Setup (Windows)
1. Install Python 3.10+.
2. Extract this folder.
3. Open a terminal in this folder and run:

   `py -m venv .venv`

   `.venv\\Scripts\\activate`

   `pip install -r requirements.txt`

4. Start the app:

   `python app.py`

5. Open `http://127.0.0.1:5000` in your browser.
6. Upload `sample_logs.csv` to test.

## Required CSV columns
`timestamp,event_type,source_ip,username,status`

- timestamp: date/time, e.g. `2026-10-29 10:01:12`
- event_type: e.g. `LOGIN`, `FILE_ACCESS`
- source_ip: source IP string
- username: account/user involved
- status: use `FAILED` or `SUCCESS` for login outcome

## Safe use
Only analyze logs you own or have permission to use. Do not upload confidential logs to a public service. The Flask debug server is for local development only, not deployment.
