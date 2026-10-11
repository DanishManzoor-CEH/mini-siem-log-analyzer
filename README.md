# Mini SIEM Log Analyzer

A beginner-friendly cybersecurity portfolio project that demonstrates log parsing, explainable rule-based detections, and optional AI-assisted SOC alert investigation.

## Features

- Upload CSV logs or paste plain-text log lines
- Normalize common fields such as timestamp, host, source IP, username, event type, status, and message
- Detect repeated failed logins / possible brute-force activity
- Flag a successful login after repeated failures from the same source IP
- Flag potentially suspicious command patterns
- Flag privileged activity and malware-related log indicators
- Dashboard metrics, severity filters, event summary, and source-IP counts
- Optional Groq LLM summary of rule-generated alerts
- Download alerts as CSV and an investigation report as PDF
- Runs on Streamlit Cloud

## Technology

Python, Streamlit, Pandas, Groq API, ReportLab, GitHub, Streamlit Community Cloud.

## Run locally

1. Install Python 3.11 or 3.12.
2. Download or clone this repository.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Optional: set your Groq API key as an environment variable named `GROQ_API_KEY`. If not set, rule-based analysis still works.
5. Start the app:

   ```bash
   streamlit run app.py
   ```

## Deploy to Streamlit Community Cloud

1. Push these files to the root of a GitHub repository.
2. Open Streamlit Community Cloud and create a new app.
3. Select your repository, branch, and `app.py` as the main file.
4. In the app settings, add a secret:

   ```toml
   GROQ_API_KEY = "your_actual_groq_api_key"
   ```

5. Deploy the app. The API key should never be committed to GitHub.

## Expected CSV fields

Recommended headers:

`timestamp,host,source_ip,username,event_type,status,message`

Common alternatives such as `src_ip`, `user`, `event_id`, `result`, `details`, and `log` are also recognized.

Example:

```csv
timestamp,host,source_ip,username,event_type,status,message
2026-10-11 09:01:03,server-a,203.0.113.25,admin,login,failed,Failed password for admin
2026-10-11 09:01:08,server-a,203.0.113.25,admin,login,failed,Failed password for admin
```

## Safety and limitations

- This is an educational demo, not an enterprise SIEM or an automated incident-response system.
- Detection rules are intentionally transparent and may produce false positives or miss activity that is not represented in the logs.
- AI output is advisory. Validate all findings against original telemetry and your organization's incident response process.
- Use fictional or sanitized logs. Do not upload passwords, tokens, personal data, or confidential production logs.
- The app does not perform live IP reputation checks, network scanning, or endpoint actions.
