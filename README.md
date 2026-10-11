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

## Updated detection features

- Time-window brute-force detection: counts the peak number of timestamped failed logins from a source IP within a configurable number of minutes.
- Windows Security event ID support: structured `event_id` / `eventid` fields recognize 4625 (failed logon) and 4624 (successful logon).
- SSH authentication parsing: common `sshd` failed-password and accepted-password messages are normalized.
- Configurable dashboard settings: failed-login threshold, time window, and failures-before-success threshold.
- Automated unit tests cover expected detections and a benign event that should not trigger an alert.

Run the tests locally with:

```bash
python -m unittest -v
```

### Example Windows CSV fields

For Windows Event Viewer exports, a CSV containing fields such as `TimeCreated`, `Computer`, `IpAddress`, `TargetUserName`, `EventID`, and `Message` can be adapted to the analyzer's canonical fields. The analyzer recognizes common timestamp, host, source-IP, username, and event-ID aliases; verify the column mapping against your actual export before relying on results.

### Detection limitations

- Time-window correlation requires parseable timestamps. Events without timestamps are excluded from brute-force window counting.
- Windows Event IDs are only as reliable as the fields provided in the CSV export. Native EVTX/XML exports may need conversion to CSV first.
- Keyword detections are starter rules, not proof of compromise. Tune and validate them against your environment.
- Community Sigma/Elastic/Splunk rules are not automatically executable by this project. Review rule logic, required telemetry, field mappings, and license terms before adapting any rule.
