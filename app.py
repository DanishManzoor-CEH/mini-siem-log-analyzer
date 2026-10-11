import json
import os
from datetime import datetime
from html import escape
from io import BytesIO

import pandas as pd
import streamlit as st
from groq import Groq

from analyzer import analyze_logs, load_logs, summarize_events


st.set_page_config(
    page_title="Mini SIEM Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp { background: #0b0f14; color: #f3f4f6; }
    .main .block-container { max-width: 1250px; padding-top: 1.5rem; padding-bottom: 3rem; }
    h1, h2, h3, h4, h5, h6 { color: #f9fafb !important; }
    p, li, label { color: #d1d5db; }
    .hero { background: linear-gradient(135deg,#111827,#17243a); border: 1px solid #263449;
            border-radius: 16px; padding: 24px 28px; margin-bottom: 20px; }
    .hero-title { font-size: 30px; font-weight: 800; color: #fff !important; margin: 0; }
    .hero-subtitle { color: #aeb9c9 !important; font-size: 14px; margin-top: 7px; }
    .metric-card { background:#111827; border:1px solid #263449; border-radius:12px;
                   padding:17px; min-height:100px; }
    .metric-label { color:#9ca3af !important; font-size:13px; margin-bottom:7px; }
    .metric-value { color:#fff !important; font-size:27px; font-weight:800; }
    .alert-card { background:#fff !important; color:#1f2937 !important; border-left:5px solid #ef4444;
                  border-radius:9px; padding:14px 17px; margin:8px 0; }
    .alert-card * { color:#1f2937 !important; }
    .alert-card-title { font-weight:800; font-size:15px; }
    .muted { color:#9ca3af !important; font-size:12px; }
    .footer { border-top:1px solid #263449; color:#6b7280; text-align:center; padding-top:15px; margin-top:32px; font-size:12px; }
    div[data-testid="stDownloadButton"] button { width:100%; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="hero-title">🛡️ Mini SIEM Log Analyzer</div>
      <div class="hero-subtitle">Rule-based security detections with optional AI-assisted alert investigation</div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.expander("How to use this tool", expanded=False):
    st.markdown(
        """
        1. Upload a CSV log file or paste sample security logs.
        2. Select **Analyze Logs** to run deterministic detection rules.
        3. Review alert severity, evidence, and affected source IPs.
        4. Optionally ask the AI to summarize the detected alerts.
        5. Download a CSV of alerts or a PDF investigation report.

        **Important:** This is a portfolio/demo analyzer, not a replacement for an enterprise SIEM.
        Use synthetic or sanitized logs. Avoid uploading personal data, credentials, or confidential logs.
        """
    )

tab_upload, tab_paste, tab_demo = st.tabs(["📁 Upload CSV", "📝 Paste Logs", "🧪 Load Demo"])

with tab_upload:
    uploaded_file = st.file_uploader(
        "Upload a CSV log file",
        type=["csv"],
        help="Recommended columns include timestamp, source_ip, username, event_type, status, and message. Common alternative column names are also supported.",
    )
    if uploaded_file is not None:
        st.caption(f"Selected file: {uploaded_file.name}")

with tab_paste:
    pasted_logs = st.text_area(
        "Paste log lines",
        height=220,
        placeholder=(
            "Oct 11 09:01:03 server sshd[120]: Failed password for admin from 203.0.113.25 port 5111 ssh2\n"
            "Oct 11 09:01:08 server sshd[121]: Failed password for admin from 203.0.113.25 port 5112 ssh2\n"
            "Oct 11 09:01:15 server sshd[122]: Accepted password for admin from 203.0.113.25 port 5113 ssh2"
        ),
    )

with tab_demo:
    st.info("Load a fictional dataset designed to demonstrate repeated login failures, a later successful login, and suspicious command activity.")
    load_demo = st.button("Load fictional demo logs", use_container_width=True)

if "raw_logs" not in st.session_state:
    st.session_state.raw_logs = ""
if "analysis" not in st.session_state:
    st.session_state.analysis = None
if "ai_summary" not in st.session_state:
    st.session_state.ai_summary = None

DEMO_LOGS = """2026-10-11 09:01:03,server-a,203.0.113.25,admin,login,failed,Failed password for admin from 203.0.113.25
2026-10-11 09:01:08,server-a,203.0.113.25,admin,login,failed,Failed password for admin from 203.0.113.25
2026-10-11 09:01:15,server-a,203.0.113.25,admin,login,failed,Failed password for admin from 203.0.113.25
2026-10-11 09:01:21,server-a,203.0.113.25,admin,login,failed,Failed password for admin from 203.0.113.25
2026-10-11 09:01:29,server-a,203.0.113.25,admin,login,failed,Failed password for admin from 203.0.113.25
2026-10-11 09:02:04,server-a,203.0.113.25,admin,login,success,Accepted password for admin from 203.0.113.25
2026-10-11 09:08:44,workstation-7,198.51.100.40,analyst,process,observed,PowerShell encoded command execution detected
2026-10-11 09:10:10,server-b,198.51.100.52,root,privilege,observed,sudo command executed by user root
2026-10-11 09:12:00,server-b,192.0.2.44,guest,login,success,Successful login for guest from 192.0.2.44
"""

if load_demo:
    st.session_state.raw_logs = DEMO_LOGS
    st.session_state.analysis = None
    st.session_state.ai_summary = None

if uploaded_file is not None:
    try:
        uploaded_bytes = uploaded_file.getvalue()
        uploaded_text = uploaded_bytes.decode("utf-8", errors="replace")
        st.session_state.raw_logs = uploaded_text
    except Exception:
        st.error("The uploaded file could not be read as UTF-8 text.")

if pasted_logs.strip():
    st.session_state.raw_logs = pasted_logs

analyze_clicked = st.button("🔍 Analyze Logs", type="primary", use_container_width=True)

if analyze_clicked:
    raw = st.session_state.raw_logs.strip()
    if not raw:
        st.warning("Upload a CSV, paste log lines, or load the demo dataset first.")
    else:
        with st.spinner("Parsing logs and running detection rules..."):
            try:
                events = load_logs(raw)
                result = analyze_logs(events)
                st.session_state.analysis = result
                st.session_state.ai_summary = None
                st.session_state.events = events
            except Exception as exc:
                st.error(f"Could not analyze these logs: {exc}")

if st.session_state.analysis is not None:
    result = st.session_state.analysis
    events = st.session_state.get("events", [])
    alerts = result["alerts"]
    event_summary = summarize_events(events)

    st.markdown("## 📊 Security Overview")
    c1, c2, c3, c4 = st.columns(4)
    metrics = [
        ("Events Analyzed", len(events)),
        ("Alerts Generated", len(alerts)),
        ("High/Critical Alerts", sum(a["severity"] in ("High", "Critical") for a in alerts)),
        ("Unique Source IPs", len({e.get("source_ip") for e in events if e.get("source_ip")})),
    ]
    for col, (label, value) in zip((c1, c2, c3, c4), metrics):
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("## 🚨 Detection Alerts")
    if alerts:
        sev_filter = st.multiselect(
            "Filter by severity",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
        )
        filtered_alerts = [a for a in alerts if a["severity"] in sev_filter]
        for alert in filtered_alerts:
            st.markdown(
                f'<div class="alert-card"><div class="alert-card-title">'
                f'⚠️ {escape(alert["title"])} · {escape(alert["severity"])}</div>'
                f'<div>{escape(alert["description"])}</div>'
                f'<div style="margin-top:7px;font-size:12px;">Evidence: {escape(alert["evidence"])}</div>'
                f'<div style="margin-top:5px;font-size:12px;">Source IP: {escape(alert.get("source_ip") or "Not identified")} '
                f'| Events: {alert.get("event_count", 1)}</div></div>',
                unsafe_allow_html=True,
            )
    else:
        st.success("No alerts matched the current detection rules. This does not guarantee the logs are benign.")

    st.markdown("## 📈 Event Summary")
    left, right = st.columns([1, 1])
    with left:
        if event_summary:
            summary_df = pd.DataFrame(
                [{"Event Type": k, "Count": v} for k, v in event_summary.items()]
            )
            st.bar_chart(summary_df.set_index("Event Type"))
        else:
            st.caption("No event types could be categorized.")
    with right:
        source_counts = {}
        for event in events:
            ip = event.get("source_ip") or "Unknown"
            source_counts[ip] = source_counts.get(ip, 0) + 1
        source_df = pd.DataFrame(
            [{"Source IP": k, "Events": v} for k, v in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
        )
        if not source_df.empty:
            st.dataframe(source_df, use_container_width=True, hide_index=True)
        else:
            st.caption("No source IP addresses found.")

    st.markdown("## 🤖 AI-Assisted Investigation")
    st.caption("Optional: AI summarizes the rule-generated alerts. It does not replace or alter the rule-based detections.")
    if st.button("Explain Alerts with AI", use_container_width=True):
        api_key = None
        try:
            api_key = st.secrets.get("GROQ_API_KEY")
        except Exception:
            api_key = None
        if not api_key:
            api_key = os.getenv("GROQ_API_KEY")

        if not api_key:
            st.session_state.ai_summary = {
                "error": "GROQ_API_KEY is not configured. Add it in Streamlit Cloud → App settings → Secrets."
            }
        else:
            with st.spinner("Preparing evidence-based alert summary..."):
                try:
                    client = Groq(api_key=api_key)
                    compact_alerts = [
                        {
                            "title": a["title"],
                            "severity": a["severity"],
                            "description": a["description"],
                            "evidence": a["evidence"],
                            "source_ip": a.get("source_ip"),
                            "event_count": a.get("event_count", 1),
                        }
                        for a in alerts[:20]
                    ]
                    system_prompt = """
You are a cautious SOC analyst assistant. Summarize only the supplied structured alerts.
Do not invent events, IP reputation, users, timestamps, malware attribution, or attack success.
Treat IP addresses and log messages as evidence only; do not claim external reputation checks were performed.
Clearly distinguish observed evidence from hypotheses. Provide:
1) concise executive summary,
2) top priorities,
3) suggested defensive investigation steps.
Do not suggest offensive actions. Return valid JSON only with keys: summary (string),
priorities (array of strings), investigation_steps (array of strings).
"""
                    response = client.chat.completions.create(
                        model="openai/gpt-oss-120b",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": json.dumps(compact_alerts)},
                        ],
                        temperature=0,
                        max_tokens=1200,
                    )
                    content = response.choices[0].message.content.strip()
                    if content.startswith("```"):
                        content = content.split("\n", 1)[-1]
                        if content.endswith("```"):
                            content = content[:-3]
                    st.session_state.ai_summary = json.loads(content.strip())
                except Exception as exc:
                    st.session_state.ai_summary = {"error": f"AI analysis failed: {exc}"}

    ai_summary = st.session_state.ai_summary
    if ai_summary:
        if "error" in ai_summary:
            st.warning(ai_summary["error"])
        else:
            st.info(ai_summary.get("summary", "No summary provided."))
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Priority areas**")
                for item in ai_summary.get("priorities", []):
                    st.markdown(f"- {item}")
            with col_b:
                st.markdown("**Suggested investigation steps**")
                for item in ai_summary.get("investigation_steps", []):
                    st.markdown(f"- {item}")

    st.markdown("## 📄 Export")
    c1, c2 = st.columns(2)
    alerts_df = pd.DataFrame(alerts)
    with c1:
        csv_bytes = alerts_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Alerts CSV",
            data=csv_bytes,
            file_name="mini_siem_alerts.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with c2:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=17*mm, rightMargin=17*mm, topMargin=15*mm, bottomMargin=15*mm)
            styles = getSampleStyleSheet()
            story = [
                Paragraph("Mini SIEM Log Analyzer — Investigation Report", styles["Title"]),
                Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
                Spacer(1, 12),
                Paragraph(f"Events analyzed: {len(events)} | Alerts generated: {len(alerts)}", styles["Heading2"]),
                Spacer(1, 8),
            ]
            for a in alerts:
                story.append(Paragraph(f"<b>{escape(a['severity'])}: {escape(a['title'])}</b>", styles["Heading3"]))
                story.append(Paragraph(escape(a["description"]), styles["BodyText"]))
                story.append(Paragraph(f"<b>Evidence:</b> {escape(a['evidence'])}", styles["BodyText"]))
                story.append(Paragraph(f"<b>Source IP:</b> {escape(a.get('source_ip') or 'Not identified')}", styles["BodyText"]))
                story.append(Spacer(1, 8))
            story.append(Spacer(1, 10))
            story.append(Paragraph("Disclaimer: This demo tool provides preliminary triage. Validate findings using trusted telemetry and your incident response process.", styles["Italic"]))
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            st.download_button(
                "⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name="mini_siem_investigation_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.error(f"PDF report generation is unavailable: {exc}")

    with st.expander("View parsed events", expanded=False):
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)

st.markdown(
    '<div class="footer">Mini SIEM Log Analyzer · Rule-based detections + optional AI assistance · Educational portfolio project</div>',
    unsafe_allow_html=True,
)
