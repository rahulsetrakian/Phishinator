import os
import requests
from dotenv import load_dotenv

load_dotenv()


def summarize_analysis(report, parsed_email, vt_report=None):
    """Provide an executive threat summary using OpenRouter API, falling back to structured local explanations."""
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        return build_local_summary(report, parsed_email, vt_report)

    subject = parsed_email.get('subject', 'No subject')
    sender = parsed_email.get('from', 'Unknown sender')
    verdict = report.get('verdict', 'unknown')
    score = report.get('score', 0)
    findings = report.get('findings', [])
    body_snippet = (parsed_email.get('body_text') or '')[:500]
    vt_summary = vt_report.get('summary') if vt_report else 'Not checked'
    unique_links = parsed_email.get('links') or []

    attachments = parsed_email.get('attachments') or []
    attachment_summary = ", ".join(
        f"{a['filename']} (SHA256: {a['sha256'][:10]}..., EICAR: {a['eicar_detected']})"
        for a in attachments
    ) if attachments else "None"

    prompt = f"""
You are an expert cybersecurity email threat analyst.

Analyze the following email report details and provide a concise, high-impact 3 to 4 sentence executive threat summary correlating the evidence.

Key Requirements:
1. Verdict: State the assessment clearly (e.g. "Likely phishing — high confidence.").
2. Correlate Indicators: Connect the tactics used: payment lure, artificial deadlines, account suspension threats, lookalike domain impersonation (e.g. paypa1-security), raw IP-address URLs, and executable attachments.
3. Threat Intelligence Context: Note that absence of VirusTotal detections on newly submitted or unknown URLs does NOT prove a URL is benign.
4. Attachment Assessment: Evaluate attachments (noting file name, SHA-256, and if the EICAR test signature is present, identify it as an intentional antivirus testing artifact).

Email Analysis Details:
- Subject: {subject}
- Sender: {sender}
- Risk Score: {score}/100 ({verdict})
- Unique URLs ({len(unique_links)}): {', '.join(unique_links)}
- Attachments: {attachment_summary}
- Key Findings: {', '.join(findings) if findings else 'None'}
- VirusTotal Summary: {vt_summary}
- Body Preview: "{body_snippet}"

Format output as a plain concise paragraph.
"""

    try:
        response = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'HTTP-Referer': 'https://phishinator.local',
                'X-Title': 'Phishinator Threat Analyzer',
            },
            json={
                'model': 'google/gemini-2.0-flash-lite-001',
                'messages': [
                    {'role': 'system', 'content': 'You are an expert cybersecurity email threat analyst.'},
                    {'role': 'user', 'content': prompt},
                ],
                'temperature': 0.3,
                'max_tokens': 300,
            },
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            choices = data.get('choices', [])
            if choices:
                ai_text = choices[0].get('message', {}).get('content', '').strip()
                if ai_text:
                    return ai_text

        return build_local_summary(report, parsed_email, vt_report)

    except Exception:
        return build_local_summary(report, parsed_email, vt_report)


def build_local_summary(report, parsed_email, vt_report=None):
    """Fallback local threat summary generator."""
    verdict = report.get('verdict', 'unknown')
    score = report.get('score', 0)
    findings = report.get('findings', [])
    attachments = parsed_email.get('attachments') or []

    eicar_found = any(a.get('eicar_detected') for a in attachments)
    exe_found = any(a.get('is_executable') for a in attachments)

    summary_parts = []

    if score >= 50:
        summary_parts.append(
            f"Likely phishing attempt (Score: {score}/100)."
        )
    elif score >= 30:
        summary_parts.append(
            f"Suspicious message requiring review (Score: {score}/100)."
        )
    else:
        summary_parts.append(
            f"Likely legitimate email (Score: {score}/100)."
        )

    if findings:
        summary_parts.append(
            f"The email combines multiple indicators: {'; '.join(findings).lower()}."
        )

    if vt_report and vt_report.get('summary'):
        summary_parts.append(vt_report.get('summary'))

    if eicar_found:
        summary_parts.append(
            "The attachment contains the EICAR test signature, indicating an intentional antivirus-testing artifact rather than genuine malware."
        )
    elif exe_found:
        summary_parts.append(
            "The message contains an executable attachment that should be treated as suspicious."
        )

    return " ".join(summary_parts)