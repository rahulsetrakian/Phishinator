import re


def analyze_email(parsed_email, vt_report=None):
    """Return an auditable, indicator-weighted phishing risk report."""
    body_text = (parsed_email.get('body_text') or '').lower()
    html_text = (parsed_email.get('html_text') or '').lower()
    combined_body = f"{body_text} {html_text}"
    subject = (parsed_email.get('subject') or '').lower()
    links = parsed_email.get('links') or []
    sender = (parsed_email.get('from') or '').lower()
    attachments = parsed_email.get('attachments') or []

    # Indicators definition
    has_urgency = any(w in combined_body or w in subject for w in [
        'urgent', 'immediately', '30 minutes', 'within 30', 'suspended', 'suspension', 'action required', 'failure to respond'
    ])

    has_lure = any(w in combined_body or w in subject for w in [
        'verify', 'verification', 'billing', 'payment failed', 'unusual payment', 'charge of', 'account access', 'password'
    ])

    # Check lookalike domain indicators
    lookalike_patterns = ['paypa1', 'bank-alerts', 'login-paypal', 'paypal-security', 'secure-paypa1', 'fake-login']
    has_lookalike = any(p in sender for p in lookalike_patterns) or any(
        any(p in link.lower() for p in lookalike_patterns) for link in links
    )

    # Check external links
    has_external_links = len(links) > 0

    # Check IP-based URLs
    has_ip_url = any(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link) for link in links)

    # Check attachments
    has_exe_attachment = any(a.get('is_executable') for a in attachments) or (
        parsed_email.get('has_attachment') and not attachments
    )
    has_eicar = any(a.get('eicar_detected') for a in attachments)

    # Check VirusTotal
    vt_status = vt_report.get('status') if vt_report else 'disabled'
    vt_results = (vt_report.get('results') or []) if vt_report else []
    vt_malicious = vt_status == 'malicious' or any(
        r.get('status') == 'malicious' for r in vt_results
    )
    vt_suspicious = (vt_status == 'suspicious' or any(
        r.get('status') == 'suspicious' for r in vt_results
    )) and not vt_malicious

    score_breakdown = [
        {
            'indicator': 'Urgent / pressure language',
            'category': 'Email Content',
            'weight': 15,
            'matched': has_urgency,
            'details': 'Urgent deadline or account suspension threat detected.',
        },
        {
            'indicator': 'Account / payment lure',
            'category': 'Email Content',
            'weight': 15,
            'matched': has_lure,
            'details': 'Direct request for payment verification or account action.',
        },
        {
            'indicator': 'Impersonation / lookalike domain',
            'category': 'Sender & Domain',
            'weight': 15,
            'matched': has_lookalike,
            'details': 'Sender or URL domain contains lookalike brand character substitution.',
        },
        {
            'indicator': 'Embedded external links',
            'category': 'Link Analysis',
            'weight': 10,
            'matched': has_external_links,
            'details': 'Email contains clickable external links.',
        },
        {
            'indicator': 'IP-address-based URL',
            'category': 'Link Analysis',
            'weight': 10,
            'matched': has_ip_url,
            'details': 'Link uses a raw IP address instead of a domain name.',
        },
        {
            'indicator': 'Executable attachment',
            'category': 'Attachment',
            'weight': 20,
            'matched': has_exe_attachment,
            'details': 'Message includes an executable file attachment (e.g. Windows .exe).',
        },
        {
            'indicator': 'Antivirus test signature (EICAR)',
            'category': 'Attachment',
            'weight': 10,
            'matched': has_eicar,
            'details': 'EICAR standard antivirus test signature detected in attachment payload.',
        },
        {
            'indicator': 'VirusTotal malicious URL detection',
            'category': 'Threat Intelligence',
            'weight': 25,
            'matched': vt_malicious,
            'details': 'One or more URLs flagged as malicious by VirusTotal engines.',
        },
        {
            'indicator': 'VirusTotal suspicious URL detection',
            'category': 'Threat Intelligence',
            'weight': 15,
            'matched': vt_suspicious,
            'details': 'One or more URLs flagged as suspicious by VirusTotal engines.',
        },
    ]

    total_score = sum(item['weight'] for item in score_breakdown if item['matched'])
    score = min(total_score, 100)

    findings = []
    if has_urgency:
        findings.append('The message uses urgency or deadline pressure language.')
    if has_lure:
        findings.append('The email contains credential or payment verification lures.')
    if has_lookalike:
        findings.append('The sender or link domains match known lookalike/impersonation patterns.')
    if has_ip_url:
        findings.append('One or more embedded links use a raw IP address instead of a domain.')
    if has_exe_attachment:
        findings.append('An executable file attachment was detected.')
    if has_eicar:
        findings.append('EICAR antivirus test signature detected in attachment payload (security test artifact).')
    if vt_malicious:
        findings.append('VirusTotal flagged one or more links as malicious.')
    elif vt_suspicious:
        findings.append('VirusTotal flagged one or more links as suspicious.')

    if score >= 50:
        verdict = 'high-risk phishing'
    elif score >= 30:
        verdict = 'suspicious but not conclusive'
    else:
        verdict = 'likely legitimate'

    explanation = build_explanation(verdict, findings, score, vt_report, has_eicar)

    return {
        'score': score,
        'verdict': verdict,
        'findings': findings,
        'explanation': explanation,
        'score_breakdown': score_breakdown,
    }


def build_explanation(verdict, findings, score, vt_report=None, has_eicar=False):
    if verdict == 'high-risk phishing':
        base = (
            f'This email scored {score}/100 based on multiple independent risk indicators, '
            'including urgent deadline pressure, payment verification lures, lookalike domain usage, '
            'and an executable file attachment. It should be treated as a likely phishing attack.'
        )
    elif verdict == 'suspicious but not conclusive':
        base = (
            f'This email scored {score}/100 with moderate warning signs. '
            'While some indicators were flagged, the evidence is not entirely conclusive.'
        )
    else:
        base = (
            f'This email scored {score}/100 and shows low risk overall. '
            'The message appears routine with no severe phishing cues.'
        )

    if has_eicar:
        base += ' Note: The attached file contains the EICAR test signature, indicating an antivirus security test artifact.'

    if vt_report:
        vt_st = vt_report.get('status')
        if vt_st == 'malicious':
            base += ' VirusTotal confirmed malicious link detections.'
        elif vt_st == 'inconclusive':
            base += ' VirusTotal did not possess prior threat records for some URLs; absence of VT detection does not guarantee safety.'

    return base

