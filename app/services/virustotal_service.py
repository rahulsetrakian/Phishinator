# CS50x Final Project - Phishinator
# AI Tool Citation: AI assistance (Google Antigravity AI pair programming assistant) was used as a helper for 
# VirusTotal v3 API URL base64url encoding and response parsing logic, in compliance with CS50x guidelines.

import base64
import os
import requests
from dotenv import load_dotenv

load_dotenv()


def get_api_key():
    return os.getenv('VIRUS_TOTAL_API') or os.getenv('VIRUS_TOTAL_API_KEY')


def encode_url_id(url):
    """Encode URL to VirusTotal v3 URL identifier format."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def get_virus_total_report(url, api_key=None):
    """Query VirusTotal v3 for a single URL report."""
    if api_key is None:
        api_key = get_api_key()
    if not api_key:
        return {'status': 'disabled', 'summary': 'No VirusTotal API key configured.', 'url': url}

    url_id = encode_url_id(url)
    endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'

    try:
        response = requests.get(
            endpoint,
            headers={'x-apikey': api_key},
            timeout=8,
        )

        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)

            if malicious > 0:
                status = 'malicious'
                summary = f'Flagged malicious by {malicious} security engine(s).'
            elif suspicious > 0:
                status = 'suspicious'
                summary = f'Flagged suspicious by {suspicious} engine(s).'
            elif harmless > 0 or undetected > 0:
                status = 'clean'
                summary = f'Verified clean across security engines ({harmless} harmless, {undetected} undetected).'
            else:
                status = 'unknown'
                summary = 'No engine verdicts available.'

            return {
                'url': url,
                'status': status,
                'summary': summary,
                'stats': stats,
            }

        elif response.status_code == 404:
            # Submit for scanning
            submit_resp = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers={'x-apikey': api_key},
                data={'url': url},
                timeout=8,
            )
            if submit_resp.status_code in (200, 201):
                return {
                    'url': url,
                    'status': 'submitted',
                    'summary': 'Newly submitted to VirusTotal for analysis.',
                    'stats': {},
                }
            return {
                'url': url,
                'status': 'unknown',
                'summary': 'No existing VirusTotal record found.',
                'stats': {},
            }
        elif response.status_code == 429:
            return {
                'url': url,
                'status': 'rate_limited',
                'summary': 'VirusTotal API rate limit reached.',
                'stats': {},
            }
        else:
            return {
                'url': url,
                'status': 'error',
                'summary': f'VirusTotal lookup returned HTTP {response.status_code}.',
                'stats': {},
            }
    except Exception as exc:
        return {
            'url': url,
            'status': 'error',
            'summary': f'VirusTotal request failed: {str(exc)}',
            'stats': {},
        }


def analyze_urls(urls, api_key=None):
    """Query VirusTotal for all unique links in an email (max 5 links to preserve quota)."""
    api_key = api_key or get_api_key()
    if not api_key:
        return {
            'status': 'disabled',
            'summary': 'No VirusTotal API key configured.',
            'results': [],
        }

    if not urls:
        return {
            'status': 'checked',
            'summary': 'No clickable links detected in email body or headers.',
            'results': [],
        }

    # Deduplicate preserving order
    unique_urls = list(dict.fromkeys(urls))[:5]
    results = []
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    for url in unique_urls:
        report = get_virus_total_report(url, api_key=api_key)
        results.append(report)
        st = report.get('status')
        if st == 'malicious':
            malicious_count += 1
        elif st == 'suspicious':
            suspicious_count += 1
        elif st == 'clean':
            clean_count += 1

    if malicious_count > 0:
        overall_status = 'malicious'
        overall_summary = f'VirusTotal detected {malicious_count} malicious URL(s) in this email.'
    elif suspicious_count > 0:
        overall_status = 'suspicious'
        overall_summary = f'VirusTotal detected {suspicious_count} suspicious URL(s) in this email.'
    elif clean_count == len(results) and len(results) > 0:
        overall_status = 'clean'
        overall_summary = f'VirusTotal verified {clean_count} link(s) without threat flags.'
    else:
        overall_status = 'inconclusive'
        overall_summary = 'VirusTotal: No existing malicious verdict was available for the analyzed URLs. Several URLs were newly submitted for analysis, while others had no existing VT record.'

    return {
        'status': overall_status,
        'summary': overall_summary,
        'results': results,
    }

