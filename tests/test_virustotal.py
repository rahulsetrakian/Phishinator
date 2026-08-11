import os
import tempfile
import unittest

from app.services.scorer_service import analyze_email
from app.services.virustotal_service import get_virus_total_report


from unittest.mock import patch, MagicMock
from app.services.virustotal_service import analyze_urls, get_virus_total_report


class VirusTotalIntegrationTests(unittest.TestCase):
    def test_missing_api_key_returns_disabled_report(self):
        report = get_virus_total_report('http://example.com', api_key='')
        self.assertEqual(report['status'], 'disabled')

    def test_malicious_virus_total_signal_increases_risk(self):
        parsed_email = {
            'body_text': 'Please verify your account now',
            'subject': 'Urgent account update',
            'links': ['http://fake-login.example'],
            'from': 'support@example.com',
            'has_attachment': False,
        }
        vt_report = {'status': 'malicious', 'summary': 'Known malicious URL'}

        report = analyze_email(parsed_email, vt_report=vt_report)

        self.assertGreaterEqual(report['score'], 75)
        self.assertIn('VirusTotal', report['explanation'])

    @patch('app.services.virustotal_service.get_virus_total_report')
    def test_submitted_or_unknown_urls_summary(self, mock_get_vt):
        mock_get_vt.return_value = {
            'url': 'http://198.51.100.23/verify',
            'status': 'submitted',
            'summary': 'Newly submitted to VirusTotal for analysis.',
            'stats': {},
        }
        vt_analysis = analyze_urls(['http://198.51.100.23/verify'], api_key='mock_key')
        self.assertEqual(vt_analysis['status'], 'inconclusive')
        self.assertIn('No existing malicious verdict was available', vt_analysis['summary'])
        self.assertNotIn('verified clean', vt_analysis['summary'].lower())


if __name__ == '__main__':
    unittest.main()

