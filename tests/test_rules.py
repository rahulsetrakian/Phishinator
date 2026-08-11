import io
import unittest

from app.services.parser_service import parse_email
from app.services.scorer_service import analyze_email


class ScoringTests(unittest.TestCase):
    def test_suspicious_email_scores_high_risk(self):
        email_content = (
            b'From: support@bank-alerts.example\r\n'
            b'To: customer@example.com\r\n'
            b'Subject: Urgent: verify your account\r\n'
            b'\r\n'
            b'Please click http://fake-login.example to verify your password immediately.'
        )

        parsed = parse_email(io.BytesIO(email_content))
        report = analyze_email(parsed)

        self.assertGreaterEqual(report['score'], 50)
        self.assertEqual(report['verdict'], 'high-risk phishing')
        self.assertTrue(report['findings'])

    def test_legitimate_email_scores_low_risk(self):
        email_content = (
            b'From: team@example.com\r\n'
            b'To: user@example.com\r\n'
            b'Subject: Weekly project update\r\n'
            b'\r\n'
            b'Thank you for your work this week. We will meet on Friday.'
        )

        parsed = parse_email(io.BytesIO(email_content))
        report = analyze_email(parsed)

        self.assertLess(report['score'], 40)
        self.assertEqual(report['verdict'], 'likely legitimate')


if __name__ == '__main__':
    unittest.main()
