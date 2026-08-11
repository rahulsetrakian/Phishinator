import io
import unittest

from app.services.parser_service import parse_email


class ParserServiceTests(unittest.TestCase):
    def test_parse_email_extracts_headers_body_and_links(self):
        email_content = (
            b'From: attacker@example.com\r\n'
            b'To: victim@example.com\r\n'
            b'Subject: Urgent password reset\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n'
            b'\r\n'
            b'Please click http://example-malicious.com to reset your password now.'
        )

        parsed = parse_email(io.BytesIO(email_content))

        self.assertEqual(parsed['subject'], 'Urgent password reset')
        self.assertEqual(parsed['from'], 'attacker@example.com')
        self.assertIn('http://example-malicious.com', parsed['links'])
        self.assertIn('reset your password', parsed['body_text'].lower())

    def test_url_normalization_and_deduplication(self):
        email_content = (
            b'From: test@example.com\r\n'
            b'Content-Type: text/html; charset=utf-8\r\n'
            b'\r\n'
            b'<html><body>'
            b'<a href="http://198.51.100.23/verify?id=1">Link 1</a>'
            b'Check: http://198.51.100.23/verify?id=1"'
            b'</body></html>'
        )

        parsed = parse_email(io.BytesIO(email_content))
        self.assertEqual(parsed['link_counts']['raw'], 3)
        self.assertEqual(parsed['link_counts']['unique'], 1)
        self.assertEqual(parsed['links'], ['http://198.51.100.23/verify?id=1'])

    def test_attachment_sha256_and_eicar_detection(self):
        eicar_payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        boundary = b"===BOUNDARY==="
        email_content = (
            b'From: attacker@example.com\r\n'
            b'Content-Type: multipart/mixed; boundary="' + boundary + b'"\r\n'
            b'\r\n--' + boundary + b'\r\n'
            b'Content-Type: text/plain\r\n\r\nBody text\r\n--' + boundary + b'\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Disposition: attachment; filename="Invoice_URGENT.exe"\r\n\r\n'
            + eicar_payload + b'\r\n--' + boundary + b'--'
        )

        parsed = parse_email(io.BytesIO(email_content))
        self.assertTrue(parsed['has_attachment'])
        self.assertEqual(len(parsed['attachments']), 1)
        att = parsed['attachments'][0]
        self.assertEqual(att['filename'], 'Invoice_URGENT.exe')
        self.assertTrue(att['is_executable'])
        self.assertTrue(att['eicar_detected'])
        self.assertEqual(len(att['sha256']), 64)


if __name__ == '__main__':
    unittest.main()

