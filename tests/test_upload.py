import io
import unittest

from app.app import app


class UploadRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        app.config.update({"TESTING": True})

    def test_home_page_is_accessible(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_upload_with_empty_file(self):
        data = {'file': (io.BytesIO(b''), 'empty.eml')}
        response = self.client.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Uploaded file is empty', response.data)

    def test_upload_with_invalid_file_type(self):
        data = {'file': (io.BytesIO(b'This is a test file'), 'test.txt')}
        response = self.client.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Invalid file type. Only .eml files are allowed.', response.data)

    def test_upload_with_valid_file(self):
        email_content = (
            b'From: sender@example.com\r\n'
            b'To: recipient@example.com\r\n'
            b'Subject: Test Email\r\n'
            b'\r\n'
            b'This is a safe test email content.'
        )

        data = {'file': (io.BytesIO(email_content), 'test.eml')}
        response = self.client.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Analysis Report', response.data)
        self.assertIn(b'likely legitimate', response.data)


if __name__ == '__main__':
    unittest.main()