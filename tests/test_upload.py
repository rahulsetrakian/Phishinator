import io

def test_if_site_is_up(client):
    # Test if the home page is accessible
    response = client.get('/')
    assert response.status_code == 200

def test_upload_with_empty_file(client):
    data = {
        'file': (io.BytesIO(b''), 'empty.eml')
    }
    response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    assert b"Uploaded file is empty" in response.data

def test_upload_with_invalid_file_type(client):
    data = {
        'file': (io.BytesIO(b'This is a test file'), 'test.txt')
    }
    response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    assert b"Invalid file type. Only .eml files are allowed." in response.data

def test_upload_with_valid_file(client):
    email_content = (
        b"From:test@example.com\r\n"
        b"To:anothertest@example.com\r\n"
        b"Subject:Test Email\r\n"
        b"\r\n"
        b"This is a test email content."
    )

    data = {
        'file': (io.BytesIO(email_content), 'test.eml')
    }

    response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    assert b"File 'test.eml' uploaded successfully!" in response.data