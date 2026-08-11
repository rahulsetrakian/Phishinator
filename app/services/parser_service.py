import hashlib
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

EICAR_PATTERN = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
EXECUTABLE_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.dll', '.com', '.pif', '.hta'}


def parse_email(file):
    """Parse an uploaded .eml file into a structured dictionary."""
    file.seek(0)
    raw_data = file.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw_data)

    headers = {}
    for header_name, header_value in msg.items():
        if header_name in headers:
            if isinstance(headers[header_name], list):
                headers[header_name].append(str(header_value))
            else:
                headers[header_name] = [headers[header_name], str(header_value)]
        else:
            headers[header_name] = str(header_value)

    body_text, html_text = extract_body_parts(msg)
    link_info = extract_links(body_text, headers, html_content=html_text)
    attachments = parse_attachments(msg)
    sender_name, sender_address = parseaddr(msg.get('From', ''))

    return {
        'headers': headers,
        'subject': msg.get('Subject', '').strip(),
        'from': sender_address or sender_name or msg.get('From', '').strip(),
        'to': msg.get('To', '').strip(),
        'body_text': body_text,
        'html_text': html_text,
        'links': link_info['unique_links'],
        'raw_links': link_info['raw_links'],
        'link_counts': {
            'raw': link_info['raw_count'],
            'unique': link_info['unique_count'],
        },
        'has_attachment': len(attachments) > 0,
        'attachments': attachments,
    }


def extract_body_parts(message):
    text_parts = []
    html_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_disposition() == 'attachment':
                continue

            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            charset = part.get_content_charset() or 'utf-8'
            try:
                decoded = payload.decode(charset)
            except (LookupError, UnicodeDecodeError):
                decoded = payload.decode('utf-8', errors='ignore')

            if content_type == 'text/plain':
                text_parts.append(decoded)
            elif content_type == 'text/html':
                html_parts.append(decoded)
    else:
        payload = message.get_payload(decode=True)
        if payload is not None:
            charset = message.get_content_charset() or 'utf-8'
            try:
                decoded = payload.decode(charset)
            except (LookupError, UnicodeDecodeError):
                decoded = payload.decode('utf-8', errors='ignore')

            if message.get_content_type() == 'text/html':
                html_parts.append(decoded)
            else:
                text_parts.append(decoded)

    return '\n'.join(text_parts).strip(), '\n'.join(html_parts).strip()


def clean_url(url):
    """Normalize URL by stripping surrounding quotes, HTML tags, and trailing punctuation."""
    if not url:
        return ''
    url = url.strip('\'"<>()[]')
    # Strip trailing quotes, closing tags, sentence punctuation
    url = re.sub(r'[\"\'>.,;:!)]+$', '', url)
    return url.strip()


def extract_links(body_text, headers, html_content=None):
    """Extract and normalize links from body text, HTML, and headers."""
    raw_urls = []

    if html_content:
        # Extract explicit href attributes
        hrefs = re.findall(r'href=[\'"]?(https?://[^\'">\s]+)', html_content, re.IGNORECASE)
        raw_urls.extend(hrefs)

    search_space = f"{body_text} {html_content or ''} {' '.join(str(v) for v in headers.values())}"
    matches = re.findall(r'https?://[^\s<>"]+', search_space, re.IGNORECASE)
    raw_urls.extend(matches)

    cleaned_raw = []
    unique_urls = []
    seen = set()

    for url in raw_urls:
        c_url = clean_url(url)
        if c_url:
            cleaned_raw.append(c_url)
            if c_url not in seen:
                seen.add(c_url)
                unique_urls.append(c_url)

    return {
        'raw_links': cleaned_raw,
        'unique_links': unique_urls,
        'raw_count': len(cleaned_raw),
        'unique_count': len(unique_urls),
    }


def parse_attachments(message):
    """Parse MIME attachments to extract metadata, SHA-256 hash, and test signature flags."""
    attachments = []
    for part in message.walk():
        cdisp = str(part.get_content_disposition() or '').lower()
        filename = part.get_filename()

        if cdisp == 'attachment' or (filename and cdisp != 'inline'):
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            filename = filename or 'unnamed_attachment'
            size_bytes = len(payload)
            content_type = part.get_content_type()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            ext = os.path.splitext(filename)[1].lower()
            is_executable = ext in EXECUTABLE_EXTENSIONS or payload.startswith(b'MZ')
            eicar_detected = EICAR_PATTERN in payload

            attachments.append({
                'filename': filename,
                'size_bytes': size_bytes,
                'content_type': content_type,
                'sha256': sha256_hash,
                'is_executable': is_executable,
                'eicar_detected': eicar_detected,
            })

    return attachments

