from email.policy import default
from email.parser import BytesParser, BytesHeaderParser
import os

def parse_email(file):
    # TODO: implement parsing
    file.seek(0)
    raw_data = file.read()
    msg = BytesParser(policy=default).parsebytes(raw_data)
    all_header = {}

    for header_name, header_value in msg.items():
        if header_name in all_header:
            if isinstance(all_header[header_name], list):
                all_header[header_name].append(str(header_value))
            else:
                all_header[header_name] = [all_header[header_name], str(header_value)]
        else:
            all_header[header_name] = str(header_value)

    print(all_header)

def has_attachment():
    # TODO: implement the check for attachment file

    return False

def extract_hash():
    # TODO: extract hash of the attachment

    return True