# CS50x Final Project - Phishinator
# AI Tool Citation: AI assistance (Google Antigravity AI pair programming assistant) was used as a helper for 
# multi-link VirusTotal API integration and error checking, in compliance with CS50x guidelines.

import os
from flask import Blueprint, Flask, render_template, request
from werkzeug.utils import secure_filename
from app.services import parser_service, scorer_service
from app.services.virustotal_service import analyze_urls
from app.services.llm_service import summarize_analysis

ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
uploader_bp = Blueprint('uploader', __name__)

UPLOAD_FOLDER = 'instance/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@uploader_bp.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return render_template('error.html', error='No file was found in the request'), 400

    file = request.files['file']
    if file.filename == '':
        return render_template('error.html', error='No file selected'), 400

    file.seek(0, 2)
    file_length = file.tell()
    file.seek(0)

    if file_length == 0:
        return render_template('error.html', error='Uploaded file is empty'), 400

    if not file.filename.lower().endswith('.eml'):
        return render_template('error.html', error='Invalid file type. Only .eml files are allowed.'), 400

    if file_length > app.config['MAX_CONTENT_LENGTH']:
        return render_template('error.html', error='File size exceeds the maximum limit of 5MB.'), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
    file.save(file_path)

    try:
        parsed_email = parser_service.parse_email(file)
        
        # Analyze all links with VirusTotal
        vt_report = None
        if parsed_email.get('links'):
            vt_report = analyze_urls(parsed_email['links'])

        report = scorer_service.analyze_email(parsed_email, vt_report=vt_report)
        
        # AI-powered executive threat summary from OpenRouter
        ai_summary = summarize_analysis(report, parsed_email, vt_report=vt_report)
        report['ai_summary'] = ai_summary

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    return render_template(
        'result.html',
        report=report,
        parsed_email=parsed_email,
        filename=file.filename,
        vt_report=vt_report,
    ), 200