import os
from flask import Blueprint, Flask, render_template, request
from werkzeug.utils import secure_filename
from app.services import parser_service

ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
uploader_bp = Blueprint('uploader', __name__)
es = parser_service

# Route for handling file uploads

UPLOAD_FOLDER = 'instance/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@uploader_bp.route('/upload', methods=['POST'])
def upload():
    # 1. Check if the 'file' key is in the request    
    if 'file' not in request.files:
        return render_template('error.html', error="No file was found in the request"), 400
    
    file = request.files['file']

    if file.filename == '':
        return render_template('error.html', error="No file selected"), 400
    
    file.seek(0, 2)
    file_length = file.tell()
    file.seek(0)

    if file_length == 0:
        return render_template('error.html', error="Uploaded file is empty"), 400
    
    # 2. Validate the file type and file size
    if not file.filename.lower().endswith('.eml'):
        return render_template('error.html', error="Invalid file type. Only .eml files are allowed."), 400

    if file_length > app.config["MAX_CONTENT_LENGTH"]:
        return render_template('error.html', error="File size exceeds the maximum limit of 5MB."), 400

    # 3. Save the file to the upload folder
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)
        # You can add additional processing of the file here if needed
        
        result = es.parse_email(file)
        
        print(result)

        #if es.has_attachment(file):
        #    hash = es.extract_hash(file)

        # score = scorer.calculate(result)
        # llm_response = llm.analyze(result)

        # Post-Analysis
        if os.path.exists(file_path):
            os.remove(file_path)

        return f"File '{file.filename}' uploaded successfully!", 200

    return render_template('error.html', error="File upload failed"), 500