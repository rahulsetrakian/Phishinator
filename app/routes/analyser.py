import os
from flask import Blueprint, Flask, render_template, request
from app.services import scorer, parser 

app = Flask(__name__)
uploader_bp = Blueprint('uploader', __name__)

# Route for handling file uploads

UPLOAD_FOLDER = 'instance/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    
    # 2. Validate the file type
    if not file.filename.lower().endswith('.eml'):
        return render_template('error.html', error="Invalid file type. Only .eml files are allowed."), 400

    # 3. Save the file to the upload folder    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        # You can add additional processing of the file here if needed

        result = parser.parse_email(file)
        score = scorer.calculate(result)
        

        return f"File '{file.filename}' uploaded successfully!", 200

    return render_template('error.html', error="File upload failed"), 500