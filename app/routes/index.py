import os
from flask import Flask, Blueprint, render_template
from app.services import parser_service, scorer_service

app = Flask(__name__)
index_bp = Blueprint('index', __name__)


@index_bp.route('/')
def index():
    return render_template('index.html')


@index_bp.route('/about')
def about():
    return render_template('about.html')


@index_bp.route('/glossary')
def glossary():
    return render_template('glossary.html')


@index_bp.route('/samples')
def samples():
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'samples')
    sample_files = []

    if os.path.isdir(sample_dir):
        for name in sorted(os.listdir(sample_dir)):
            if name.endswith('.eml'):
                sample_path = os.path.join(sample_dir, name)
                with open(sample_path, 'rb') as handle:
                    parsed_email = parser_service.parse_email(__import__('io').BytesIO(handle.read()))
                report = scorer_service.analyze_email(parsed_email)
                sample_files.append({
                    'name': name,
                    'score': report['score'],
                    'verdict': report['verdict'],
                })

    return render_template('samples.html', sample_files=sample_files)