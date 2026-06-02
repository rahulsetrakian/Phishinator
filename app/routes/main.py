from flask import Flask, Blueprint, render_template

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

@index_bp.route('/test')
def test():
    return render_template('test.html')