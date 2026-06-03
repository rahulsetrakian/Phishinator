from flask import Flask, Blueprint, render_template

app = Flask(__name__)
index_bp = Blueprint('index', __name__)

# routes for index blueprints

@index_bp.route('/')
def index():
    return render_template('index.html')

@index_bp.route('/about')
def about():
    return render_template('about.html')

@index_bp.route('/glossary')
def glossary():
    return render_template('glossary.html')