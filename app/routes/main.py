from flask import Flask, Blueprint, render_template

app = Flask(__name__)
index_bp = Blueprint('index', __name__)

@index_bp.route('/')
def index():
    return render_template('index.html', user="skipper")