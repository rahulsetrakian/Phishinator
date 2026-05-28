from flask import Flask, render_template
from app.routes.main import index_bp

app = Flask(__name__)
app.register_blueprint(index_bp)