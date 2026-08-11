# CS50x Final Project - Phishinator
# AI Tool Citation: AI assistance (Google Antigravity AI pair programming assistant) was used as a helper for 
# code refactoring, rate limiting setup, and UI layout optimization, in compliance with CS50x guidelines.

import os
from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .routes.index import index_bp
from .routes.analyser import uploader_bp

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per minute"],
    storage_uri="memory://",
)

app.register_blueprint(index_bp)
app.register_blueprint(uploader_bp)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', error="Rate limit exceeded. Please wait a minute before sending more requests."), 429