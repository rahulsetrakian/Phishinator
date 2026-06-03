from flask import Flask, render_template
from app.routes.index import index_bp
from app.routes.analyser import uploader_bp

app = Flask(__name__)
app.register_blueprint(index_bp)
app.register_blueprint(uploader_bp)

# Handling 404 page 
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404