from flask import Flask
from routes.organization import organization_bp

app = Flask(__name__)

app.register_blueprint(organization_bp, url_prefix="/organization")

@app.route("/")
def hello():
    return "Hello, Flask!"

if __name__ == "__main__":
    app.run(debug=True)
