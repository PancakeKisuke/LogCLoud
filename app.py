#imports
from flask import Flask, render_template
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy

# My webapp
app = Flask(__name__)

#index is is the homepage of the whole app
# the app route decorator binds th e function to the URL, the "/" is default homepage
@app.route("/")

def index():
    return render_template('index.html')

#the runner and debugger

if __name__ in "__main__":
    app.run(debug=True)