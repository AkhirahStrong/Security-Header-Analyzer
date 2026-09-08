

from flask import Flask, render_template, request
from analyzer import scan_headers

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    results = None

    if request.method == "POST":
        url = request.form.get("url")
        results = scan_headers(url)

    return render_template("index.html", results=results)


if __name__ == "__main__":
    app.run(debug=True)