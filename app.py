from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/seeker/dashboard")
def seeker_dashboard():
    return render_template("seeker_dashboard.html")

@app.route("/recruiter/dashboard")
def recruiter_dashboard():
    return render_template("recruiter_dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)