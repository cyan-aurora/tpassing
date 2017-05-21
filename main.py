#!/usr/bin/env python3

import bcrypt
import logging
import configparser

from flask import Flask, request, session, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_required, login_user, logout_user

secure_config = configparser.ConfigParser()
secure_config.read("secure.ini")

app = Flask(__name__)
app.config["SECRET_KEY"] = secure_config.get("Flask", "secret_key")

mysql_password = secure_config.get("SQL", "password")
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:" + mysql_password + "@localhost/transpassing"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model):
	user_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(40), unique=True)
	password = db.Column(db.String(60))

	def __init__(self, user_id, username, password):
		self.user_id = user_id
		self.username = username
		self.password = bcrypt.hashpw(password, bcrypt.gensalt())

	def __repr__(self):
		return "<User %r>" % self.username

	# Flask login interface
	authenticated = False
	def is_authenticated(self):
		return authenticated
	def is_active(self):
		return True
	def is_anonymous(self):
		return is_authenticated()
	def get_id(self):
		return str(self.user_id)

@login_manager.user_loader
def load_user(user_id_string):
	return User.query.filter_by(user_id=int(user_id_string)).first()

@app.route("/")
def default():
	return render_template("index.html")

@app.route("/login", methods=["get"])
def login_form():
	return render_template("login-form.html")

@app.route("/login", methods=["post"])
def login():
	logging.info(request.form["username"])
	user = User.query.filter_by(username=request.form["username"]).first()
	if not user:
		return render_template("no-login.html")
	given_password = request.form["password"].encode("utf-8")
	correct_hash = user.password.encode("utf-8")
	given_hash = bcrypt.hashpw(given_password, correct_hash)
	if given_hash == correct_hash:
		login_user(user)
		session["username"] = user.username
		return redirect("/browse")
	else:
		return render_template("no-login.html")

@app.route("/logout")
def logout():
	logout_user()
	return redirect("/")

@app.route("/browse")
@login_required
def browse_submissions():
	return render_template("browse.html")

@app.route("/submit", methods=["get"])
@login_required
def submission_page():
	return render_template("submit.html")

@app.route("/submit", methods=["post"])
@login_required
def submit_post():
	return "You submitted. Not really LOL this thing sucks."

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
