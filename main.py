#!/usr/bin/env python3

import bcrypt
import logging
import configparser

from flask import Flask, request, session, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

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
	def login(self, given_password):
		given_password = given_password.encode("utf-8")
		correct_hash = self.password.encode("utf-8")
		given_hash = bcrypt.hashpw(given_password, correct_hash)
		self.authenticated = (given_hash == correct_hash)
		if self.is_authenticated():
			login_user(self)
		return self.is_authenticated()
	def is_authenticated(self):
		print(self.authenticated)
		return self.authenticated
	def is_active(self):
		return True
	def is_anonymous(self):
		return is_authenticated()
	def get_id(self):
		return str(self.user_id)

class Post(db.Model):
	post_id = db.Column(db.Integer, primary_key=True)
	url = db.Column(db.String(150))
	user = db.Column(db.String(100))
	gender = db.Column(db.String(50))
	description = db.Column(db.Text)
	created = db.Column(db.DateTime, default=db.func.current_timestamp())

	def __init__(self, user, url, gender, description):
		self.user = user
		self.url = url
		self.gender = gender
		self.description = description

	def __repr__(self):
		return "<Post %r at %r>" % (self.user, self.date)

@login_manager.user_loader
def load_user(user_id_string):
	return User.query.filter_by(user_id=int(user_id_string)).first()

@app.route("/")
def browse():
	# If logged in, root is browsing. Otherwise it's explanation.
	# Kinda like how Google Drive does it
	if current_user.is_authenticated:
		number_posts = 15;
		posts = Post.query.limit(15).all();
		return render_template("browse.html", posts=posts)
	else:
		return render_template("about.html")

# So you can still access about when logged in
@app.route("/about")
def about():
	return render_template("about.html")

@app.route("/login", methods=["get"])
def login_form():
	return render_template("login-form.html")

@app.route("/login", methods=["post"])
def login():
	user = User.query.filter_by(username=request.form["username"]).first()
	if user and user.login(request.form["password"]):
		return redirect("/")
	else:
		return render_template("no-login.html")

@app.route("/logout")
def logout():
	logout_user()
	return redirect("/")

@app.route("/submit", methods=["get"])
@login_required
def submission_page():
	return render_template("submit.html")

@app.route("/submit", methods=["post"])
@login_required
def submit_post():
	post = Post(
			current_user.username,
			request.form["url"],
			request.form["gender"],
			request.form["text"]
			)
	db.session.add(post)
	db.session.commit()
	return "You submitted."

@app.route("/why-links")
def why_links():
	return render_template("why-links.html")

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
