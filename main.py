#!/usr/bin/env python3

import sys

if sys.version_info < (3, 0):
	sys.stdout.write("Run with python 3 please.")
	sys.exit(1)

import bcrypt
import logging
import configparser
import datetime
from random import SystemRandom

from captcha.image import ImageCaptcha

from flask import Flask, request, session, render_template, redirect, send_file, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from flask_principal import Principal, Identity, AnonymousIdentity, identity_changed, Permission, ActionNeed
from wtforms import Form, StringField, PasswordField, TextAreaField, validators

secure_config = configparser.ConfigParser()
secure_config.read("secure.ini")
config = configparser.ConfigParser()
config.read("config.ini")

app = Flask(__name__)
app.config["SECRET_KEY"] = secure_config.get("Flask", "secret_key")

mysql_password = secure_config.get("SQL", "password")
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:" + mysql_password + "@localhost/transpassing"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

words = open("captcha-words.txt").read().splitlines()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
	user_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(40), unique=True)
	password = db.Column(db.String(60))

	def __init__(self, username, password):
		self.username = username.encode("utf-8")
		self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

	def __repr__(self):
		return "<User %r>" % self.username

	# Flask login interface
	def login(self, given_password):
		given_password = given_password.encode("utf-8")
		correct_hash = self.password.encode("utf-8")
		if correct_hash and bcrypt.checkpw(given_password, correct_hash):
			login_user(self)
			identity_changed.send(current_app._get_current_object(), identity=Identity(self.user_id))
			return True
		return False
	def generate_captcha(self):
		generator = SystemRandom()
		number_words = 1
		phrase = " ".join([words[generator.randrange(len(words))] for i in range(number_words)])
		session["captcha_answer"] = phrase
		# These don't need to be cryptographically secure, they're just to prevent you guess at the same one over and over
		unique_ids = 200
		session["captcha_id"] = generator.randrange(unique_ids)
		return session["captcha_id"]
	def check_captcha(self, given_answer):
		if given_answer == session["captcha_answer"]:
			session["solved_captcha"] = True
			return True
		return False
	def get_id(self):
		return str(self.user_id)

class Post(db.Model):
	post_id     = db.Column(db.Integer, primary_key = True)
	url         = db.Column(db.String(150))
	user        = db.Column(db.String(100))
	gender      = db.Column(db.String(50))
	description = db.Column(db.Text)
	created     = db.Column(db.DateTime, default = db.func.current_timestamp())
	expires     = db.Column(db.Interval, default = datetime.timedelta(30))

	def __init__(self, user, url, gender, description, expires):
		self.user = user
		self.url = url
		self.gender = gender
		self.description = description
		if expires:
			self.expires = datetime.timedelta(int(expires))

	def __repr__(self):
		return "<Post %r at %r>" % (self.user, self.date)

class LoginForm(Form):
	username = StringField("", [
		validators.DataRequired(),
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = PasswordField("", [
		validators.DataRequired(),
		validators.Length(min=6, max=60)
	], render_kw={"placeholder": "password"})

class SubmitForm(Form):
	url = StringField("", [
		validators.URL()
	], render_kw={"placeholder": "link"})
	gender = StringField("", [
	], render_kw={"placeholder": "target gender (optional)"})
	text = TextAreaField("", [
	], render_kw={"placeholder": "description / any additional text"})

class RegistrationForm(Form):
	username = StringField("", [
		validators.DataRequired(),
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = PasswordField("", [
		validators.DataRequired(),
		validators.Length(min=6, max=60)
	], render_kw={"placeholder": "password"})
	confirm = PasswordField("", [
		validators.EqualTo("password", "Check that the passwords match")
	], render_kw={"placeholder": "confirm password"})

@app.context_processor
def add_login_form():
	return { "login_form" : LoginForm(request.form) }

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
		return about()

@app.route("/captcha/<captcha_id>")
@login_required
def captcha_image(captcha_id):
	if int(session["captcha_id"]) == int(captcha_id):
		# Should exist on nearly any server but is weird enough to not be pre-trained
		captcha = ImageCaptcha(fonts=[config.get("System", "font")])
		return send_file(captcha.generate(session["captcha_answer"]), mimetype="image/png")
	else:
		return "tried to access an outdated captcha. should have accessed " + str(session["captcha_id"]), 403

@app.route("/captcha/solve", methods=["post"])
@login_required
def solve_captcha():
	if current_user.check_captcha(request.form["answer"]):
		return redirect(request.form["to"])
	else:
		captcha_id = current_user.generate_captcha()
		return render_template("captcha.html", captcha_id=captcha_id, to=request.form["to"])

@app.route("/post/<post_id>")
@login_required
def view_post(post_id):
	if "solved_captcha" in session and session["solved_captcha"]:
		post = Post.query.filter_by(post_id=int(post_id)).first()
		return render_template("post.html", post=post)
	else:
		return captcha_not_solved(post_id)

@app.route("/post/<post_id>/link")
@login_required
def view_link(post_id):
	if "solved_captcha" in session and session["solved_captcha"]:
		post = Post.query.filter_by(post_id=int(post_id)).first()
		return redirect(post.url)
	else:
		return captcha_not_solved(post_id)

@app.route("/post/<post_id>")
@app.route("/post/<post_id>/link")
@login_required
def captcha_not_solved(post_id):
	to = request.path
	captcha_id = current_user.generate_captcha()
	return render_template("captcha.html", captcha_id=captcha_id, to=to)

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

	# Flask-Login logout
	logout_user()

	# Flask-Principal logout
	for key in ("identity.name", "identity.auth_type"):
		session.pop(key, None)

	# About / unsigned-in page
	return redirect("/")

@app.route("/register", methods=["get", "post"])
def register_page():
	form = RegistrationForm(request.form)
	if request.method == "POST" and form.validate():
		user = User(form.username.data, form.password.data)
		db.session.add(user)
		db.session.commit()
		return redirect("/login")
	return render_template("register.html", form=form)

@app.route("/submit", methods=["get", "post"])
@login_required
def submission_page():
	form = SubmitForm(request.form)
	if request.method == "POST" and form.validate():
		post = Post(
				current_user.username,
				form.url.data,
				form.gender.data,
				form.text.data
				)
		db.session.add(post)
		db.session.commit()
		return redirect("/post/" + str(post.post_id))
	return render_template("submit.html", form=form)

@app.route("/why-links")
def why_links():
	return render_template("why-links.html")

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=True)
