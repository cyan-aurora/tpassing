#!/usr/bin/env python3

# This is the main (and currently only) entry point of tpassing

### IMPORT AND SETUP

import sys

if sys.version_info < (3, 0):
	sys.stdout.write("Run with python 3 please.")
	sys.exit(1)

import bcrypt
import logging
import configparser
import time
import datetime
from functools import wraps
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

### CLASSES

class CaptchaManager():

	def bind_session(self):
		if not "captcha" in session:
			# Captcha manager's data has not yet been put on the session
			session["captcha"] = {}
			self.data = session["captcha"]
			self.data["last_needed"] = 0
			self.data["solved"] = False
			self.data["image_id"] = 0
			self.data["answer"] = ""
			self.data["number_needed"] = 0
		else:
			# Reference self.data to the session for convenience
			self.data = session["captcha"]

	# Check if there has been a recent enough request to warrant requesting a captcha
	# Only needed() calls are counted as bona fide requests
	def needed(self):
		self.bind_session()
		if self.data["solved"]:
			# A captcha has been solved and not been used yet
			self.data["solved"] = False
			session.modified = True
			return False
		if self.data["last_needed"] == 0:
			self.data["last_needed"] = time.time()
			return True
		self.data["number_needed"] += 1
		session.modified = True
		captcha_base_time = config.getint("Captcha", "base_wait_time")
		captcha_time = captcha_base_time * 2 ** self.data["number_needed"]
		if time.time() < self.data["last_needed"] + captcha_time:
			# The last request was too recent, require a captcha
			return True
		self.data["last_needed"] = time.time() # It counts as a "solution" to not need it
		session.modified = True
		return False

	# Merely check if an answer matches the last given captcha
	def check(self, given_answer):
		self.bind_session()
		if self.data["answer"] == given_answer:
			# Since they could just refresh their session every time anyway, we make the users lives easier
			self.data["number_needed"] = 0
			self.data["solved"] = True
			session.modified = True
			return True
		return False

	# Generate a captcha, return ID (used in url) of image
	def generate(self):
		generator = SystemRandom()
		number_words = config.getint("Captcha", "num_words")
		phrase = " ".join([words[generator.randrange(len(words))] for i in range(number_words)])
		self.data["answer"] = phrase
		# These don't need to be cryptographically secure
		# In order to make sure your browser doesn't cache the image, a new request is made each time, with a new id
		unique_ids = config.getint("Captcha", "num_image_ids")
		self.data["image_id"] = generator.randrange(unique_ids)
		session.modified = True
		return self.data["image_id"]

	def generate_image(self):
		captcha = ImageCaptcha(fonts=[config.get("System", "font")])
		return send_file(captcha.generate(self.data["answer"]), mimetype="image/png")

	def valid_id(self, given_id):
		return self.data["image_id"] == int(given_id)

# Singleton :( is good? TODO
captcha = CaptchaManager()

class User(db.Model, UserMixin):
	user_id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(40), unique=True)
	password = db.Column(db.String(60))

	def __init__(self, username, password):
		self.username = username.encode("utf-8")
		self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

	def __repr__(self):
		return "<User %r>" % self.username

	def init_login(self):
		pass # TODO: Remove?

	# Flask login interface
	def login(self, given_password):
		given_password = given_password.encode("utf-8")
		correct_hash = self.password.encode("utf-8")
		if correct_hash and bcrypt.checkpw(given_password, correct_hash):
			login_user(self)
			identity_changed.send(current_app._get_current_object(), identity=Identity(self.user_id))
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

### NON-ROUTE FUNCTIONS (library functions)

# Use the decorator @captcha_required on routes to require a captcha when neccessary
def captcha_required(route):
	@wraps(route)
	def check_captcha(*args, **kwargs):
		if not captcha.needed():
			return route(*args, **kwargs)
		else:
			return captcha_not_solved()
	return check_captcha

def captcha_not_solved():
	to = request.path
	captcha_id = captcha.generate()
	return render_template("captcha.html", captcha_id=captcha_id, to=to)

def get_post(post_id):
	return Post.query.filter_by(post_id=int(post_id)).first()

@app.context_processor
def add_login_form():
	return { "login_form" : LoginForm(request.form) }

@login_manager.user_loader
def load_user(user_id_string):
	user = User.query.filter_by(user_id=int(user_id_string)).first()
	user.init_login()
	return user

### ROUTES

@app.route("/")
@app.route("/browse")
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
def captcha_image(captcha_id):
	if captcha.valid_id(captcha_id):
		return captcha.generate_image()
	else:
		return "tried to access an outdated captcha. should be " + str(session["captcha"]["image_id"]), 403

@app.route("/captcha/solve", methods=["post"])
def solve_captcha():
	if captcha.check(request.form["answer"]):
		return redirect(request.form["to"])
	else:
		return "you didn't get it right buddy"
		return captcha_not_solved()

@app.route("/post/<post_id>")
@login_required
@captcha_required
def view_post(post_id):
	post = get_post(post_id)
	created = post.created
	return render_template("post.html", post=post)

@app.route("/post/<post_id>/link")
@login_required
@captcha_required
def view_link(post_id):
	post = get_post(post_id)
	return redirect(post.url)

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
@captcha_required
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

@app.route("/debug")
def debug_page():
	if app.debug:
		debug = {
				"captcha data" : captcha.data,
				"current time" : time.time()
				}
		return render_template("debug.html", display=debug)
	else:
		return "nice try. not available inprod."

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=True)
