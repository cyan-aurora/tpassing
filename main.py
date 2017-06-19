#!/usr/bin/env python3

# This is the main (and currently only) entry point of tpassing

### IMPORT AND SETUP

import sys

if sys.version_info < (3, 0):
	sys.stdout.write("Run with python 3 please. Are you in your virtualenv?")
	sys.exit(1)

import bcrypt
import logging
import configparser
import time
import datetime
import json
from functools import wraps
from random import SystemRandom

from captcha.image import ImageCaptcha

from flask import Flask, request, session, render_template, redirect, send_file, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from flask_principal import Principal, Identity, AnonymousIdentity, identity_changed, Permission, ActionNeed
from wtforms import Form, StringField, PasswordField, TextAreaField, validators
from flaskext.markdown import Markdown

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

Markdown(app)

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

	@classmethod
	def get_by_name(cls, name):
		user = User.query.filter_by(username=name).first()
		return user

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
	post_id     = db.Column(db.Integer, primary_key=True)
	url         = db.Column(db.String(150))
	user        = db.Column(db.String(100))
	gender      = db.Column(db.String(50))
	description = db.Column(db.Text)
	created     = db.Column(db.DateTime, default=db.func.current_timestamp())
	expires     = db.Column(db.DateTime)
	comments    = db.relationship("Comment", lazy="dynamic", cascade="all, delete")

	def __init__(self, user, url, gender, description, days_to_expiration):
		self.user        = user
		self.url         = url
		self.gender      = gender
		self.description = description
		self.expires     = datetime.datetime.now() + datetime.timedelta(days = int(days_to_expiration))

	def __repr__(self):
		return "<Post %r by %r>" % (self.post_id, self.user)

	@classmethod
	def get_by_id(cls, post_id):
		post = cls.query.filter_by(post_id=int(post_id)).first()
		if post and post.expires > datetime.datetime.now():
			return post
		return None

class Comment(db.Model):
	comment_id = db.Column(db.Integer, primary_key=True)
	post_id    = db.Column(db.Integer, db.ForeignKey("post.post_id"))
	user       = db.Column(db.String(100))
	created    = db.Column(db.DateTime, default=db.func.current_timestamp())
	text       = db.Column(db.Text)

	def __init__(self, user, text):
		self.user = user
		self.text = text

	def __repr__(self):
		return "<Comment %r by %r>" % (self.item_on_id, self.user)

	@classmethod
	def get_by_id(cls, comment_id):
		comment = cls.query.filter_by(comment_id=int(comment_id)).first()
		# TODO: Check for expiration?
		return comment

class Vote(db.Model):
	# Though all other fields will never be the same, each one could be duplicate
	vote_id = db.Column(db.Integer, primary_key = True)
	vote_type = db.Column(db.Enum("comment-agree", "comment-quality"))
	item_on_id = db.Column(db.Integer) # It's a foreignkey but can't specify because could be from any class
	user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	vote_value = db.Column(db.Enum("up", "down"))

	def __init__(self, vote_type, item_on_id, vote_value):
		self.vote_type    = vote_type
		self.item_on_id   = int(item_on_id)
		self.vote_value   = vote_value
		self.user_id      = int(current_user.user_id)

	def __repr__(self):
		return "<%r Vote on %r by %r>" % (self.vote_type, self.item_on_id, self.user_id)

	@classmethod
	def get(cls, vote_type, item_on_id, user_id):
		# A user can only have one vote_type on an item
		vote_query = cls.query.filter_by(
			vote_type=vote_type,
			item_on_id=int(item_on_id),
			user_id=int(user_id)
			)
		return vote_query.first() # Guaranteed to only be one

	@classmethod
	def vote(cls, vote_type, item_id, vote_value):
		vote = cls.get(vote_type, item_id, current_user.user_id)
		rv = ""
		if vote:
			if vote.vote_value == vote_value:
				# Undoing a previously done vote
				db.session.delete(vote)
				rv = "undo"
			else:
				# A vote of another type was previously made
				# Modify its vote type
				vote.vote_value = vote_value
				rv = "switch"
		else:
			vote = cls(vote_type, item_id, vote_value)
			db.session.add(vote)
			rv = "vote"
		db.session.commit()
		return rv

	@classmethod
	def count_on_comment(cls, comment, vote_type, vote_value):
		query = cls.query.filter_by(item_on_id=comment.comment_id,
			vote_type=vote_type,
			vote_value=vote_value
			)
		return query.count()

	@classmethod
	def get_post_comment_votes(cls, post_id, vote_type):
		votes = db.session.query(Comment.comment_id, cls.vote_type)\
			.join(cls, cls.item_on_id == Comment.comment_id)\
			.filter(cls.user_id == current_user.user_id)\
			.filter(Comment.post_id == int(post_id))\
			.filter(cls.vote_type == vote_type)\
			.all()
		return votes

class Login_Form(Form):
	username = StringField("", [
		validators.DataRequired(),
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = PasswordField("", [
		validators.DataRequired(),
		validators.Length(min=10, max=60)
	], render_kw={"placeholder": "password"})

class Submit_Form(Form):
	url = StringField("", [
		validators.URL()
	], render_kw={"placeholder": "link"})
	gender = StringField("", [
	], render_kw={"placeholder": "target gender (optional)"})
	text = TextAreaField("", [
	], render_kw={"placeholder": "description / any additional text"})
	expires = StringField("days to expiration: ", [
	], render_kw={"placeholder": "days"}, default=30)

class Registration_Form(Form):
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

def captcha_not_solved(to=None):
	if not to:
		to = request.path
	captcha_id = captcha.generate()
	return render_template("captcha.html", captcha_id=captcha_id, to=to)

@app.context_processor
def add_login_form():
	return { "login_form" : Login_Form(request.form) }

@login_manager.user_loader
def load_user(user_id_string):
	user = User.query.filter_by(user_id=int(user_id_string)).first()
	user.init_login()
	return user

@app.context_processor
def utility_processor():
	return {
		"comment_votes": Vote.count_on_comment
	}

### ROUTES

@app.route("/")
@app.route("/browse")
def browse():
	# If logged in, root is browsing. Otherwise it's explanation.
	# Kinda like how Google Drive does it
	if current_user.is_authenticated:
		number_posts = 15;
		posts = (Post.query
			.filter(Post.expires > datetime.datetime.now())
			.order_by(Post.created.desc())
			.limit(15).all())
		return render_template("browse.html", posts=posts)
	else:
		return about()

@app.route("/captcha/<captcha_id>")
def captcha_image(captcha_id):
	if captcha.valid_id(captcha_id):
		# Add headers to both force latest IE rendering engine or Chrome Frame
		# This is not for security. Security-wise caches are covered by
		# captcha_id. This just makes sure a cached image isn't shown when it's
		# been changed, for the user's experience
		# Thanks to https://arusahni.net/blog/2014/03/flask-nocache.html
		response = make_response(captcha.generate_image())
		response.headers['Last-Modified'] = datetime.datetime.now()
		response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
		response.headers['Pragma'] = 'no-cache'
		response.headers['Expires'] = '-1'
		return response
	else:
		return "tried to access an outdated captcha. should be " + str(session["captcha"]["image_id"]), 403

@app.route("/captcha/solve", methods=["post"])
def solve_captcha():
	if captcha.check(request.form["answer"]):
		return redirect(request.form["to"])
	else:
		return captcha_not_solved(request.form["to"])

@app.route("/post/<post_id>")
@login_required
@captcha_required
def view_post(post_id):
	post = Post.get_by_id(post_id)
	if post:
		comments = post.comments.limit(100).all()
		return render_template("post.html", post=post, comments=comments)
	else:
		return render_template("removed.html")

@app.route("/post/<post_id>/link")
@login_required
@captcha_required
def view_link(post_id):
	post = Post.get_by_id(post_id)
	if post:
		return redirect(post.url)
	else:
		return render_template("removed.html")

@app.route("/post/<post_id>/comment", methods=["post"])
@login_required
@captcha_required
def comment_on_post(post_id):
	post = Post.get_by_id(post_id)
	comment = Comment(current_user.username, request.form["comment"])
	post.comments.append(comment)
	db.session.commit()
	return redirect("/post/" + post_id)

@app.route("/post/<post_id>/delete")
@login_required
@captcha_required
def delete_post(post_id):
	post = Post.get_by_id(post_id)
	if current_user.username == post.user:
		db.session.delete(post)
		db.session.commit()
		# TODO: Flash
		return redirect("/")
	else:
		# TODO: Better
		return "It appears you are not the owner of this post, or you are not logged in."

@app.route("/comment/<comment_id>/vote")
@login_required
def vote_on_comment(comment_id):
	vote_value = request.args.get("vote")
	rv = {}
	vote_type = "comment-" + request.args.get("type")
	rv["performed"] = Vote.vote(vote_type, comment_id, vote_value)
	return json.dumps(rv)

@app.route("/post/<post_id>/comments/votes")
@login_required
def send_comment_votes(post_id):
	rv = {
		"agreement_votes" : Vote.get_post_comment_votes(post_id, "comment-agree"),
		"quality_votes" : Vote.get_post_comment_votes(post_id, "comment-quality")
		}
	print(rv)
	for vote_class, votes in rv.items():
		for i, vote in enumerate(votes):
			vote_dict = {}
			rv[vote_class][i] = vote_dict
			vote_dict["comment_id"] = vote[0]
			vote_dict["type"] = vote[1]
	return json.dumps(rv)

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
	form = Registration_Form(request.form)
	if request.method == "POST" and form.validate():
		user = User(form.username.data, form.password.data)
		db.session.add(user)
		db.session.commit()
		return redirect("/login")
	return render_template("register.html", form=form)

@app.route("/submit", methods=["get", "post"])
@login_required
@captcha_required
def submission_page():
	form = Submit_Form(request.form)
	if request.method == "POST" and form.validate():
		post = Post(
				current_user.username,
				form.url.data,
				form.gender.data,
				form.text.data,
				form.expires.data
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
