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
from wtforms import Form, StringField, PasswordField, TextAreaField, validators, ValidationError
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

### NON-ROUTE FUNCTIONS (library functions)

# Used in WTForms to validate captcha
def check_captcha(form, field):
	if not captcha.check(field.data):
		raise ValidationError("CAPTCHA is incorrect")

def username_unique(form, field):
	username = field.data
	if User.query.filter(User.username == username) is not None:
		raise ValidationError("Username is already taken")

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
		"votes": Vote.count_on_id
	}

### CLASSES

class Captcha_Manager():

	def bind_session(self):
		if not "captcha" in session:
			# Captcha manager's data has not yet been put on the session
			session["captcha"] = {}
			self.data = session["captcha"]
			self.data["answer"] = self.generate()
		else:
			# Reference self.data to the session for convenience
			self.data = session["captcha"]

	# Merely check if an answer matches the last given captcha
	def check(self, given_answer):
		self.bind_session()
		rv = False
		if self.data["answer"] == given_answer:
			rv = True
		self.generate()
		return rv

	# Generate a captcha, return ID (used in url) of image
	def generate(self):
		generator = SystemRandom()
		number_words = config.getint("Captcha", "num_words")
		phrase = " ".join([words[generator.randrange(len(words))] for i in range(number_words)])
		self.data["answer"] = phrase
		session.modified = True
		return self.data["answer"]

	def generate_image(self):
		self.bind_session()
		captcha_image = ImageCaptcha(fonts=[config.get("System", "font")])
		return send_file(captcha_image.generate(self.data["answer"]), mimetype="image/png")

# Singleton :( is good? TODO
captcha = Captcha_Manager()

class User(db.Model, UserMixin):
	user_id  = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(40), unique=True)
	password = db.Column(db.String(60))
	posts    = db.relationship("Post")
	comments = db.relationship("Comment")

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

	# @hybrid_method
	# def comment_karma(self):
	# 	return 0

class Post(db.Model):
	post_id     = db.Column(db.Integer, primary_key=True)
	url         = db.Column(db.String(150))
	gender      = db.Column(db.String(50))
	description = db.Column(db.Text)
	created     = db.Column(db.DateTime, default=db.func.current_timestamp())
	expires     = db.Column(db.DateTime)
	user_id     = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	user        = db.relationship("User", back_populates="posts")
	comments    = db.relationship("Comment", lazy="dynamic", cascade="all, delete")
	views       = db.relationship("View", lazy="dynamic", cascade="all, delete")

	def __init__(self, user_id, url, gender, description, days_to_expiration):
		self.user_id     = user_id
		self.url         = url
		self.gender      = gender
		self.description = description
		self.expires     = datetime.datetime.now() + datetime.timedelta(days = int(days_to_expiration))

	def __repr__(self):
		return "<Post %r by %r>" % (self.post_id, self.user.username)

	@classmethod
	def get_by_id(cls, post_id):
		post = cls.query.filter_by(post_id=int(post_id)).first()
		if post and post.expires > datetime.datetime.now():
			return post
		return None

	@classmethod
	def coolest(cls):
		# This is a SQL mess (TODO) to compute the following formula:
		# `commenting rep` + `post quality score` - `total upvotes on comments on all own posts` - `total upvotes on comments on this post`
		# This makes it so giving good feedback makes your post higher up,
		# new posts appear higher up,
		# and people who post often appear lower down (unless they comment more often)
		weights = {
			# post_quality is 1/2 as important as trad LD coolness
			"post_quality" : 1,
			"feedback_given" : 2,
			"feedback_received" : -1,
			# post_received's purpose is for when you have multiple posts
			"post_received" : -1,
		}
		labeled_user_posts = db.aliased(User.posts, name="user_posts")
		# The amount of positive feedback the poster has received
		user_post_comments_up = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Post.user, labeled_user_posts, labeled_user_posts.comments)
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "up"))
			.group_by(Post)
			.subquery())
		# The amount of positive feedback /this post/ has received
		post_comments_up = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Post.comments)
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "up"))
			.group_by(Post)
			.subquery())
		# The amount of /positive/ feedback the poster has given
		user_comments_up = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Post.user, User.comments)
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "up"))
			.group_by(Post)
			.subquery())
		# The amount of /negative/ feedback the poster has given
		user_comments_down = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Post.user, User.comments)
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "down"))
			.group_by(Post)
			.subquery())
		# The amount of positive post quality votes
		post_up = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Vote, (Vote.item_on_id == Post.post_id) & (Vote.vote_type == "post-quality") & (Vote.vote_value == "up"))
			.group_by(Post)
			.subquery())
		# The amount of negative post quality votes
		post_down = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Vote, (Vote.item_on_id == Post.post_id) & (Vote.vote_type == "post-quality") & (Vote.vote_value == "down"))
			.group_by(Post)
			.subquery())
		return (Post.query
			.join(user_post_comments_up, Post.post_id == user_post_comments_up.c.post_id)
			.join(post_comments_up, Post.post_id == post_comments_up.c.post_id)
			.join(user_comments_up, Post.post_id == user_comments_up.c.post_id)
			.join(user_comments_down, Post.post_id == user_comments_down.c.post_id)
			.join(post_up, Post.post_id == post_up.c.post_id)
			.join(post_down, Post.post_id == post_down.c.post_id)
			.order_by((
					+ weights["post_quality"] * (post_up.c.count - post_down.c.count)
					+ weights["feedback_given"] * (user_comments_up.c.count - user_comments_down.c.count)
					+ weights["feedback_received"] * user_post_comments_up.c.count
					+ weights["post_received"] * post_comments_up.c.count)
				.desc()))

class Comment(db.Model):
	comment_id = db.Column(db.Integer, primary_key=True)
	post_id    = db.Column(db.Integer, db.ForeignKey("post.post_id"))
	user_id    = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	created    = db.Column(db.DateTime, default=db.func.current_timestamp())
	text       = db.Column(db.Text)
	user       = db.relationship("User", back_populates="comments")

	def __init__(self, user_id, text):
		self.user_id = user_id
		self.text = text

	def __repr__(self):
		return "<Comment %r by %r>" % (self.item_on_id, self.user.username)

	@classmethod
	def get_by_id(cls, comment_id):
		comment = cls.query.filter_by(comment_id=int(comment_id)).first()
		# TODO: Check for expiration?
		return comment

class Vote(db.Model):
	# Though all other fields will never be the same, each one could be duplicate
	vote_id = db.Column(db.Integer, primary_key = True)
	vote_type = db.Column(db.Enum("comment-agree", "comment-quality", "post-passes", "post-quality"))
	item_on_id = db.Column(db.Integer) # It's a foreignkey but can't specify because could be from any class
	user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	vote_value = db.Column(db.Enum("up", "down", "maybe"))

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
		item_id = int(item_id)
		vote = cls.get(vote_type, item_id, current_user.user_id)
		rv = ""
		if vote:
			if vote.vote_value == vote_value:
				# Undoing a previously done vote
				db.session.delete(vote)
				rv = ("undo", vote_value)
			else:
				# A vote of another type was previously made
				# Send back the previous value
				rv = ("switch", vote.vote_value)
				# Modify its vote type
				vote.vote_value = vote_value
		else:
			vote = cls(vote_type, item_id, vote_value)
			db.session.add(vote)
			rv = ("vote", "")
		db.session.commit()
		return rv

	@classmethod
	def count_on_id(cls, item_id, vote_type, vote_value):
		query = cls.query.filter_by(item_on_id=item_id,
			vote_type=vote_type,
			vote_value=vote_value
			)
		return query.count()

	@classmethod
	def get_post_votes(cls, post_id):
		votes = db.session.query(Comment.comment_id, cls.vote_type, cls.vote_value)\
			.filter((cls.vote_type == "comment-quality") | (cls.vote_type == "comment-agree"))\
			.join(cls, cls.item_on_id == Comment.comment_id)\
			.filter(cls.user_id == current_user.user_id)\
			.filter(Comment.post_id == int(post_id))\
			.union_all(db.session.query(cls.item_on_id, cls.vote_type, cls.vote_value)
				.filter((cls.vote_type == "post-passes") | (cls.vote_type == "post-quality"))
				.join(Post, Post.post_id == cls.item_on_id)
				.filter(cls.user_id == current_user.user_id)\
				.filter(Post.post_id == int(post_id))
			).all()
		return votes

	@classmethod
	def comment_subq(cls, vote_type, vote_value):
		return (db.session.query(
				Comment.comment_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == vote_type) & (Vote.vote_value == vote_value))
			.group_by(Comment)
			.subquery())

class View(db.Model):
	view_id = db.Column(db.Integer, primary_key = True)
	user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	post_id = db.Column(db.Integer, db.ForeignKey("post.post_id"))
	post    = db.relationship("Post", back_populates="views")
	def __init__(self, user_id, post_id):
		self.user_id = user_id
		self.post_id = post_id
	def __repr__(self):
		return "<View %r by %r>" % (self.post_id, self.user_id)
	@classmethod
	def view(cls, post_id):
		entry = cls(current_user.user_id, post_id)
		db.session.add(entry)
		db.session.commit()


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
		validators.URL(),
		validators.Optional()
	], render_kw={"placeholder": "link"})
	gender = StringField("", [
	], render_kw={"placeholder": "target gender (optional)"})
	text = TextAreaField("", [
	], render_kw={"placeholder": "description / any additional text"})
	expires = StringField("days to expiration: ", [
	], render_kw={"placeholder": "days"}, default=30)
	captcha = StringField("", [
		check_captcha
	], render_kw={"placeholder": "enter the text above"})

class Registration_Form(Form):
	username = StringField("", [
		validators.DataRequired(),
		username_unique,
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = PasswordField("", [
		validators.DataRequired(),
		validators.Length(min=6, max=60)
	], render_kw={"placeholder": "password"})
	confirm = PasswordField("", [
		validators.EqualTo("password", "Check that the passwords match")
	], render_kw={"placeholder": "confirm password"})
	captcha = StringField("", [
		check_captcha
	], render_kw={"placeholder": "enter the text above"})

### ROUTES

@app.route("/")
@app.route("/browse")
def browse():
	# If logged in, root is browsing. Otherwise it's explanation.
	# Kinda like how Google Drive does it
	if current_user.is_authenticated:
		number_posts = 100;
		show_viewed = request.args.get("show-viewed")
		post_viewed = (db.session.query(
				Post.post_id,
				View.view_id)
			.join(View, (View.post_id == Post.post_id) & (View.user_id == current_user.user_id))
			.subquery())
		posts = (Post.coolest()
			.outerjoin(post_viewed, Post.post_id == post_viewed.c.post_id)
			.filter(post_viewed.c.view_id != None if show_viewed else post_viewed.c.view_id == None)
			.limit(number_posts).all())
		return render_template("browse.html", posts=posts, showing_viewed=show_viewed, is_more=len(posts)==number_posts)
	else:
		return about()

@app.route("/captcha")
def captcha_image():
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

@app.route("/post/<post_id>")
@login_required
def view_post(post_id):
	post = Post.get_by_id(post_id)
	if post:
		View.view(post_id)
		max_comments = 1000
		# We sort comments by (quality difference) + c * (agreement difference)
		# c: The percent as valuable agreement is to quality in the comment sorting algorithm
		agree_to_quality_factor = 1
		quality_up = Vote.comment_subq("comment-quality", "up")
		quality_down = Vote.comment_subq("comment-quality", "down")
		agree_up = Vote.comment_subq("comment-agree", "up")
		agree_down = Vote.comment_subq("comment-agree", "down")
		comments = (post.comments
			.join(quality_up, Comment.comment_id == quality_up.c.comment_id)
			.join(quality_down, Comment.comment_id == quality_down.c.comment_id)
			.join(agree_up, Comment.comment_id == agree_up.c.comment_id)
			.join(agree_down, Comment.comment_id == agree_down.c.comment_id)
			.order_by((agree_to_quality_factor * (agree_up.c.count - agree_down.c.count) + (quality_up.c.count - quality_down.c.count)).desc())
			.limit(max_comments).all())
		return render_template("post.html", post=post, comments=comments)
	else:
		return render_template("removed.html")

@app.route("/post/<post_id>/link")
@login_required
def view_link(post_id):
	post = Post.get_by_id(post_id)
	if post:
		return redirect(post.url)
	else:
		return render_template("removed.html")

@app.route("/post/<post_id>/comment", methods=["post"])
@login_required
def comment_on_post(post_id):
	post = Post.get_by_id(post_id)
	comment = Comment(current_user.user_id, request.form["comment"])
	post.comments.append(comment)
	db.session.commit()
	return redirect("/post/" + post_id)

@app.route("/post/<post_id>/delete")
@login_required
def delete_post(post_id):
	post = Post.get_by_id(post_id)
	if current_user.user_id == post.user_id:
		db.session.delete(post)
		db.session.commit()
		# TODO: Flash
		return redirect("/")
	else:
		# TODO: Better
		return "It appears you are not the owner of this post, or you are not logged in."

@app.route("/vote")
@login_required
def vote_on_post():
	item_id = request.args.get("id")
	vote_type = request.args.get("type")
	vote_value = request.args.get("value")
	action, previous = Vote.vote(vote_type, item_id, vote_value)
	rv = {}
	rv["id"] = item_id
	rv["type"] = vote_type
	rv["value"] = vote_value if action != "undo" else ""
	rv["performed"] = action
	rv["previous"] = previous
	return json.dumps(rv)

@app.route("/post/<post_id>/votes")
@login_required
def send_votes(post_id):
	votes = Vote.get_post_votes(post_id)
	rv = { "votes" : [] }
	for i, vote in enumerate(votes):
		vote_dict = {}
		rv["votes"].append(vote_dict)
		vote_dict["id"]    = vote[0]
		vote_dict["type"]  = vote[1]
		vote_dict["value"] = vote[2]
	return json.dumps(rv)

# So you can still access about when logged in
@app.route("/about")
def about():
	return render_template("about/index.html")

@app.route("/about/security")
def about_security():
	return render_template("about/security.html")

@app.route("/about/coolness")
def about_coolness():
	return render_template("about/coolness.html")

@app.route("/about/feedback")
def about_feedback():
	return render_template("about/feedback.html")

@app.route("/about/links")
def about_links():
	return render_template("about/links.html")

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
	form = Registration_Form(request.form)
	if request.method == "POST" and form.validate():
		user = User(form.username.data, form.password.data)
		db.session.add(user)
		db.session.commit()
		return redirect("/login")
	return render_template("register.html", form=form)

@app.route("/submit", methods=["get", "post"])
@login_required
def submission_page():
	form = Submit_Form(request.form)
	if request.method == "POST" and form.validate():
		post = Post(
				current_user.user_id,
				form.url.data,
				form.gender.data,
				form.text.data,
				form.expires.data
				)
		db.session.add(post)
		db.session.commit()
		return redirect("/post/" + str(post.post_id))
	return render_template("submit.html", form=form)

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
