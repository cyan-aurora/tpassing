#!/usr/bin/env python3

# This is the main (and currently only) entry point of tpassing

### IMPORT AND SETUP

from os import getenv
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
from urllib.parse import urlparse, urljoin

from captcha.image import ImageCaptcha

import flask
from flask import Flask, request, session, render_template, redirect, send_file, make_response, current_app, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from flask_principal import Principal, Identity, AnonymousIdentity, identity_changed, Permission, ActionNeed
from flask_moment import Moment
from flask_sslify import SSLify
from wtforms import Form, validators, ValidationError
import wtforms
from flaskext.markdown import Markdown

secure_config = configparser.ConfigParser()
secure_config.read("secure.ini")
config = configparser.ConfigParser()
config.read("config.ini")

app = Flask(__name__)
app.config["SECRET_KEY"] = secure_config.get("Flask", "secret_key")

sslify = SSLify(app, permanent=True)

mysql_password = secure_config.get("SQL", "password")
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:" + mysql_password + "@localhost/transpassing"
if getenv("GAE_SERVICE"): # Using GAE
	mysql_address = "/cloudsql/" + secure_config.get("SQL", "gae_connection_name")
	mysql_password = secure_config.get("SQL", "gae_password")
	app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:" + mysql_password + "@/transpassing?unix_socket=" + mysql_address
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

words = open("captcha-words.txt").read().splitlines()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

Markdown(app)

moment = Moment(app)

### NON-ROUTE FUNCTIONS (library functions)

# Used in WTForms to validate captcha
def check_captcha(form, field):
	if not captcha.check(field.data):
		raise ValidationError("CAPTCHA is incorrect")

def username_unique(form, field):
	username = field.data
	if User.query.filter(User.username == username).first() is not None:
		raise ValidationError("Username is already taken")

def is_safe_url(target):
	ref_url = urlparse(request.host_url)
	test_url = urlparse(urljoin(request.host_url, target))
	return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc

def is_trusted_user():
	# Requiring trust means we've provided constructive feedback, or a positive post
	feedback_up = (db.session.query(
			db.func.count(Vote.vote_id).label("count"))
		.filter(User.user_id == current_user.user_id)
		.outerjoin(User.comments)
		.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "up"))
		).first().count
	feedback_down = (db.session.query(
			db.func.count(Vote.vote_id).label("count"))
		.filter(User.user_id == current_user.user_id)
		.outerjoin(User.comments)
		.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == "comment-quality") & (Vote.vote_value == "down"))
		).first().count
	posts_up = (db.session.query(
			db.func.count(Vote.vote_id).label("count"))
		.filter(User.user_id == current_user.user_id)
		.outerjoin(User.posts)
		.outerjoin(Vote, (Vote.item_on_id == Post.post_id) & (Vote.vote_type == "post-quality") & (Vote.vote_value == "up"))
		).first().count
	posts_down = (db.session.query(
			db.func.count(Vote.vote_id).label("count"))
		.filter(User.user_id == current_user.user_id)
		.outerjoin(User.posts)
		.outerjoin(Vote, (Vote.item_on_id == Post.post_id) & (Vote.vote_type == "post-quality") & (Vote.vote_value == "down"))
		).first().count
	feedback_required = config.getint("Trust", "feedback_margin_required")
	posts_required = config.getint("Trust", "post_margin_required")
	if feedback_up - feedback_down >= feedback_required or posts_up - posts_down >= posts_required:
		# We're good, move on to the next confirmation step
		return True
	else:
		return False

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
		captcha_image = ImageCaptcha(fonts=[config.get("Captcha", "font")])
		return send_file(captcha_image.generate(self.data["answer"]), mimetype="image/png")

# Singleton :( is good? TODO
captcha = Captcha_Manager()

class User(db.Model, UserMixin):
	user_id        = db.Column(db.Integer, primary_key=True)
	username       = db.Column(db.String(40), unique=True)
	password       = db.Column(db.String(60))
	posts          = db.relationship("Post")
	comments       = db.relationship("Comment")
	email          = db.Column(db.String(40))
	updates        = db.Column(db.Boolean)
	password_reset = db.Column(db.Integer)

	def __init__(self, username, password):
		self.username = username.encode("utf-8")
		self.password = self.hash_password(password)

	def __repr__(self):
		return "<User %r>" % self.username

	@classmethod
	def get_by_name(cls, name):
		user = User.query.filter_by(username=name).first()
		return user

	@classmethod
	def get_by_reset_token(cls, token):
		user = User.query.filter_by(password_reset=int(token)).first()
		return user

	@classmethod
	def hash_password(self, password):
		return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

	def init_login(self):
		pass # TODO: Remove?

	# Flask login interface
	def login(self, given_password, remember):
		if self.correct_password(given_password):
			login_user(self, remember=remember)
			# TODO: Isn't this outdated / unused??
			identity_changed.send(current_app._get_current_object(), identity=Identity(self.user_id))
			return True
		return False

	def correct_password(self, given_password):
		given_password = given_password.encode("utf-8")
		correct_hash = self.password.encode("utf-8")
		if correct_hash and bcrypt.checkpw(given_password, correct_hash):
			return True
		return False

	def get_id(self):
		return str(self.user_id)

	@classmethod
	def full_login(self, given_username, given_password, remember):
		user = User.query.filter_by(username=given_username).first()
		if user and user.login(given_password, remember):
			return True
		return False

	# @hybrid_method
	# def comment_karma(self):
	# 	return 0

class Post(db.Model):
	post_id         = db.Column(db.Integer, primary_key=True)
	url             = db.Column(db.String(150))
	gender          = db.Column(db.String(50))
	description     = db.Column(db.Text)
	created         = db.Column(db.DateTime, default=db.func.current_timestamp())
	expires         = db.Column(db.DateTime)
	allow_age       = db.Column(db.Boolean, default=False)
	require_captcha = db.Column(db.Boolean, default=False)
	require_trust   = db.Column(db.Boolean, default=False)
	user_id         = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	user            = db.relationship("User", back_populates="posts")
	comments        = db.relationship("Comment", lazy="dynamic", cascade="all, delete-orphan")
	views           = db.relationship("View", lazy="dynamic", cascade="all, delete-orphan")

	def __init__(self, user_id, url, gender, description, expires, allow_age, require_captcha, require_trust):
		self.user_id         = user_id
		self.url             = url
		self.gender          = gender
		self.description     = description
		self.expires         = expires
		self.allow_age       = allow_age
		self.require_captcha = require_captcha
		self.require_trust   = require_trust

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
		# The amount of passing votes the post has received, regardless of value
		post_passing_votes = (
			db.session.query(
				Post.post_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Vote, (Vote.item_on_id == Post.post_id) & (Vote.vote_type == "post-passes"))
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
			.filter(Post.expires > datetime.datetime.now())
			.join(user_post_comments_up, Post.post_id == user_post_comments_up.c.post_id)
			.join(post_comments_up, Post.post_id == post_comments_up.c.post_id)
			.join(user_comments_up, Post.post_id == user_comments_up.c.post_id)
			.join(user_comments_down, Post.post_id == user_comments_down.c.post_id)
			.join(post_passing_votes, Post.post_id == post_passing_votes.c.post_id)
			.join(post_up, Post.post_id == post_up.c.post_id)
			.join(post_down, Post.post_id == post_down.c.post_id)
			.order_by((
					+ config.getfloat("Coolness", "post_quality")          * (post_up.c.count - post_down.c.count)
					+ config.getfloat("Coolness", "feedback_given")        * (user_comments_up.c.count - user_comments_down.c.count)
					+ config.getfloat("Coolness", "feedback_received")     * user_post_comments_up.c.count
					+ config.getfloat("Coolness", "post_passing_received") * post_passing_votes.c.count
					+ config.getfloat("Coolness", "post_received")         * post_comments_up.c.count)
				.desc()))

class Comment(db.Model):
	comment_id = db.Column(db.Integer, primary_key=True)
	post_id    = db.Column(db.Integer, db.ForeignKey("post.post_id", ondelete="CASCADE"))
	user_id    = db.Column(db.Integer, db.ForeignKey("user.user_id", ondelete="CASCADE"))
	created    = db.Column(db.DateTime, default=db.func.current_timestamp())
	text       = db.Column(db.Text)
	user       = db.relationship("User", back_populates="comments")
	post       = db.relationship("Post", back_populates="comments")

	def __init__(self, user_id, text):
		self.user_id = user_id
		self.text = text

	def __repr__(self):
		return "<Comment %r by %r>" % (self.item_on_id, self.user.username)

	@classmethod
	def get_by_id(cls, comment_id):
		comment = cls.query.filter_by(comment_id=int(comment_id)).first()
		return comment

class Vote(db.Model):
	# Though all other fields will never be the same, each one could be duplicate
	vote_id = db.Column(db.Integer, primary_key=True)
	vote_type = db.Column(db.Enum("comment-agree", "comment-quality", "post-passes", "post-quality", "age"))
	item_on_id = db.Column(db.Integer) # It's a foreignkey but can't specify because could be from any class
	user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
	vote_value = db.Column(db.Enum("up", "down", "maybe", "age"))
	vote_age = db.Column(db.Integer)

	def __init__(self, vote_type, item_on_id, vote_value, vote_age=0):
		self.vote_type    = vote_type
		self.item_on_id   = int(item_on_id)
		self.vote_value   = vote_value
		self.user_id      = int(current_user.user_id)
		self.vote_age     = int(vote_age)

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
	def vote(cls, vote_type, item_id, vote_value, vote_age=0):
		item_id = int(item_id)
		vote_age = int(vote_age)
		vote = cls.get(vote_type, item_id, current_user.user_id)
		rv = ""
		if vote:
			if vote.vote_value == vote_value and vote_age == 0:
				# Undoing a previously done vote
				db.session.delete(vote)
				rv = ("undo", vote_value)
			else:
				# A vote of another type was previously made
				# Send back the previous value
				previous = vote.vote_value
				# If it's an age, we send the age instead
				if vote.vote_type == "age":
					previous = vote.vote_age
				rv = ("switch", previous)
				# Modify the vote
				vote.vote_value = vote_value
				vote.vote_age = vote_age
		else:
			vote = cls(vote_type, item_id, vote_value, vote_age)
			db.session.add(vote)
			rv = ("vote", "")
		db.session.commit()
		return rv

	@classmethod
	def count_on_id(cls, item_id, vote_type, vote_value=0):
		if vote_type == "age":
			rv = cls.get_median_age(item_id)
		else:
			rv = cls.query.filter_by(item_on_id=item_id,
				vote_type=vote_type,
				vote_value=vote_value
				).count()
		return rv

	@classmethod
	def get_post_votes(cls, post_id):
		votes = db.session.query(Comment.comment_id, cls.vote_type, cls.vote_value)\
			.filter((cls.vote_type == "comment-quality") | (cls.vote_type == "comment-agree"))\
			.join(cls, cls.item_on_id == Comment.comment_id)\
			.filter(cls.user_id == current_user.user_id)\
			.filter(Comment.post_id == int(post_id))\
			.union_all(db.session.query(cls.item_on_id, cls.vote_type, cls.vote_value)
				.filter((cls.vote_type == "post-passes") | (cls.vote_type == "post-quality") | (cls.vote_type == "age"))
				.join(Post, Post.post_id == cls.item_on_id)
				.filter(cls.user_id == current_user.user_id)\
				.filter(Post.post_id == int(post_id))
			).all()
		return votes

	@classmethod
	def get_age_vote(cls, post_id):
		vote = (db.session.query(cls.vote_age)
			.filter_by(user_id=current_user.user_id, item_on_id=post_id, vote_type="age")
			.first())
		if vote:
			return vote[0]
		else:
			return None

	@classmethod
	def get_average_age(cls, post_id):
		votes = (db.session.query(db.func.avg(cls.vote_age))
			.filter(cls.vote_type == "age")
			.filter(cls.item_on_id == int(post_id))
			).first()
		return int(votes[0])

	@classmethod
	def get_median_age(cls, post_id):
		count = cls.query.filter_by(vote_type="age", item_on_id=int(post_id)).count()
		votes = (db.session.query(cls.vote_age)
			.filter_by(vote_type="age", item_on_id=int(post_id))
			.order_by(cls.vote_age)
			).limit(int(count/2)+1).all()
		if count > 0:
			return votes[int(count/2)][0]
		else:
			return 0

	@classmethod
	def comment_subq(cls, vote_type, vote_value):
		return (db.session.query(
				Comment.comment_id,
				db.func.count(Vote.vote_id).label("count"))
			.outerjoin(Vote, (Vote.item_on_id == Comment.comment_id) & (Vote.vote_type == vote_type) & (Vote.vote_value == vote_value))
			.group_by(Comment)
			.subquery())

class View(db.Model):
	view_id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey("user.user_id", ondelete="CASCADE"))
	post_id = db.Column(db.Integer, db.ForeignKey("post.post_id", ondelete="CASCADE"))
	post    = db.relationship("Post", back_populates="views")
	def __init__(self, user_id, post_id):
		self.user_id = user_id
		self.post_id = post_id
	def __repr__(self):
		return "<View %r by %r>" % (self.post_id, self.user_id)
	@classmethod
	def get(cls, post_id):
		view_query = cls.query.filter_by(
			user_id = current_user.user_id,
			post_id = post_id)
		return view_query.first()
	@classmethod
	def view(cls, post_id):
		view = cls.get(post_id)
		if view:
			return True
		else:
			entry = cls(current_user.user_id, post_id)
			db.session.add(entry)
			db.session.commit()
			return False


class Login_Form(Form):
	username = wtforms.StringField("", [
		validators.DataRequired(),
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = wtforms.PasswordField("", [
		validators.DataRequired(),
		# We allow minimum 6 in the login form because we previously allowed
		# password of 6 length in registration
		validators.Length(min=6, max=60)
	], render_kw={"placeholder": "password"})
	remember = wtforms.BooleanField("remember me")

class Submit_Form(Form):
	url = wtforms.StringField("", [
		validators.URL(),
		validators.Optional()
	], render_kw={"placeholder": "link (optional)"})
	gender = wtforms.StringField("", [
	], render_kw={"placeholder": "target gender (optional)"})
	description = wtforms.TextAreaField("", [
	], render_kw={"placeholder": "description / any additional text (optional)"})
	expires = wtforms.StringField("days to expiration:", [
	], render_kw={"placeholder": "days"}, default=30)
	expires_date = wtforms.DateField("expiration date:")
	disable_age = wtforms.BooleanField("do not allow users to vote on my apparent age")
	require_captcha = wtforms.BooleanField("require a captcha to view this post (prevent robots from accessing)")
	require_trust = wtforms.BooleanField("require an upvoted post or comment to view this post (prevent trolls from accessing)")

class Register_Form(Form):
	username = wtforms.StringField("", [
		validators.DataRequired(),
		username_unique,
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "username"})
	password = wtforms.PasswordField("", [
		validators.DataRequired(),
		validators.Length(min=8, max=200)
	], render_kw={"placeholder": "password"})
	confirm = wtforms.PasswordField("", [
		validators.EqualTo("password", "Check that the passwords match")
	], render_kw={"placeholder": "confirm password"})
	email = wtforms.StringField("", [
		validators.Email(),
		validators.Length(min=4, max=40),
		validators.Optional()
	], render_kw={"placeholder": "email (optional)"})
	updates = wtforms.BooleanField("recieve an update when a post is made or i get feedback (never more than weekly)")
	captcha = wtforms.StringField("", [
		check_captcha
	], render_kw={"placeholder": "enter the text above"})

class Password_Reset_Form(Register_Form):
	# Username NOT required to be unique (shouldn't be)
	username = wtforms.StringField("", [
		validators.DataRequired(),
		validators.Length(min=1, max=99)
	], render_kw={"placeholder": "existing account username"})

class Settings_Form(Form):
	email = wtforms.StringField("", [
		validators.Email(),
		validators.Length(min=4, max=40),
		validators.Optional()
	], render_kw={"placeholder": "email (optional)"})
	updates = wtforms.BooleanField("recieve an update when a post is made or i get feedback (never more than weekly)")

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

@app.route("/me", methods=["get", "post"])
@login_required
def self_page():
	form = Settings_Form(request.form, obj=current_user)
	if request.method == "POST" and form.validate():
		current_user.email = form.email.data
		current_user.updates = form.updates.data
		db.session.commit()
		flash("settings updates successfully")
	return render_template("user.html", form=form)

@app.route("/user/<user_id>")
@login_required
def user_page(user_id):
	user=User.query.filter_by(user_id=int(user_id)).first()
	return render_template("user.html", user=user)

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

@app.route("/post/<post_id>", methods=["get", "post"])
@login_required
def view_post(post_id):
	post = Post.get_by_id(post_id)
	if post:
		been_viewed = View.get(post_id)
		# If we require trust, and this isn't our post, we check
		if post.require_trust and not been_viewed and post.user_id != current_user.user_id:
			if is_trusted_user():
				pass
			else:
				flash("sorry, but this poster has requested that only users with an upvoted post or comment see their post")
				return redirect("/browse")
		# If we require a captcha, and we've not already solved one, we check
		if post.require_captcha and not been_viewed:
			if request.method == "POST":
				if captcha.check(request.form["answer"]):
					# Continue on with the post-getting process
					pass
				else:
					flash("sorry, the captcha answer was incorrect")
					return render_template("captcha.html")
			else:
				return render_template("captcha.html")
		if not been_viewed:
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

@app.route("/post/<post_id>/edit", methods=["get", "post"])
@login_required
def edit_post(post_id):
	post = Post.get_by_id(post_id)
	if post.user_id != current_user.user_id:
		flash("it appears you are not the owner of this post, or you are not logged in")
		return redirect("/post/" + str(post_id))
	form = Submit_Form(request.form, obj=post)
	if request.method == "POST" and form.validate():
		post.__init__(
			current_user.user_id,
			form.url.data,
			form.gender.data,
			form.description.data,
			form.expires_date.data,
			not form.disable_age.data,
			form.require_captcha.data,
			form.require_trust.data,
		)
		db.session.commit()
		flash("post edited successfully")
		return redirect("/post/" + str(post.post_id))
	else:
		# We use the date rather than relative for UX
		form.expires_date.data = post.expires
		form.disable_age.data = not post.allow_age
		return render_template("submit.html", form=form, edit=True)


@app.route("/post/<post_id>/link", methods=["get", "post"])
@login_required
def view_link(post_id):
	post = Post.get_by_id(post_id)
	if post:
		been_viewed = View.get(post_id)
		# If we require trust, and this isn't our post, we check
		if post.require_trust and not been_viewed and post.user_id != current_user.user_id:
			if is_trusted_user():
				pass
			else:
				flash("sorry, but this poster has requested that only users with an upvoted post or comment see their post")
				return redirect("/browse")
		# If we require a captcha, and we've not already solved one, we check
		if post.require_captcha and not been_viewed:
			if request.method == "POST":
				if captcha.check(request.form["answer"]):
					# Continue on with the post-getting process
					pass
				else:
					flash("sorry, the captcha answer was incorrect")
					return render_template("captcha.html")
			else:
				return render_template("captcha.html")
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
		flash("the post was deleted successfully")
		return redirect("/")
	else:
		flash("it appears you are not the owner of this post, or you are not logged in")
		return redirect("/post/" + str(post_id))

@app.route("/comment/<comment_id>/delete")
@login_required
def delete_comment(comment_id):
	comment = Comment.get_by_id(comment_id)
	post_url = "/post/" + str(comment.post.post_id)
	if current_user.user_id == comment.user_id:
		db.session.delete(comment)
		db.session.commit()
		flash("the comment was deleted successfully")
		return redirect(post_url)
	else:
		flash("it appears you are not the owner of this comment, or you are not logged in")
		return redirect(post_url)

@app.route("/comment/<comment_id>/edit", methods=["post"])
@login_required
def edit_comment(comment_id):
	comment = Comment.get_by_id(comment_id)
	if comment.user_id != current_user.user_id:
		flash("it appears you are not the owner of this comment, or you are not logged in")
		return redirect("/post/" + str(comment.post_id))
	comment.text = request.form["comment"];
	db.session.commit()
	flash("comment edited successfully")
	return redirect("/post/" + str(comment.post_id))

@app.route("/vote")
@login_required
def vote_on_post():
	item_id = request.args.get("id")
	vote_type = request.args.get("type")
	vote_value = request.args.get("value")
	vote_age = 0
	rv = {}
	if vote_type == "age":
		if vote_value.isdigit():
			vote_age = int(vote_value)
			vote_value = "age"
			rv["age"] = vote_age
		else:
			rv["error"] = "Value for age votes should be a number."
			return json.dumps(rv)
	action, previous = Vote.vote(vote_type, item_id, vote_value, vote_age)
	rv["id"] = item_id
	rv["type"] = vote_type
	rv["value"] = vote_value if action != "undo" else ""
	rv["performed"] = action
	rv["previous"] = previous
	if vote_type =="age":
		rv["med_age"] = Vote.get_median_age(item_id)
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
	rv["age"] = Vote.get_age_vote(post_id)
	return json.dumps(rv)

# So you can still access about when logged in
@app.route("/about")
def about():
	form = Register_Form(request.form)
	return render_template("about/index.html", form=form)

@app.route("/about/security")
def about_security():
	return render_template("about/security.html")

@app.route("/about/coolness")
def about_coolness():
	return render_template("about/coolness.html")

@app.route("/about/feedback")
def about_feedback():
	return render_template("about/feedback.html")

@app.route("/about/free")
def about_links():
	return render_template("about/free.html")

@app.route("/about/links")
def about_freedom():
	return render_template("about/links.html")

@app.route("/about/donate")
def donate():
	return render_template("about/donate.html")

@app.route("/about/contributors")
def contributors_list():
	return render_template("about/contributors.html")

@app.route("/about/reddit")
def reddit_proof():
	return render_template("about/reddit.html")

@app.route("/login", methods=["get", "post"])
def login():
	form = Login_Form(request.form)
	reg_form = Register_Form(request.form)
	if request.method == "POST" and form.validate():
		success = User.full_login(form.username.data, form.password.data, form.remember.data)
		if success:
			next_url = request.args.get("next")
			if not is_safe_url(next_url):
				flask.abort(400)
			return redirect(next_url or "/")
		else:
			return render_template("no-login.html")
	return render_template("login-form.html", login_form=form, form=reg_form)

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
	form = Register_Form(request.form)
	if request.method == "POST" and form.validate():
		user = User(form.username.data, form.password.data)
		if form.email:
			user.email = form.email.data;
		user.updates = form.updates.data;
		db.session.add(user)
		db.session.commit()
		user.login(form.password.data, False)
		flash("account created successfully")
		return redirect("/")
	return render_template("register.html", form=form)

@app.route("/reset/<token>", methods=["get", "post"])
def password_reset(token):
	form = Password_Reset_Form(request.form)
	user = User.get_by_reset_token(token)
	if not user:
		flash("sorry, but that password reset link was not found. this may mean that your account was compromised. please email cyanauroratp@gmail!")
		return render_template("no-login.html")
	if request.method == "POST" and form.validate():
		# Success or not, this token is now invalidated
		user.password_reset = 0;
		if form.username.data == user.username:
			user.password = User.hash_password(form.password.data)
			db.session.commit()
			user.login(form.password.data, False)
			flash("password updated successfully")
			return redirect("/")
		else:
			flash("incorrect username or reset link. this reset link is now expired. please email cyanauroratp@gmail.com for a new one")
			db.session.commit()
			return redirect("/")
	return render_template("register.html", form=form, reset=True)

@app.route("/reset/generate", methods=["get", "post"])

@app.route("/unsubscribe/<user_id>")
def unsubscribe(user_id):
	user = User.query.filter_by(user_id=int(user_id)).first()
	if user:
		user.updates = False
		db.session.commit()
		flash("successfully unsubscribed from email updates")
		return redirect("/")
	else:
		flash("the user id and username did not match. is the unsubscribe link correct?")
		return redirect("/")

@app.route("/submit", methods=["get", "post"])
@login_required
def submission_page():
	form = Submit_Form(request.form)
	if request.method == "POST" and form.validate():
		post = Post(
				current_user.user_id,
				form.url.data,
				form.gender.data,
				form.description.data,
				datetime.datetime.now() + datetime.timedelta(days=int(form.expires.data)),
				not form.disable_age.data,
				form.require_captcha.data,
				form.require_trust.data,
				)
		db.session.add(post)
		db.session.commit()
		flash('remember, <a href="/about/coolness">give feedback; get feedback</a>. make sure to leave some comments in order to receive your own.')
		return redirect("/post/" + str(post.post_id))
	return render_template("submit.html", form=form)

@app.route("/favicon.ico")
def favicon():
	return flask.send_from_directory("static", "favicon.ico")

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
