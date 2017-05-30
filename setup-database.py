#!/usr/bin/env python3

from main import db, app
from sys import exit
from sqlalchemy_utils import database_exists

if not database_exists(app.config["SQLALCHEMY_DATABASE_URI"]):
	print('A database named "transpassing" belonging to root with the entered password was not found.')
	if input("Create it? [Y/n] ") in "YESyesYes":
		from sqlalchemy_utils import create_database
		from flask_sqlalchemy import SQLAlchemy
		create_database(app.config["SQLALCHEMY_DATABASE_URI"])
		print("Database created.")
		db = SQLAlchemy(app)
	else:
		print("Not creating database. Cannot create Tables without database.")
		exit(0)

db.create_all()
print("Tables set up.")

