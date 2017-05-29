#!/usr/bin/env python3

print("This will set up (but not create) the databases based on main.py.")

if raw_input("Continue? [Y/n] ") in "YESyesYes":

	from main import db
	db.create_all()

	print("Databases set up.")

else:

	print("Skipping.")
