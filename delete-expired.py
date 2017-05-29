#!/usr/bin/env python

# Delete all rows that have expired
# Important inprod for security but not so much for a dev env
# Used in a cron job created by setup-cron.sh

from main import db, User, Post
import datetime

q = Post.query.filter(Post.expires <= datetime.datetime.now())
count = q.count()
print(datetime.datetime.now(), end="> ")
print("Found " + str(count) + " old entries.", end="")
# Add this to make grepping easire
if count:
	print(" | Deleted")
else:
	# Add a newline finally
	print()
q.delete(synchronize_session="fetch")
db.session.commit()
