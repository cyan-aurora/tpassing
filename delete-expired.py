#!/usr/bin/env python

# Delete all rows that have expired
# Important inprod for security but not so much for a dev env
# Used in a cron job created by setup-cron.sh

from main import db, User, Post
import datetime

d = Post.query.filter(Post.expires <= datetime.datetime.now())
d.delete(synchronize_session=False)
