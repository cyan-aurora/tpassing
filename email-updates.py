# A script that emails people who have asked for it, updates
# Run daily on cron

# tpassing / Flask / jinja stuff
# import main
from main import db, config, Post, User, app
import jinja2

# General stuff
import datetime
import sys
import os

# Email stuff
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Collect the data

email_time_file = "templates/email/last-email.txt"
# Allow first-time run to setup the file
if not os.path.isfile(email_time_file):
	# Send everything, send all
	last = 0
else:
	with open(email_time_file, "r") as last:
		last = datetime.datetime.fromtimestamp(float(last.read()))

if last + datetime.timedelta(7) > datetime.datetime.now():
	print("An email was sent too recently to send again")
	sys.exit()

# Query for any new posts
new_posts = Post.query.filter(Post.created > last).all()

if not new_posts:
	sys.exit("No new posts")

email_users = User.query.filter((User.updates == 1) & (User.email != "")).all()

# Construct the email

with open("templates/email/new-post.html", 'r') as fp:
	# Create a text/plain message
	raw = fp.read()
	template = app.jinja_env.from_string(raw)

# Send the email to everyone who wants it

s = smtplib.SMTP('localhost')
s.starttls()

for user in email_users:

	# Final render in email construction
	rendered = template.render(new_posts=new_posts, to=user)
	html = MIMEText(rendered, "html")

	msg = MIMEMultipart("alternative")

	msg['Subject'] = "tpassing updates"
	msg['From'] = config.get("Email", "from")
	msg['To'] = user.email

	msg.attach(html)
	s.sendmail(msg['From'], [msg['To']], msg.as_string())

	print("Sending new post message to " + msg['To'])

# Send the message via our own SMTP server, but don't include the
# envelope header.
s.quit()

# Remember the last time we emailed everyone
now = datetime.datetime.now().timestamp()
with open(email_time_file, "w") as last:
	last.write(str(now))
