# A script that emails people who have asked for it, updates
# Run daily on cron

# tpassing / Flask / jinja stuff
# import main
from main import db, config, Post, User, app
import jinja2

# General stuff
import datetime
import sys

# Email stuff
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Collect the data

with open("templates/email/last-email.txt", "r") as last:
	last = datetime.datetime.fromtimestamp(int(last.read()))

if last + datetime.timedelta(7) > datetime.datetime.now():
	print("no new posts")
	sys.exit()

# Query for any new posts
new_posts = Post.query.filter(Post.created > last).all()

email_users = User.query.filter((User.updates != None) & (User.email != None)).all()

# Construct the email

with open("templates/email/new-post.html", 'r') as fp:
    # Create a text/plain message
	raw = fp.read()
	template = app.jinja_env.from_string(raw)

# Send the email to everyone who wants it

s = smtplib.SMTP('localhost')
s.starttls()

msg = MIMEMultipart("alternative")

msg['Subject'] = "tpassing updates"
msg['From'] = config.get("Email", "from")

for user in email_users:
	# Final render in email construction
	rendered = template.render(new_posts=new_posts, to=user)
	html = MIMEText(rendered, "html")

	msg.attach(html)
	msg['To'] = user.email
	print(user.email)
	s.sendmail(msg['From'], [msg['To']], msg.as_string())

# Send the message via our own SMTP server, but don't include the
# envelope header.
s.quit()

