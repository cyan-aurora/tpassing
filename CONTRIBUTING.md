Contributing
------------

Thus far I have made this site myself. If someone would like to help, I would
love it.

Things you could do to help out:

- Offer me server space
- Work on the website backend
- Work on the style / frontend (in code or in ideas)
- Bug reporting
- Feature suggestions
- Feedback on the website
- Donate to the website's operating (domain, servers, ...) (email me)

How to develop the website:

The website is built in Python 3 with [Flask](http://flask.pocoo.org/) and
[SQLAlchemy](http://flask-sqlalchemy.pocoo.org/2.1/). The templates are HTML
(plus Jinja, from Flask, for dynamics). It's currently running on Apache with
WSGI Python on an old computer from 2003 running Debian. If you're familiar
with any of those, I'd love your help.

Running:

First, you must set up a fake database for testing. Make sure you have myqsl
(`sudo apt-get install mysql-server` on debian), then:

	$ mysql
	> CREATE DATABASE transpassing;
	> exit
	Bye

If you have a mysql password make sure to put it in `dummy-config.ini` (this
will be moved to `secure.ini` after setup)

Now make sure you have python3 and virtualenv installed. On debian installing
python3 will look like:

	$ sudo apt-get install python3 python3-dev python3-pip

Then on any system but windows you can do:

	$ sudo pip install virtualenv

Now set up tpassing:

	$ git clone https://github.com/cyan-aurora/transpassing && cd transpassing
    $ ./setup.sh # builds a virtual environment with required dependencies
	$ . venv/bin/activate

You'll be in a fully setup python environment.

Now run!

	$ ./main.py

Then load up `localhost:5000` in a browser. To set up debugging and
auto-reloading make sure `debug` is `True` on the last line of `main.py`.
