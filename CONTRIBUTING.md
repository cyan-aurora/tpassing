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

The website is built in [Flask](http://flask.pocoo.org/) +
[SQLAlchemy](http://flask-sqlalchemy.pocoo.org/2.1/). The templates are HTML
(plus Jinja, from Flask, for dynamics). It's currently running on Apache with
WSGI Python on an old computer from 2003 running Debian. If you're familiar
with any of those, I'd love your help.

Running:

First make sure you have virtualenv installed (`sudo pip install virtualenv` or
`sudo apt-get install python-virtualenv` will work nearly anywhere but
Windows). Then:

	$ git clone https://github.com/cyan-aurora/transpassing && cd transpassing
    $ ./setup.sh # builds a virtual environment with required dependencies
	$ . venv/bin/activate
	$ ./main.py

Then load up `localhost:5000` in a browser. To set up debugging make sure
`debug` is `True` on the last line of `main.py`.
