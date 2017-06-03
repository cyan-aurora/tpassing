Contributing
------------

Thus far I have made this site myself. If someone would like to help, I would
love it.

Things you could do to help out:

- Offer me server space (it's currently running on a 2003 desktop)
- Work on the website backend
- Work on the CSS / templates
- [Bug reporting / feature suggestions](https://github.com/cyan-aurora/transpassing/issues)
- Donate to the website's operating expenses (domain, servers, ...) (email me
at cyanauroratp@gmail.com)

I tag issues that would be good for outside contributors to work on with "[help
wanted][]" but you're welcome to work on anything!

[help wanted]: https://github.com/cyan-aurora/transpassing/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22

The website is built in Python 3 with [Flask](http://flask.pocoo.org/) and
[SQLAlchemy](http://flask-sqlalchemy.pocoo.org/2.1/). The templates are HTML
(plus Jinja, from Flask, for dynamics).

## Setting up a development environment:

**TLDR**: Install mysql/python3. Clone repo and run `setup.sh`. Run `init`
and load `localhost:5000`.

The build tools should work on Linux and Mac. If you're running Windows you'll
want to use Cygwin or Windows 10's "Linux subsystem". If you want to use native
Windows, email me at cyanauroratp@gmail.com and I will give you some pointers.

Make sure you have myqsl, python3, and pip installed. On debian-based systems
this would look like:

	$ sudo apt-get install mysql-server python3 python3-dev python3-pip

But you can use whatever package manager is available to you. Make sure to note
the password used when installing mysql.

Now set up tpassing:

	$ git clone https://github.com/cyan-aurora/transpassing && cd transpassing
	$ ./setup.sh

Follow the instructions given; it should pretty comprehensively set up
everything you need. In general you can answer `y` to everything.

Finally, you can start the debug server.

	$ ./init

Then load up `localhost:5000` in a browser.

*In production, expired posts are deleted daily for security and space. It's
not necessary in debug, but if you'd like to set that up you can run
`setup-cron.sh`.*

### **Please** email me if you have *any* questions: cyanauroratp@gmail.com
