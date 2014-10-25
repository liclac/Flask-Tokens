Flask-Tokens
============

Token authentication for your Flask applications, built on top of [PyJWT](https://github.com/progrium/pyjwt/).

Why tokens?
-----------

In a normal web application, you'd authorize the user via sessions and cookies, presumably using something like [Flask-Login](https://flask-login.readthedocs.org/en/latest/) or [Flask-Security](https://pythonhosted.org/Flask-Security/).

But what do you do when your clients aren't users in a web browser, but applications communicating with you as an API? You give them access tokens, is what.

**JWT** stands for JSON Web Tokens, and is a proposed standard for secure, verifiable tokens, that can carry any data that can be represented as JSON.

Flask-Tokens encapsulates authentication using JWT tokens in a Flask application.

How do I use it?
----------------

Detailed usage information will be added soon, for now, have a look at the examples.
