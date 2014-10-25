from flask import abort
from flask.ext.tokens import Tokens

tokens = Tokens()

# We'll just keep our users in a dictionary to keep it simple
users = {
	1: {
		'id': 1,
		'username': "testuser",
		'password': "test123"
	}
}

# The user loader is the most important thing here: it takes a dictionary of
# user-submitted auth data, and returns a matching user record (if any).
# 
# In a real application, you'd probably do something like:
# 
# user = User.query.filter_by(username=auth['username'])
# if user.verify_password(auth['password']):
#     return user
@tokens.user_loader
def user_loader(auth):
	# Error out if username or password is missing
	if not 'username' in auth or not 'password' in auth:
		abort(400)
	
	for user in users.values():
		if user['username'] == auth['username'] and \
			user['password'] == auth['password']:
			return user

# The serializer is responsible for turning your user object (which can be
# anything) into something that can be serialized into JSON and stored in the
# token. The user's ID is a good example. You can store multiple keys if you
# need to (like a username/realm pair), but try to keep the tokens small!
# 
# Note: DON'T STORE SENSITIVE DATA IN YOUR TOKENS! Tokens are only signed, not
# encrypted. They're protected against tampering, but reading the data inside
# them is trivial.
@tokens.serializer
def serializer(user):
	return { 'user_id': user['id'] }

# The deserializer is the opposite of the serializer: it takes the token
# payload, and uses data from the serializer to load the corresponding user.
# If the user can't be found (their account has been deleted), return None.
# 
# As tokens are cryptographically signed, you can trust them not to have been
# tampered with, as long as nobody knows your SECRET_KEY.
@tokens.deserializer
def deserializer(payload):
	return users[payload['user_id']]
