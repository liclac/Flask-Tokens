import datetime
import functools
import jwt
from flask import Blueprint, current_app, request, abort, jsonify, _request_ctx_stack
from werkzeug.local import LocalProxy

DEFAULT_CONFIG = {
	'TOKENS_EXPIRY': datetime.timedelta(hours=10),
	'TOKENS_LEEWAY': datetime.timedelta(seconds=0),
	
	'TOKENS_ENABLE_BLUEPRINT': True,
	'TOKENS_BLUEPRINT_NAME': 'tokens',
	'TOKENS_URL_PREFIX': None,
	
	'TOKENS_ENABLE_AUTHORIZE': True,
	'TOKENS_AUTHORIZE_ENDPOINT': '/auth',
	
	'TOKENS_ENABLE_REFRESH': True,
	'TOKENS_REFRESH_ENDPOINT': '/auth/refresh'
}



# Proxy used to access the currently signed in user; this is only set if
# verify_token has been called. If you want it available everywhere, you can
# call verify_token in a before_request() handler.
current_user = LocalProxy(lambda: _get_user())

def _get_user():
	if not hasattr(_request_ctx_stack.top, 'current_user'):
		verify_authorization_header()
	return _request_ctx_stack.top.current_user



def verify_authorization_header():
	header = 'Authorization'
	prefix = 'Bearer '
	
	if not header in request.headers or \
		not request.headers[header].startswith(prefix):
		# Nullify the current user to mark that, well, we tried. Don't try to
		# overwrite it if a user is already authorized by other means though.
		if not hasattr(_request_ctx_stack.top, 'current_user'):
			_request_ctx_stack.top.current_user = None
		return False
	
	ext = current_app.extensions['tokens']
	token = request.headers[header][len(prefix):]
	
	return bool(ext.verify_token(token))

def token_required(func):
	@functools.wraps(func)
	def f(*args, **kwargs):
		if not verify_authorization_header():
			abort(403)
		return func(*args, **kwargs)
	
	return f



def _authorize_route():
	'''Endpoint for authorizing a user.
	
	It takes freeform authorization as POST data, runs it through the extension
	and returns a token, if any.
	'''
	ext = current_app.extensions['tokens']
	res = {}
	
	token = ext.make_token(request.form)
	if not token: abort(403)
	
	res['token'] = token
	
	if current_app.config.get('TOKENS_ENABLE_REFRESH'):
		refresh_token = ext.issue_refresh_token(current_user)
		if refresh_token:
			res['refresh_token'] = refresh_token
	
	if ext._auth_response_handler:
		res = ext._auth_response_handler(current_user, res)
	
	return jsonify(res)

def _refresh_route():
	'''Endpoint for refreshing an expired token.
	
	It takes two POST parameters: token, and refresh_token. The former is an
	old token to be renewed, the latter is a refresh token to authorize it.
	
	This is not mounted at all if 'TOKENS_ENABLE_REFRESH' is False.
	'''
	if not 'token' in request.form or not 'refresh_token' in request.form:
		abort(400)
	
	ext = current_app.extensions['tokens']
	res = {}
	
	old_token = request.form['token']
	refresh_token = request.form['refresh_token']
	token = ext.refresh_token(old_token, refresh_token)
	if not token: abort(403)
	
	res['token'] = token
	
	if ext._auth_response_handler:
		res = ext._refresh_response_handler(current_user, res)
	
	return jsonify(res)



# Just stick this thing onto your Flask object, and decorate some handlers.
class Tokens(object):
	_user_loader = None
	_serializer = None
	_deserializer = None
	_payload_handler = None
	_verifier = None
	_refresh_handler = None
	_refresh_issuer = None
	_auth_response_handler = None
	_refresh_response_handler = None
	
	
	
	def __init__(self, app):
		self.app = app
		if self.app:
			self.init_app(self.app)
	
	def init_app(self, app):
		# Register the extension on the application object
		if not hasattr(app, 'extensions'):
			app.extensions = {}
		app.extensions['tokens'] = self
		
		# Register default configuration values
		for key, value in DEFAULT_CONFIG.items():
			app.config.setdefault(key, value)
		
		# Mount the blueprint with the provided routes
		if app.config.get('TOKENS_ENABLE_BLUEPRINT'):
			bp = Blueprint(app.config.get('TOKENS_BLUEPRINT_NAME'), __name__)
			
			if app.config.get('TOKENS_ENABLE_AUTHORIZE'):
				bp.add_url_rule(app.config.get('TOKENS_AUTHORIZE_ENDPOINT'), 'authorize', _authorize_route, methods=['POST'])
			
			if app.config.get('TOKENS_ENABLE_REFRESH'):
				bp.add_url_rule(app.config.get('TOKENS_REFRESH_ENDPOINT'), 'refresh', _refresh_route, methods=['POST'])
			
			app.register_blueprint(bp, url_prefix=app.config.get('TOKENS_URL_PREFIX'))
	
	
	
	def make_token(self, auth):
		# Try to authorize the user first of all
		user = self._user_loader(auth)
		
		# Sign the user in for the remainder of the request, or just put a None
		# there to mark that an attempt to log in was made, and that there's no
		# need to try again when current_user is accessed next.
		_request_ctx_stack.top.current_user = user
		
		# Don't do anything if the login was wrong
		if not user:
			return None
		
		# Return a ready-made token
		return self._encode(self._make_payload(user))
	
	def verify_token(self, token):
		# Try to decode the token; abort if it's invalid or expired
		payload = self._decode(token)
		if not payload:
			return None
		
		# Deserialize a proper user object from the payload
		user = self._deserializer(payload)
		
		# If there's a verfier provided, run that before accepting the token!
		# This is what makes token revocation, etc. possible; you can just run
		# a function that looks the token up in a db, checks an "issued at"
		# timestamp against a "all tokens revoked at" one, etc.
		if not self._verifier or self._verifier(user, payload):
			_request_ctx_stack.top.current_user = user
			return payload
		else:
			# Nullify the current user, to prevent attempts to repeatedly
			# revalidate the user when current_user is accessed
			_request_ctx_stack.top.current_user = None
	
	def refresh_token(self, token, refresh_token):
		# Decode the token, completely ignoring the expiration
		payload = self._decode(token, verify_expiration=False)
		if not payload:
			return None
		
		# Deserialize the user from the payload
		user = self._deserializer(payload)
		
		# Ask the refresh handler for a new payload; if it returns None, the
		# refresh was denied for whatever reason. This is very app-specific.
		new_payload = self._refresh_handler(user, payload, refresh_token)
		if new_payload:
			# Sign the user in for the remainder of the request
			_request_ctx_stack.top.current_user = user
			
			# Process it through the payload builder; this will assign a new
			# expiry date, and let the user's payload handler postprocess it
			new_payload = self._make_payload(user, new_payload)
			return self._encode(payload)
		else:
			# Nullify the current user, to prevent attempts to repeatedly
			# revalidate the user when current_user is accessed
			_request_ctx_stack.top.current_user = None
	
	def issue_refresh_token(self, user):
		return self._refresh_issuer(user)
	
	
	
	def _make_payload(self, user, payload={}):
		# Merge userdata into the payload
		userdata = self._serializer(user)
		for key, value in userdata.items():
			payload[key] = value
		
		# Add an expiry date in there
		expiry = current_app.config.get('TOKENS_EXPIRY')
		payload['exp'] = datetime.datetime.utcnow() + expiry
		
		# Let the payload handler have a go at the payload before signing it;
		# here's your chance to modify the data any way you wish. It's your
		# token, I don't know what you'll want to put inside it.
		if self._payload_handler:
			payload = self._payload_handler(user, payload)
		
		return payload
	
	def _encode(self, payload):
		secret = current_app.config.get('SECRET_KEY')
		return jwt.encode(payload, secret)
	
	def _decode(self, token, verify_expiration=True):
		try:
			# Try to decode the token - this blows up spectacularly if it fails
			leeway = current_app.config.get('TOKENS_LEEWAY')
			return jwt.decode(token, current_app.config.get('SECRET_KEY'), leeway=leeway.total_seconds())
		except jwt.DecodeError:
			# The token was tampered with, corrupted or otherwise invalid
			return None
		except jwt.ExpiredSignature:
			# The token has already expired, and the leeway couldn't save it :(
			return None
	
	
	
	def user_loader(self, handler):
		'''Callback for authenticating a user's credentials.
		
		Should return some kind of representation of the user if the
		authorization is successful, None otherwise.
		
		```
		@tokens.user_loader
		def user_loader(auth):
			user = User.query.filter_by(username=auth['username']).first()
			if user and user.verify_password(auth['password']):
				return user
		```
		'''
		self._user_loader = handler
	
	def serializer(self, handler):
		'''Callback for serializing a user into a token payload.
		
		Should return a dictionary of items that can be used to uniquely
		identify the user.
		
		Do not store sensitive information (eg. passwords) in the token!
		Tokens are signed with your SECRET_KEY, which means nobody can tamper
		with them unless they know your secret, but anyone can decode the
		payload and have a look inside.
		
		Examples of good identifiers:
			- an ID
			- a username
			- a Facebook/Twitter/... profile
		
		There is no hard upper limit on how much you can put into your tokens,
		but do try not to put anything unnecesary in there. The less data has
		to be transmitted with every authenticated request, the better.
		
		```
		@tokens.serializer
		def serializer(user):
			return { 'user_id': user.id }
		```
		'''
		self._serializer = handler
	
	def deserializer(self, handler):
		'''Callback for deserializing a token payload into a user.
		
		Should return a user object, identified by the information in the
		payload. This is the opposite of serializer.
		
		```
		@tokens.deserializer
		def deserializer(payload):
			return User.query.get(payload['user_id'])
		```
		'''
		self._deserializer = handler
	
	def payload_handler(self, handler):
		'''(optional) Callback for postprocessing the proposed payload.
		
		This is your chance to add or remove objects or claims from the token
		payload before it is encoded and returned. The payload will at this
		point contain the keys returned from the serializer, and the 'exp'
		(expiry time) claim (as a datetime object).
		
		```
		from datetime import datetime
		
		@tokens.payload_handler
		def payload_handler(user, payload:
			# Store the timestamp for when the token was issued as 'iat'
			payload['iat'] = (datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		'''
		self._payload_handler = handler
	
	def verifier(self, handler):
		'''(optional) Callback for verifying tokens.
		
		Should simply return True or False for whether the token is still valid
		or not. Expiry checking is done separately, and expired tokens will not
		even get passed to this handler.
		
		If you want to implement token revocation (especially important if
		you're using nonexpiring tokens and/or revocation tokens), here's where
		you'll want to look the token up in a database, compare their issued
		time against a revocation time, etc.
		
		```
		from datetime import datetime
		
		@tokens.verifier
		def verifier(user, payload):
			# Assuming payload_handler adds the timestamp for when the token
			# was issued as 'iat', and the user has the datetime for when all
			# tokens were last revoked as 'last_revocation'
			return datetime.utcfromtimestamp(payload['iat']) > user.last_revocation
		```
		'''
		self._verifier = handler
	
	def refresh_handler(self, handler):
		'''Callback for refreshing a token.
		
		*(Not used if refresh tokens are disabled.)*
		
		Look the refresh token up to see if it's valid, and return the payload,
		or None if the token is invalid. You may modify the payload, but as
		payload_handler will be run after this, so there should be little need.
		
		```
		@tokens.refresh_handler
		def refresh_handler(user, payload, refresh_token):
			if refresh_token == user.refresh_token:
				return payload
		```
		'''
		self._refresh_handler = handler
	
	def refresh_issuer(self, handler):
		'''Callback for issuing a refresh token.
		
		*(Not used if refresh tokens are disabled.)*
		
		Issue a new refresh token (or reuse an existing one). Refresh tokens
		should be unguessable strings that can be verified on the server side,
		presumably randomly generated, that can be invalidated at will.
		
		```
		import string, random
		
		@tokens.refresh_issuer
		def refresh_issuer(user):
			# If there is no refresh token, just generate 50 random characters.
			if not user.refresh_token:
				user.refresh_token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(50))
		```
		'''
		self._refresh_issuer = handler
	
	def auth_response_handler(self, handler):
		'''(optional) Callback for processing the auth view response.
		
		The response is a dictionary, by default:
		
		```
		{
			"token": "Encoded token goes here",
			"refresh_token": "Refresh token here (unless those are disabled)"
		}
		```
		
		If you want to add or remove items from the dictionary, here's your
		chance to do so.
		
		```
		from datetime import datetime
		
		@tokens.auth_response_handler
		def auth_response_handler(user, payload):
			payload['expires_at'] = (datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		```
		'''
		self._auth_response_handler = handler
	
	def refresh_response_handler(self, handler):
		'''(optional) Callback for processing the refresh view response.
		
		Similar to auth_response_handler, for the refresh endpoint. Default
		response is:
		
		```
		{
			"token": "Encoded, renewed token goes here"
		}
		```
		
		Add or remove items at will.
		
		```
		from datetime import datetime
		
		@tokens.refresh_response_handler
		def refresh_response_handler(user, payload):
			payload['expires_at'] = (datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		```
		'''
		self._refresh_response_handler = handler
