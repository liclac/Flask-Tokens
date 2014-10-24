import datetime
import jwt
from flask import Blueprint, current_app, _request_ctx_stack
from werkzeug.local import LocalProxy
from .blueprint import bp

DEFAULT_CONFIG = {
	'TOKENS_EXPIRY': datetime.timedelta(hours=10),
	'TOKENS_LEEWAY': datetime.timedelta(seconds=0),
	
	'TOKENS_ENABLE_BLUEPRINT': True,
	'TOKENS_BLUEPRINT_NAME': 'tokens',
	'TOKENS_URL_PREFIX': None,
	
	'TOKENS_ENABLE_AUTHORIZE': True,
	'TOKENS_AUTHORIZE_ENDPOINT': '/auth',
	
	'TOKENS_ENABLE_REFRESH': False,
	'TOKENS_REFRESH_ENDPOINT': '/refresh'
}

# Proxy used to access the currently signed in user; this is only set if
# verify_token has been called. If you want it available everywhere, you can
# call verify_token in a before_request() handler.
current_user = LocalProxy(lambda: _request_ctx_stack.top.current_user)

def _authorize_route():
	'''Endpoint for authorizing a user.
	
	It takes freeform authorization as POST data, runs it through the extension
	and returns a token, if any.
	
	TODO: Refresh Tokens
	TODO: Add a response processor that can add arbitrary data.
	'''
	pass

def _refresh_route():
	'''Endpoint for refreshing an expired token.
	
	It takes two POST parameters: token, and refresh_token. The former is an
	old token to be renewed, the latter is a refresh token to authorize it.
	'''
	pass

# Just stick this thing onto your Flask object, and decorate some handlers.
class Tokens(object):
	_user_loader = None
	_serializer = None
	_deserializer = None
	_payload_handler = None
	_verifier = None
	_refresh_handler = None
	
	
	
	def __init__(self, app):
		self.app = app
		if self.app:
			self.init_app(self.app)
	
	def init_app(self, app):
		# Register the extension on the application object
		if not hasattr(app, 'extensions'):
			app.extensions = {}
		app.extensions['extensionname'] = self
		
		# Register default configuration values
		for key, value in DEFAULT_CONFIG.items():
			app.config.setdefault(key, value)
		
		# Mount the blueprint with the provided routes
		if app.config.get('TOKENS_ENABLE_BLUEPRINT'):
			bp = Blueprint(app.config.get('TOKENS_BLUEPRINT_NAME'), __name__)
			
			if app.config.get('TOKENS_ENABLE_AUTHORIZE'):
				bp.route(_authorize_route, methods=['POST'])
			
			if app.config.get('TOKENS_ENABLE_REFRESH'):
				bp.route(_refresh_route, methods=['POST'])
			
			app.register_blueprint(bp, url_prefix=app.config.get('TOKENS_URL_PREFIX'))
	
	
	
	def make_token(self, auth):
		# Try to authorize the user first of all, no point in doing anything if
		# the login is wrong >.>
		user = self._user_loader(auth)
		if not user:
			return None
		
		# Sign the user in for the remainder of the request
		_request_ctx_stack.top.current_user = user
		
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
		if not self._verifier or self._verifier(user):
			_request_ctx_stack.top.current_user = user
			return user
	
	def refresh_token(self, token, refresh_token):
		# Decode the token, completely ignoring the expiration
		payload = self._decode(token, verify_expiration=False)
		
		# Deserialize the user from the payload
		user = self._deserializer(payload)
		
		# Ask the refresh handler for a new payload; if it returns None, the
		# refresh was denied for whatever reason. This is very app-specific.
		new_payload = self._refresh_handler(user, payload, refresh_token)
		if new_payload:
			# Process it through the payload builder; this will assign a new
			# expiry date, and let the user's payload handler postprocess it
			new_payload = self._make_payload(user, new_payload)
			return self._encode(payload)
	
	
	
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
			payload = self._payload_handler(payload, user)
		
		return payload
	
	def _encode(self, payload):
		leeway = current_app.config.get('TOKENS_LEEWAY')
		secret = current_app.config.get('SECRET_KEY')
		return jwt.encode(payload, secret, leeway=leeway.total_seconds())
	
	def _decode(self, token, verify_expiration=True):
		try:
			# Try to decode the token - this blows up spectacularly if it fails
			return jwt.decode(token, current_app.config.get('SECRET_KEY'))
		except jwt.DecodeError:
			# The token was tampered with, corrupted or otherwise invalid
			return None
		except jwt.ExpiredSignature:
			# The token has already expired, and the leeway couldn't save it :(
			return None
	
	
	
	def user_loader(self, handler):
		self._user_loader = handler
	
	def serializer(self, handler):
		self._serializer = handler
	
	def deserializer(self, handler):
		self._deserializer = handler
	
	def payload_handler(self, handler):
		self._payload_handler = handler
	
	def verifier(self, handler):
		self._verifier = handler
	
	def refresh_handler(self, handler):
		self._refresh_handler = handler
