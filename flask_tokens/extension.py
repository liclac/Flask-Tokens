import datetime
import jwt
from flask import Blueprint, current_app, _request_ctx_stack
from werkzeug.local import LocalProxy
from .blueprint import bp

DEFAULT_CONFIG = {
	'TOKENS_URL_PREFIX': None,
	'TOKENS_EXPIRY': datetime.timedelta(hours=10),
	'TOKENS_LEEWAY': datetime.timedelta(seconds=0)
}

current_user = LocalProxy(lambda: _request_ctx_stack.top.current_user)

class Tokens(object):
	_user_loader = None
	_serializer = None
	_deserializer = None
	_payload_handler = None
	_verifier = None
	
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
		
		# Register the blueprint with our endpoints
		app.register_blueprint(bp, url_prefix=app.config.get('TOKENS_URL_PREFIX'))
	
	def make_token(self, auth):
		# Try to authorize the user first of all, no point in doing anything if
		# the login is wrong >.>
		user = self._user_loader(auth)
		if not user:
			return None
		
		# Sign the user in for the remainder of the request
		_request_ctx_stack.top.current_user = user
		
		# Load application configuration for easy access
		secret = current_app.config.get('SECRET_KEY')
		expiry = current_app.config.get('TOKENS_EXPIRY')
		leeway = current_app.config.get('TOKENS_LEEWAY')
		
		# Verify all the things; better to assert now than to fail/bug in a bit
		assert secret, "You must set your application's SECRET_KEY before tokens can be generated"
		assert self._serializer, "You need a serializer to make tokens"
		assert self._user_loader, "You need a user loader to make tokens"
		
		# Serialize the user into an initial payload for later modification
		payload = self._serializer(user)
		
		# Unless the serializer already set the expiry (why!?), and that
		# setting isn't None, add an expiry date. Expiring tokens are great.
		if not 'exp' in payload and expiry:
			payload['exp'] = datetime.datetime.utcnow() + expiry
		
		# Let the payload handler have a go at the payload before signing it;
		# here's your chance to modify the data any way you wish. It's your
		# token, I don't know what you'll want to put inside it.
		if self._payload_handler:
			payload = self._payload_handler(payload, user)
		
		return jwt.encode(payload, secret, leeway=leeway.total_seconds())
	
	def verify_token(self, token):
		try:
			# Try to decode the token - this blows up spectacularly if it fails
			payload = jwt.decode(token, current_app.config.get('SECRET_KEY'))
		except jwt.DecodeError:
			# The token was tampered with, corrupted or otherwise invalid
			return None
		except jwt.ExpiredSignature:
			# The token has already expired, and the leeway couldn't save it :(
			return None
		
		user = self._deserializer(payload)
		if not self._verifier or self._verifier(user):
			_request_ctx_stack.top.current_user = user
			return user
	
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
