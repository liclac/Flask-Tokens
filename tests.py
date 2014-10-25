import string, random
import unittest
import datetime
from flask import Flask
from flask.ext.tokens import *
from flask.ext.testing import TestCase

class TestTokens(TestCase):
	def create_app(self):
		app = Flask(__name__)
		app.config['TESTING'] = True
		app.config['SECRET_KEY'] = 'Lorem ipsum'
		
		tokens = Tokens(app)
		
		@tokens.user_loader
		def user_loader(auth):
			for user in self.users.values():
				if auth['username'] == user['username'] and\
					auth['password'] == user['password']:
					return user
		
		@tokens.serializer
		def serializer(user):
			return { 'user_id': user['id'] }
		
		@tokens.deserializer
		def deserializer(payload):
			return self.users[payload['user_id']]
		
		@tokens.payload_handler
		def payload_handler(user, payload):
			payload['iat'] = (datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		
		@tokens.verifier
		def verifier(user, payload):
			return datetime.datetime.utcfromtimestamp(payload['iat']) > user['last_revocation']
		
		@tokens.refresh_handler
		def refresh_handler(user, payload, refresh_token):
			if refresh_token == user['refresh_token']:
				return payload
		
		@tokens.refresh_issuer
		def refresh_issuer(user):
			if not user['refresh_token']:
				user['refresh_token'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(50))
		
		
		@tokens.auth_response_handler
		def auth_response_handler(user, payload):
			payload['expires_at'] = (datetime.datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		
		@tokens.refresh_response_handler
		def refresh_response_handler(user, payload):
			payload['expires_at'] = (datetime.datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		
		return app
	
	def setUp(self):
		self.users = {
			1: {
				'id': 1,
				'username': 'username',
				'password': 'password',
				'last_revocation': datetime.datetime.utcfromtimestamp(0),
				'refresh_token': None
			}
		}
	
	def test_auth_invalid(self):
		res = self.client.post('/auth', data={'username': 'username', 'password': 'wrongpass'})
		self.assert_403(res)
	
	def test_auth_valid(self):
		res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		self.assert_200(res)

if __name__ == '__main__':
	unittest.main()
