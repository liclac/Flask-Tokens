import string, random
import unittest
import datetime
from flask import Flask, jsonify
from flask.ext.tokens import *
from flask.ext.testing import TestCase
import jwt

SECRET_KEY = 'Lorem ipsum'

class TestTokens(TestCase):
	def create_app(self):
		app = Flask(__name__)
		app.config['TESTING'] = True
		app.config['SECRET_KEY'] = SECRET_KEY
		
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
			return user['refresh_token']
		
		
		@tokens.auth_response_handler
		def auth_response_handler(user, payload):
			payload['expires_at'] = (datetime.datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		
		@tokens.refresh_response_handler
		def refresh_response_handler(user, payload):
			payload['expires_at'] = (datetime.datetime.utcnow() + current_app.config.get('TOKENS_EXPIRY') - datetime.datetime.utcfromtimestamp(0)).total_seconds()
			return payload
		
		@app.route('/')
		def index():
			return jsonify(user_id=current_user['id'] if current_user else 0)
		
		@app.route('/protected')
		@token_required
		def protected():
			return jsonify(user_id=current_user['id'])
		
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
		self.assert_403(self.client.post('/auth', data={'username': 'username', 'password': 'wrongpass'}))
	
	def test_auth_valid(self):
		res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		self.assert_200(res)
		assert 'token' in res.json
		assert 'refresh_token' in res.json
		assert 'expires_at' in res.json
		jwt.decode(res.json['token'], SECRET_KEY)
	
	def test_token_payload(self):
		res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		token = res.json['token']
		payload = jwt.decode(token, SECRET_KEY)
		
		assert 'user_id' in payload
		assert 'iat' in payload
	
	def test_refresh_invalid(self):
		self.assert_400(self.client.post('/auth/refresh', data={}))
		self.assert_400(self.client.post('/auth/refresh', data={'token': 'test'}))
		self.assert_400(self.client.post('/auth/refresh', data={'refresh_token': 'test'}))
		self.assert_403(self.client.post('/auth/refresh', data={'token': 'test', 'refresh_token': 'test'}))
	
	def test_refresh(self):
		auth_res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		res = self.client.post('/auth/refresh', data={'token': auth_res.json['token'], 'refresh_token': auth_res.json['refresh_token']})
		
		self.assert_200(res)
		jwt.decode(res.json['token'], SECRET_KEY)
	
	def test_optional_no_token(self):
		res = self.client.get('/')
		self.assert_200(res)
		assert res.json['user_id'] == 0
	
	def test_optional_with_token(self):
		auth_res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		res = self.client.get('/', headers={'Authorization': 'Bearer ' + auth_res.json['token']})
		self.assert_200(res)
		assert res.json['user_id'] == 1
	
	def test_required_decorator(self):
		auth_res = self.client.post('/auth', data={'username': 'username', 'password': 'password'})
		res = self.client.get('/protected', headers={'Authorization': 'Bearer ' + auth_res.json['token']})
		self.assert_200(res)
		assert res.json['user_id'] == 1

if __name__ == '__main__':
	unittest.main()
