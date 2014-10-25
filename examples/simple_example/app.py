from flask import Flask, jsonify
from flask.ext.tokens import current_user, token_required
from tokens import tokens

app = Flask(__name__)
app.config['SECRET_KEY'] = "asdfghjkl"

tokens.init_app(app)

@app.route('/')
def index():
	if current_user:
		return "Hi, %s!" % current_user['username']
	else:
		return "Hi, anonymous!"

@app.route('/protected')
@token_required
def protected():
	return "This is something super-secret that only %s can see!" % current_user['username']

if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0')
