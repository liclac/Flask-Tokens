from flask import Blueprint

bp = Blueprint('tokens', __name__)

@bp.route('/auth', methods=['POST'])
def authorize_route():
	pass

@bp.route('/refresh', methods=['POST'])
def refresh_route():
	pass
