# project/server/auth/views.py

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from project.server import bcrypt, db
from project.server.models import User

auth_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User registration resource
    """

    def post(self):
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                # insert user into db
                db.session.add(user)
                db.session.commit()
                # generate auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                print("=============================================")
                print(e)
                print("=============================================")
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occured. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please log in.'
            }
            return make_response(jsonify(responseObject)), 202


# define the api resource
registration_view = RegisterAPI.as_view('register_api')

# add rules for api endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
