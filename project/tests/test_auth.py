# project/tests/test_auth.py

import unittest
import json

from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase


class TestAuthBlueprint(BaseTestCase):
    def test_registration(self):
        """ Test user registration """
        with self.client:
            response = self.client.post(
                'auth/register',
                data=json.dumps(dict(
                    email='joe@gmail.com',
                    password='123456'
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully registered.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)

    def test_registered_with_already_registered_user(self):
        """ Test registration with already registered email """
        user = User(
            email="joe@gmail.com",
            password='test'
        )
        db.session.add(user)
        db.session.commit()

        with self.client:
            response = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="123456"
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'User already exists. Please log in.'
            )
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 202)

    def test_registered_user_login(self):
        """ Test login of registered user """
        with self.client:
            # user registration
            resp_register = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="123456"
                )),
                content_type="application/json",
            )
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # registered user login
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="123456"
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(
                data['message'] == 'Successfully logged in.'
            )
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_non_registered_user_login(self):
        """ Test login of non-registered user """
        with self.client:
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="123456"
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'User does not exist.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_user_with_incorrect_password_login(self):
        """ Test login with wrong password """
        with self.client:
            # user registration
            resp_register = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="123456"
                )),
                content_type="application/json",
            )
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # registered user login using wrong password
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email="joe@gmail.com",
                    password="654321"
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Incorrect password.'
            )
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
