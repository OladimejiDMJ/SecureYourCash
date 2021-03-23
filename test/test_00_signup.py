from . import BaseAPITestCase, db
from unittest.mock import Mock

class TestSignup(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        # Dropping and creating tables on signup test\
        # to ensure retest success
        db.drop_all()
        db.create_all()

    def test_valid_user_signup(self):
        response = self.app.post(
            '/signup', data=self.user_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'OTP', response.data)
