from . import BaseAPITestCase


class TestLogin(BaseAPITestCase):

    def test_login(self):
        response = self.app.post(
            '/login', data=self.user_data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login successful', response.data)
