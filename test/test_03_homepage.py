from . import BaseAPITestCase


class TestHomepage(BaseAPITestCase):
    def test_homepage_without_token(self):
        response = self.app.get(
            '/', follow_redirects=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Bad Token', response.data)

    def test_homepage_with_token(self):
        # Logging in to get token
        auth_token = self.app.post(
            '/login', data=self.user_data, follow_redirects=True).json.get('auth_token')
        response = self.app.get(
            '/', headers={'Authorization': f'Bearer {auth_token}'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.user_data['email']}", response.json)
