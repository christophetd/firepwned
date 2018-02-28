import unittest
from firefox_saved_credentials import get_saved_credentials
import os

class TestSavedCredentialsExtraction(unittest.TestCase):
    
    def test_extracts_saved_passwords_unencrypted(self):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        profile_path = os.path.join(current_dir, "resources", "unencrypted-profile")
        credentials = get_saved_credentials(profile_path, master_password=None)
        self.assertEqual(len(credentials), 1)
        self.assertEquals(credentials[0], {
            'url': 'https://github.com',
            'username': 'christophetd',
            'password': 'mypassword'
        })

    def test_extracts_saved_passwords_encrypted(self):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        profile_path = os.path.join(current_dir, "resources", "encrypted-profile")
        credentials = get_saved_credentials(profile_path, master_password="nevergonnagiveyouup")
        self.assertEqual(len(credentials), 1)
        self.assertEquals(credentials[0], {
            'url': 'https://github.com',
            'username': 'christophetd',
            'password': 'mypassword'
        })