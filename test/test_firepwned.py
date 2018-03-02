import unittest
import firepwned
import cli
import os

class TestFirepwned(unittest.TestCase):

    def test_end_to_end(self):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        profile_path = os.path.join(current_dir, "resources", "unencrypted-profile")
        args = cli.parser.parse_args([ '--profile', profile_path, '--no-master-password' ])
        pwned_passwords = firepwned.main(args)
        self.assertTrue('mypassword' in pwned_passwords)
        self.assertGreater(pwned_passwords['mypassword'], 0)