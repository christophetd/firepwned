from httmock import urlmatch, HTTMock
import unittest
import hashlib
from pwned_passwords import is_password_pwned, PREFIX_LEN

class TestPwnedPasswords(unittest.TestCase):

    def test_detects_pwned_password(self):

        password = "password"
        hash = hashlib.sha1(bytes(password, "utf8")).hexdigest()
        hash_prefix = hash[0:PREFIX_LEN]
        hash_suffix = hash[PREFIX_LEN:]

        @urlmatch(scheme='https', netloc=r'api.pwnedpasswords.com', path=r'/range/' + hash_prefix)
        def mock(url, request):
            return "\n".join([
                "1D72CD07550416C216D8AD296BF5C0AE8E0:9",
                "1E2AAA439972480CEC7F16C795BBB429372:1",
                "1E3687A61BFCE35F69B7408158101C8E414:1",
                "%s:%s" % (hash_suffix.upper(), "100"),
                "20597F5AC10A2F67701B4AD1D3A09F72250:3",
                "20AEBCE40E55EDA1CE07D175EC293150A7E:1",
                "20FFB975547F6A33C2882CFF8CE2BC49720:1"
            ])

        with HTTMock(mock):
            self.assertTrue(is_password_pwned(password))

    def test_detects_not_pwned_password(self):

        password = "password"
        hash = hashlib.sha1(bytes(password, "utf8")).hexdigest()
        hash_prefix = hash[0:PREFIX_LEN]

        @urlmatch(scheme='https', netloc=r'api.pwnedpasswords.com', path=r'/range/' + hash_prefix)
        def mock(url, request):
            return "\n".join([
                "1D72CD07550416C216D8AD296BF5C0AE8E0:9",
                "1E2AAA439972480CEC7F16C795BBB429372:1",
                "1E3687A61BFCE35F69B7408158101C8E414:1",
                "20597F5AC10A2F67701B4AD1D3A09F72250:3",
                "20AEBCE40E55EDA1CE07D175EC293150A7E:1",
                "20FFB975547F6A33C2882CFF8CE2BC49720:1"
            ])

        with HTTMock(mock):
            self.assertFalse(is_password_pwned(password))

    def test_api_error(self):
        @urlmatch(scheme='https', netloc=r'api.pwnedpasswords.com', path=r'/range/.*')
        def mock(url, request):
            return {
                'status_code': 503
            }

        with HTTMock(mock):
            self.assertRaises(Exception, is_password_pwned, "password")