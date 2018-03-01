import requests
import hashlib
import logging

PREFIX_LEN = 5
LINE_DELIMITER = ":"
API_URL = "https://api.pwnedpasswords.com/range/"

def is_password_pwned(password):
    hash = hashlib.sha1(bytes(password, "utf8")).hexdigest()
    hash_prefix = hash[0:PREFIX_LEN]
    hash_suffix = hash[PREFIX_LEN:]
    LOG = logging.getLogger('root')

    LOG.debug('Checking on HIBP API if password "%s" is pwned' % password)
    headers = {
        'User-Agent': 'https://github.com/christophetd/firepwned'
    }
    response = requests.get(API_URL + hash_prefix, headers=headers)
    if response.status_code != 200:
        raise Exception("PwnedPasswords API looks down")

    results = response.text.split("\n")

    for result in results:
        hash_suffix_candidate, count = result.split(LINE_DELIMITER)
        if hash_suffix_candidate.lower().lstrip() == hash_suffix:
            return (True, int(count))

    return (False, 0)