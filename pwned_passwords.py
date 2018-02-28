import requests
import hashlib

PREFIX_LEN = 5
LINE_DELIMITER = ":"

def is_password_pwned(password):
    hash = hashlib.sha1(bytes(password, "utf8")).hexdigest()
    hash_prefix = hash[0:PREFIX_LEN]
    hash_suffix = hash[PREFIX_LEN:]

    response = requests.get("https://api.pwnedpasswords.com/range/" + hash_prefix)
    if response.status_code != 200:
        raise Exception("PwnedPasswords API looks down")

    results = response.text.split("\n")

    for result in results:
        hash_suffix_candidate, count = result.split(LINE_DELIMITER)
        if hash_suffix_candidate.lower().lstrip() == hash_suffix:
            return True

    return False