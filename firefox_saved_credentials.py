#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is largely based on firefox_decrypt (https://github.com/unode/firefox_decrypt),
# available under the GPL-3.0 license.

import ctypes as ct
import json
import logging
import os
import sqlite3
import sys
from base64 import b64decode
from subprocess import PIPE, Popen

try:
    # Python 3
    from subprocess import DEVNULL
except ImportError:
    # Python 2
    DEVNULL = open(os.devnull, 'w')

try:
    # Python 3
    from urllib.parse import urlparse
except ImportError:
    # Python 2
    from urlparse import urlparse

try:
    # Python 3
    from configparser import ConfigParser
    raw_input = input
except ImportError:
    # Python 2
    from ConfigParser import ConfigParser

PY3 = sys.version_info.major > 2
LOG = None
VERBOSE = False


def get_version():
    """Obtain version information from git if available otherwise use
    the internal version number
    """
    def internal_version():
        return '.'.join(map(str, __version_info__))

    try:
        p = Popen(["git", "describe", "--tags"], stdout=PIPE, stderr=DEVNULL)
    except OSError:
        return internal_version()

    stdout, stderr = p.communicate()

    if p.returncode:
        return internal_version()
    else:
        return stdout.strip().decode("utf-8")


__version_info__ = (0, 7, 0)
__version__ = get_version()


class NotFoundError(Exception):
    """Exception to handle situations where a credentials file is not found
    """
    pass


class Exit(Exception):
    """Exception to allow a clean exit from any point in execution
    """
    ERROR = 1
    MISSING_PROFILEINI = 2
    MISSING_SECRETS = 3
    BAD_PROFILEINI = 4
    LOCATION_NO_DIRECTORY = 5

    FAIL_LOAD_NSS = 11
    FAIL_INIT_NSS = 12
    FAIL_NSS_KEYSLOT = 13
    FAIL_SHUTDOWN_NSS = 14
    BAD_MASTER_PASSWORD = 15
    NEED_MASTER_PASSWORD = 16

    PASSSTORE_NOT_INIT = 20
    PASSSTORE_MISSING = 21
    PASSSTORE_ERROR = 22

    READ_GOT_EOF = 30
    MISSING_CHOICE = 31
    NO_SUCH_PROFILE = 32

    UNKNOWN_ERROR = 100
    KEYBOARD_INTERRUPT = 102

    def __init__(self, exitcode):
        self.exitcode = exitcode

    def __unicode__(self):
        return "Premature program exit with exit code {0}".format(self.exitcode)


class Credentials(object):
    """Base credentials backend manager
    """
    def __init__(self, db):
        self.db = db

        LOG.debug("Database location: %s", self.db)
        if not os.path.isfile(db):
            raise NotFoundError("ERROR - {0} database not found\n".format(db))

        LOG.info("Using %s for credentials.", db)

    def __iter__(self):
        pass

    def done(self):
        """Override this method if the credentials subclass needs to do any
        action after interaction
        """
        pass


class SqliteCredentials(Credentials):
    """SQLite credentials backend manager
    """
    def __init__(self, profile):
        db = os.path.join(profile, "signons.sqlite")

        super(SqliteCredentials, self).__init__(db)

        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self):
        LOG.debug("Reading password database in SQLite format")
        self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType "
                       "FROM moz_logins")
        for i in self.c:
            # yields hostname, encryptedUsername, encryptedPassword, encType
            yield i

    def done(self):
        """Close the sqlite cursor and database connection
        """
        super(SqliteCredentials, self).done()

        self.c.close()
        self.conn.close()


class JsonCredentials(Credentials):
    """JSON credentials backend manager
    """
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")

        super(JsonCredentials, self).__init__(db)

    def __iter__(self):
        with open(self.db) as fh:
            LOG.debug("Reading password database in JSON format")
            data = json.load(fh)

            try:
                logins = data["logins"]
            except:
                raise Exception("Unrecognized format in {0}".format(self.db))

            for i in logins:
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])


class NSSDecoder(object):
    class SECItem(ct.Structure):
        """struct needed to interact with libnss
        """
        _fields_ = [
            ('type', ct.c_uint),
            ('data', ct.c_char_p),  # actually: unsigned char *
            ('len', ct.c_uint),
        ]

    class PK11SlotInfo(ct.Structure):
        """opaque structure representing a logical PKCS slot
        """

    def __init__(self):
        # Locate libnss and try loading it
        self.NSS = None
        self.load_libnss()

        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self._set_ctypes(ct.c_int, "NSS_Init", ct.c_char_p)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, ct.c_char_p)
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

        # for error handling
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _set_ctypes(self, restype, name, *argtypes):
        """Set input/output types on libnss C functions for automatic type casting
        """
        res = getattr(self.NSS, name)
        res.restype = restype
        res.argtypes = argtypes
        setattr(self, "_" + name, res)

    @staticmethod
    def find_nss(locations, nssname):
        """Locate nss is one of the many possible locations
        """
        for loc in locations:
            if os.path.exists(os.path.join(loc, nssname)):
                return loc

        LOG.warn("%s not found on any of the default locations for this platform. "
                 "Attempting to continue nonetheless.", nssname)
        return ""

    def load_libnss(self):
        """Load libnss into python using the CDLL interface
        """
        if os.name == "nt":
            nssname = "nss3.dll"
            locations = (
                "",  # Current directory or system lib finder
                r"C:\Program Files (x86)\Mozilla Firefox",
                r"C:\Program Files\Mozilla Firefox"
            )
            firefox = self.find_nss(locations, nssname)

            os.environ["PATH"] = ';'.join([os.environ["PATH"], firefox])
            LOG.debug("PATH is now %s", os.environ["PATH"])

        elif os.uname()[0] == "Darwin":
            nssname = "libnss3.dylib"
            locations = (
                "",  # Current directory or system lib finder
                "/usr/local/lib/nss",
                "/usr/local/lib",
                "/opt/local/lib/nss",
                "/sw/lib/firefox",
                "/sw/lib/mozilla",
                "/usr/local/opt/nss/lib",  # nss installed with Brew on Darwin
                "/opt/pkg/lib/nss", # installed via pkgsrc
            )

            firefox = self.find_nss(locations, nssname)
        else:
            nssname = "libnss3.so"
            firefox = ""  # Current directory or system lib finder

        try:
            nsslib = os.path.join(firefox, nssname)
            LOG.debug("Loading NSS library from %s", nsslib)

            self.NSS = ct.CDLL(nsslib)

        except Exception as e:
            LOG.error("Problems opening '%s' required for password decryption", nssname)
            LOG.error("Error was %s", e)
            raise Exit(Exit.FAIL_LOAD_NSS)

    def handle_error(self):
        """If an error happens in libnss, handle it and print some debug information
        """
        LOG.debug("Error during a call to NSS library, trying to obtain error info")

        code = self._PORT_GetError()
        name = self._PR_ErrorToName(code)
        name = "NULL" if name is None else name.decode("ascii")
        # 0 is the default language (localization related)
        text = self._PR_ErrorToString(code, 0)
        text = text.decode("utf8")

        LOG.debug("%s: %s", name, text)

    def decode(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)

        e = self._PK11SDR_Decrypt(inp, out, None)
        LOG.debug("Decryption of data returned %s", e)
        try:
            if e == -1:
                LOG.error("Password decryption failed. Passwords protected by a Master Password!")
                self.handle_error()
                raise Exit(Exit.NEED_MASTER_PASSWORD)

            res = ct.string_at(out.data, out.len).decode("utf8")
        finally:
            # Avoid leaking SECItem
            self._SECITEM_ZfreeItem(out, 0)

        return res


class NSSInteraction(object):
    """
    Interact with lib NSS
    """
    def __init__(self):
        self.profile = None
        self.NSS = NSSDecoder()

    def load_profile(self, profile):
        """Initialize the NSS library and profile
        """
        LOG.debug("Initializing NSS with profile path '%s'", profile)
        self.profile = profile

        e = self.NSS._NSS_Init(b"sql:" + self.profile.encode("utf8"))
        LOG.debug("Initializing NSS returned %s", e)

        if e != 0:
            LOG.error("Couldn't initialize NSS, maybe '%s' is not a valid profile?", profile)
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_INIT_NSS)

    def authenticate(self, password):
        """Check if the current profile is protected by a master password,
        prompt the user and unlock the profile.
        """
        LOG.debug("Retrieving internal key slot")
        keyslot = self.NSS._PK11_GetInternalKeySlot()

        LOG.debug("Internal key slot %s", keyslot)
        if not keyslot:
            LOG.error("Failed to retrieve internal KeySlot")
            self.NSS.handle_error()
            raise Exit(Exit.FAIL_NSS_KEYSLOT)

        try:
            # NOTE It would be great to be able to check if the profile is
            # protected by a master password. In C++ one would do:
            #   if (keyslot->needLogin):
            # however accessing instance methods is not supported by ctypes.
            # More on this topic: http://stackoverflow.com/a/19636310
            # A possibility would be to define such function using cython but
            # this adds an unecessary runtime dependency

            if password:
                LOG.debug("Authenticating with password '%s'", password)
                e = self.NSS._PK11_CheckUserPassword(keyslot, password.encode("utf8"))

                LOG.debug("Checking user password returned %s", e)

                if e != 0:
                    LOG.error("Master password is not correct")

                    self.NSS.handle_error()
                    raise Exit(Exit.BAD_MASTER_PASSWORD)

            else:
                LOG.warn("Attempting decryption with no Master Password")
        finally:
            # Avoid leaking PK11KeySlot
            self.NSS._PK11_FreeSlot(keyslot)

    def unload_profile(self):
        """Shutdown NSS and deactive current profile
        """
        e = self.NSS._NSS_Shutdown()

        if e != 0:
            LOG.error("Couldn't shutdown current NSS profile")

            self.NSS.handle_error()
            raise Exit(Exit.FAIL_SHUTDOWN_NSS)

    def decode_entry(self, user64, passw64):
        """Decrypt one entry in the database
        """
        LOG.debug("Decrypting username data '%s'", user64)
        user = self.NSS.decode(user64)

        LOG.debug("Decrypting password data '%s'", passw64)
        passw = self.NSS.decode(passw64)

        return user, passw

    def decrypt_passwords(self):
        """
        Decrypt requested profile using the provided password and print out all
        stored passwords.
        """
        def output_line(line):
            if PY3:
                sys.stdout.write(line)
            else:
                sys.stdout.write(line.encode("utf8"))

        # Any password in this profile store at all?
        got_password = False
        header = True

        credentials = obtain_credentials(self.profile)
        LOG.info("Decrypting credentials")
        result = []

        for url, user, passw, enctype in credentials:
            # enctype informs if passwords are encrypted and protected by
            # a master password
            if enctype:
                user, passw = self.decode_entry(user, passw)

            LOG.debug("Decoding username '%s' and password '%s' for website '%s'", user, passw, url)
            LOG.debug("Decoding username '%s' and password '%s' for website '%s'", type(user), type(passw), type(url))
            result.append({
                'url': url,
                'username': user,
                'password': passw
            })

        credentials.done()

        return result

def obtain_credentials(profile):
    """Figure out which of the 2 possible backend credential engines is available
    """
    try:
        credentials = JsonCredentials(profile)
    except NotFoundError:
        try:
            credentials = SqliteCredentials(profile)
        except NotFoundError:
            LOG.error("Couldn't find credentials file (logins.json or signons.sqlite).")
            raise Exit(Exit.MISSING_SECRETS)

    return credentials

def get_saved_credentials(profile_path, master_password):
    global LOG
    LOG = logging.getLogger('root')
    nss = NSSInteraction()
    nss.load_profile(profile_path)
    try:
        nss.authenticate(master_password)
        result = nss.decrypt_passwords()
        return result
    finally:
        nss.unload_profile()