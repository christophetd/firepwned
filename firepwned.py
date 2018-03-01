#!/usr/bin/env python

from firefox_saved_credentials import get_saved_credentials, Exit
import pwned_passwords
import sys
import logging
import cli
import prettytable
import getpass
from os.path import expanduser
import os
from concurrent.futures import ThreadPoolExecutor

COLOR_RED = '\033[91m'
COLOR_RESET = '\033[0m'
COLOR_BOLD = '\033[1m'

def check_python_version():
    if sys.version_info[0] < 3:
        sys.stderr.write("Firepwned doesn't support Python 2. Please run it with Python 3, or use the Docker image.\n")
        sys.exit(1)

def setup_logging(args):
    if args.loglevel == "debug":
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        format="%(levelname)s - %(message)s",
        level=level,
    )

    global LOG
    LOG = logging.getLogger(__name__)

    # Prevent requests from displaying useless log messages
    logging.getLogger("urllib3").setLevel(logging.WARNING)

def read_master_password():
    master_password = getpass.getpass("Master password (just hit enter if you don't have any): ")
    if master_password == '':
        return None

    return master_password

def read_profile_path(args):
    if args.profile_path is not None:
        return args.profile_path

    directory = expanduser("~/.mozilla/firefox")
    profiles = [ subdir for subdir in os.listdir(directory) if subdir.endswith('.default') ]

    if len(profiles) > 1:
        LOG.warning("Detected multiple profiles in %s. Using the first one only (%s)" % (directory, profiles[0]))

    return directory + os.path.sep + profiles[0]


def main(args):
    check_python_version()
    setup_logging(args)
    master_password = read_master_password()
    profile_path = read_profile_path(args)
    try:
        saved_credentials = get_saved_credentials(profile_path, master_password)
    except Exit as e:
        LOG.error('Unable to retrieve Firefox saved credentials.')
        sys.exit(1)

    LOG.info("Successfully read %d saved credentials" % len(saved_credentials))
    LOG.info("Checking for pwned passwords using up to %d threads" % args.threads)

    table = prettytable.PrettyTable([
        COLOR_BOLD + 'Website' + COLOR_RESET,
        COLOR_BOLD + 'Username' + COLOR_RESET,
        COLOR_BOLD + 'Password' + COLOR_RESET,
        COLOR_BOLD + 'Status' + COLOR_RESET
    ], hrules=prettytable.ALL)

    executor = ThreadPoolExecutor(max_workers=args.threads)
    pwned_credentials = []
    checked_passwords = {} # password => boolean indicating if it's been pwned

    def check_pwned_credentials(credentials):
        password = credentials['password']
        if not (password in checked_passwords):
            checked_passwords[password] = pwned_passwords.is_password_pwned(password)
        else:
            LOG.debug('Password "%s" already checked (pwned: %s), skipping' % (password, checked_passwords[password][0]))

        if checked_passwords[password][0] == True:
            pwned_credentials.append(credentials)

    for credentials in saved_credentials:
        executor.submit(check_pwned_credentials, credentials)

    executor.shutdown(wait=True)

    for credentials in pwned_credentials:
        password = credentials['password']
        message = 'Pwned in %d breaches!' % checked_passwords[password][1]
        table.add_row([
            credentials['url'],
            credentials['username'],
            password,
             COLOR_RED + COLOR_BOLD + message + COLOR_RESET
        ])

    if len(pwned_credentials) == 0:
        LOG.info("Good news - it looks like none of your Firefox saved password is pwned!")
    else:
        print(table)

if __name__ == "__main__":
    main(cli.parser.parse_args())