#!/usr/bin/env python

import getpass
import logging
import os
import platform
import sys
from concurrent.futures import ThreadPoolExecutor
from os.path import expanduser

import prettytable

import cli
from firefox_saved_credentials import get_saved_credentials, Exit
from pwned_passwords import is_password_pwned

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


def read_master_password(args):
    if args.no_password:
        return None

    master_password = getpass.getpass("Master password (just hit enter if you don't have any): ")
    if master_password == '':
        return None

    return master_password


def read_profile_path(args):
    if args.profile_path is not None:
        return args.profile_path

    if platform.system() == 'Darwin':
        profile_path = "~/Library/Application Support/Firefox/Profiles"
    else:
        profile_path = "~/.mozilla/firefox"

    directory = expanduser(profile_path)
    profiles = [subdir for subdir in os.listdir(directory) if subdir.endswith('.default')]

    if len(profiles) > 1:
        LOG.warning("Detected multiple profiles in %s. Using the first one only (%s)" % (directory, profiles[0]))

    return directory + os.path.sep + profiles[0]


# Returns a set of passwords
def build_password_set(credentials):
    return set([credential['password'] for credential in credentials])


def get_pwned_passwords(passwords, num_threads):
    executor = ThreadPoolExecutor(max_workers=num_threads)
    pwned_passwords = {}  # Map [Password => Number of times pwned]

    def check_password(password):
        pwned, count = is_password_pwned(password)
        if pwned:
            pwned_passwords[password] = count

    for password in passwords:
        executor.submit(check_password, password)

    executor.shutdown(wait=True)
    return pwned_passwords


def display_results(saved_credentials, pwned_passwords):
    if len(pwned_passwords) == 0:
        LOG.info("Good news - it looks like none of your Firefox saved password is pwned!")
        return

    table = prettytable.PrettyTable([
        COLOR_BOLD + 'Website' + COLOR_RESET,
        COLOR_BOLD + 'Username' + COLOR_RESET,
        COLOR_BOLD + 'Password' + COLOR_RESET,
        COLOR_BOLD + 'Status' + COLOR_RESET
    ], hrules=prettytable.ALL)

    for credential in saved_credentials:
        password = credential['password']
        if password in pwned_passwords:
            count = pwned_passwords[password]
            message = 'Pwned in %d breaches!' % count
            table.add_row([
                credential['url'],
                credential.get('username', '(none)'),
                password,
                COLOR_RED + COLOR_BOLD + message + COLOR_RESET
            ])

    print(table)


def main(args):
    check_python_version()
    setup_logging(args)
    master_password = read_master_password(args)
    profile_path = read_profile_path(args)

    try:
        saved_credentials = get_saved_credentials(profile_path, master_password)
    except Exit as e:
        LOG.error('Unable to retrieve Firefox saved credentials.')
        LOG.error(e)
        sys.exit(1)

    LOG.info("Successfully read %d saved credentials" % len(saved_credentials))
    LOG.info("Checking for pwned passwords using up to %d threads" % args.threads)

    password_list = build_password_set(saved_credentials)
    pwned_passwords = get_pwned_passwords(password_list, num_threads=args.threads)
    display_results(saved_credentials, pwned_passwords)

    return pwned_passwords


if __name__ == "__main__":
    main(cli.parser.parse_args())
