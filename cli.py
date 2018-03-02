import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument(
    '--loglevel',
    dest = 'loglevel',
    choices = ['info', 'debug'],
    default = 'info'
)

parser.add_argument(
    '-p', '--profile-path',
    dest = 'profile_path',
    help = 'Path to your Firefox profile directory (e.g. ~/.mozilla/firefox/abcd.default)',
)

parser.add_argument(
    '-t', '--threads',
    dest = 'threads',
    type = int,
    default = 10
)

parser.add_argument(
    '--no-master-password', 
    dest = 'no_password',
    action = 'store_true',
    help = 'Try to open the Firefox profile without any master password.'
)