#!/usr/bin/env python
'''Python Wrapper for OPC Standard Storage (Object Storage) RESTFul APIs
# ---  TO DO List --- #
# -- Add exception handling at all appropriate call -- #
'''

import sys, argparse, getpass, logging, ConfigParser
sys.path.append('../lib')
import opcstorage


parser = argparse.ArgumentParser()
parser.add_argument("-c", type=str, help="configuration file", required=True)
parser.add_argument("-o", type=str, help="operations {BULK_DELETE|CREATE|DELETE|DOWNLOAD|LIST|LIST_EXT|UPLOAD}", required=True)
parser.add_argument("-n", type=str, help="container or object name")
parser.add_argument("-f", type=str, help="filename to upload to Storage cloud")
args = parser.parse_args()

# Prompt for password input and store in a variable
try:
    password = getpass.getpass('Identity Domain Password:')
except (KeyboardInterrupt):
    opcstorage.log('Control-C : Program Interrupted')
    sys.exit(1)

operation = args.o
config_file = args.c
object_name = args.n
file_name = args.f

cp = ConfigParser.ConfigParser()
cp.read(config_file)

parameters = dict(cp.items('Section 1'))

identity_domain = parameters['identity_domain']
username = parameters['username']
storage_url = parameters['storage_url']
logfile = parameters['logfile']
cert_file = parameters['cert_file']
download_dir = parameters['download_dir']

# Set logging and print name of logfile to check
loglevel="INFO"
nloglevel =getattr(logging, loglevel, None)
opcstorage.logsetting(logfile, nloglevel)

opcstorage.log(' ')
opcstorage.log('{:90}'.format("-" * 90))
opcstorage.log('{:30} {:30}'.format('logfile', logfile))

opcstorage.log('{:30} {:30}'.format('username', username))
opcstorage.log('{:30} {:30}'.format('identity domain', identity_domain))
opcstorage.log('{:30} {:30}'.format('storage_url', storage_url))
opcstorage.log('{:30} {:30}'.format('certificate file', cert_file))
opcstorage.log('{:30} {:30}'.format('download dir',download_dir))
opcstorage.log('{:90}'.format("-" * 90))
opcstorage.log(' ')

# Validate Operations

opcstorage.is_valid_ops_request(operation, object_name, file_name)

# Now I have all the input variables to make REST call to OPC
try:
    opcstorage.opcexec(operation, identity_domain, object_name, storage_url, cert_file, username, password, download_dir, file_name)
    opcstorage.log(' ')
except KeyboardInterrupt:
    opcstorage.log('Control-C : Program Interrupted')
    sys.exit(1)

