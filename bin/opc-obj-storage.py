#!/usr/bin/python
'''Python Wrapper for OPC Standard Storage (Object Storage) RESTFul APIs
# ---  TO DO List --- #
# -- Use persistent session instead of new connection and authentication to improve performance -- #
# -- Add exception handling at all appropriate call -- #
'''

import sys, argparse, getpass, logging, ConfigParser
sys.path.append('../lib')
import helper


parser = argparse.ArgumentParser()
parser.add_argument("-c", type=str, help="configuration file", required=True)
parser.add_argument("-o", type=str, help="operations {LIST|DELETE|BULK_DELETE|DOWNLOAD", required=True)
parser.add_argument("-v", type=str, help="verbose listing of container", nargs='?',default='n')
parser.add_argument("-n", type=str, help="container or object name")
args = parser.parse_args()

# Prompt for password input and store in a variable
password = getpass.getpass('Identity Domain Password:')

operation = args.o
config_file = args.c
object_name = args.n
verbose = args.v

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
helper.logsetting(logfile, nloglevel)

helper.log(' ')
helper.log('{:90}'.format("-" * 90))
helper.log('{:30} {:30}'.format('logfile', logfile))

helper.log('{:30} {:30}'.format('username', username))
helper.log('{:30} {:30}'.format('identity domain', identity_domain))
helper.log('{:30} {:30}'.format('storage_url', storage_url))
helper.log('{:30} {:30}'.format('certificate file', cert_file))
helper.log('{:30} {:30}'.format('download dir',download_dir))
helper.log('{:90}'.format("-" * 90))
helper.log(' ')

# Validate Operations

helper.is_valid_ops_request(operation)

# Now I have all the input variables to make REST call to OPC

helper.opcexec(operation, identity_domain, object_name, storage_url, cert_file, username, password)
helper.log(' ')

