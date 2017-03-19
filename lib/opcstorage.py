#!/usr/bin/env python
'''Python Wrapper for OPC Standard Storage (Object Storage) RESTFul APIs
# ---  TO DO List --- #
# -- Add exception handling at all appropriate call -- #
'''

import sys, os, argparse, getpass, requests, time, logging, ConfigParser, json, re
from collections import defaultdict


def logsetting(logfile, loglevel):
    """Configure logging"""
    logging.basicConfig(level=loglevel,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename=logfile,
                        filemode='a')


def log(logmessage):
    """Print message to standard output and log file"""
    logging.info(logmessage)
    print logmessage


def convertsize(B):
    """Return the given bytes as a human friendly KB, MB, GB, or TB string"""

    if B is None:
        B = 0

    B = float(B)
    KB = float(1024)
    MB = float(KB ** 2)
    GB = float(KB ** 3)
    TB = float(KB ** 4)

    if B < KB:
        return '{0} {1}'.format(B,'Bytes' if 0 == B > 1 else 'Byte')
    elif KB <= B < MB:
        return '{0:.2f} KB'.format(B/KB)
    elif MB <= B < GB:
        return '{0:.2f} MB'.format(B/MB)
    elif GB <= B < TB:
        return '{0:.2f} GB'.format(B/GB)
    elif TB <= B:
        return '{0:.2f} TB'.format(B/TB)


def is_valid_ops_request(operation, object_name):
    """Validate arguments and their combinations"""

    if operation not in ('LIST','LIST_EXT','DELETE','BULK_DELETE','DOWNLOAD','CREATE','UPLOAD'):
        message = '{:50} {:40}'.format('Invalid Operation Request! Should be one of - ','BULK_DELETE|CREATE|DELETE|DOWNLOAD|LIST|LIST_EXT|UPLOAD')
        log(message)
        exit(1)
    if operation == 'LIST_EXT' and object_name is None:
        message = '{:80}'.format('Invalid Operation Request! Should specify container name for extended listing')
        log(message)
        exit(1)
    if operation == 'BULK_DELETE' and object_name is None:
        message = '{:80}'.format('Invalid Operation Request! Should specify container name for bulk delete operation')
        log(message)
        exit(1)
    if operation == 'CREATE' and object_name is None:
        message = '{:80}'.format('Invalid Operation Request! Should specify container name for creating container')
        log(message)
        exit(1)
    if operation == 'DELETE' and object_name is None:
        message = '{:80}'.format('Invalid Operation Request! Should specify object name for deleting object')
        log(message)
        exit(1)


def getsessionobject(username,password,cert_file):
    """Create a persistent session object to be used by all other functions"""

    try:
        s = requests.Session()
        s.auth = (username, password)
        s.verify = cert_file
        return s
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise


def validatesession(url, session):
    """Check that session is valid"""

    try:
        response = session.head(url)
        return response.status_code
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise


def getcontainerinfo(url, session):
    """Return object count, last modified and size of container"""

    retVal = defaultdict(dict)

    try:
        response = session.head(url)
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise
    if response.status_code == 204:
        retVal['status_code'] = 204
        retVal['headers'] = response.headers
        return retVal

    else:
        log('Job request not accepted - Response code %s' % response.status_code)
        retVal['status_code'] = response.status_code
        return retVal


def getobjectlist(url, session):
    """Return name of objects in a container """

    try:
        response = session.get(url)
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise
    if response.status_code == 200:
        return response.text
    else:
        log('Job request not accepted - Response code %s' % response.status_code)


def getobjectinfo(url, session):
    """Return object name, last modified and size"""

    retVal = defaultdict(dict)

    try:
        response = session.head(url)
    except Exception as e:
        log('An error occurred : %\n' % e)
        raise
    if response.status_code == 200:
        retVal['status_code'] = 200
        retVal['headers'] = response.headers
        return retVal
    else:
        log('Job request not accepted - Response code %s' % response.status_code)
        retVal['status_code'] = response.status_code
        return retVal


def getaccountinfo(url, session):
    """Return list of all containers in an account (identity domain) """

    try:
        response = session.get(url)
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise
    if response.status_code == 200:
        return response.text
    else:
        log('Job request not accepted - Response code %s' % response.status_code)


def print_header():
    """Print header for container listing output"""

    header = '{:30} {:30} {:>20} {:>20}'.format('container name','last modified','number of objects','size of container')
    log(header)
    log(' ')


def print_object_header(container_name):
    """Print header for object listing output"""

    header = '{:30} {:>30}'.format('container name : ',container_name)
    log(header)
    header = '{:50} {:30} {:>10}'.format('object name','last modified','size of object')
    log(header)
    log(' ')


def pretty_output(ci_dict, container_name):
    """Print container information (Lst Modified, Size and Number of Objects)"""

    try:
        last_modified = time.ctime(float(ci_dict[container_name]['X-Last-Modified-Timestamp']))
    except Exception as e:
        last_modified = ''
    size = convertsize(ci_dict[container_name]['X-Container-Bytes-Used'])
    num_object = ci_dict[container_name]['X-Container-Object-Count']

    detail = '{:30} {:30} {:>20} {:>20}'.format(container_name, last_modified, num_object, size)
    log(detail)


def pretty_object_output(oi_dict, object_name):
    """Print object information (Last Modified and Size)"""

    last_modified = oi_dict[object_name]['Last-Modified']
    size = convertsize(oi_dict[object_name]['Content-Length'])

    detail = '{:50} {:>30} {:>10}'.format(object_name[:50], last_modified, size)
    log(detail)


def convert_to_list(in_str):
    """Convert output stream from API call response to a list of elements breaking at new line"""

    out = []
    buff = []
    for c in in_str:
        if c == '\n':
            out.append(''.join(buff))
            buff = []
        else:
            buff.append(c)
    else:
        if buff:
            out.append(''.join(buff))

    return out


def listcontainer(url, object_name, session_handler):
    """Return Last Modified, Size and Number of Objects in a container"""

    ci_dict = defaultdict(dict)
    url = url + '/' + object_name
    container_info = getcontainerinfo(url, session_handler)

    if container_info['status_code'] == 204:
        ci_dict[object_name]['X-Last-Modified-Timestamp'] = container_info['headers'].get('X-Last-Modified-Timestamp')
        ci_dict[object_name]['X-Container-Bytes-Used'] = container_info['headers'].get('X-Container-Bytes-Used')
        ci_dict[object_name]['X-Container-Object-Count'] = container_info['headers'].get('X-Container-Object-Count')

        print_header()
        pretty_output(ci_dict, object_name)


def listallcontainer(storage_url, session_handler):
    """Return Last Modified, Size and Number of Objects in all containers in the account"""

    ci_dict = defaultdict(dict)
    top_level_info = convert_to_list(getaccountinfo(storage_url, session_handler))
    print_header()

    for object_name in top_level_info:
        if object_name:

            url = storage_url + '/' + object_name
            container_info = getcontainerinfo(url, session_handler)

            if container_info['status_code'] == 204:
                ci_dict[object_name]['X-Last-Modified-Timestamp'] = container_info['headers'].get('X-Last-Modified-Timestamp')
                ci_dict[object_name]['X-Container-Bytes-Used'] = container_info['headers'].get('X-Container-Bytes-Used')
                ci_dict[object_name]['X-Container-Object-Count'] = container_info['headers'].get('X-Container-Object-Count')

                pretty_output(ci_dict, object_name)


def listallobjectsincontainer(storage_url, container_name, session_handler):
    """Return Last Modified, Size of all Objects in a container"""

    oi_dict = defaultdict(dict)
    url = storage_url + '/' + container_name
    object_list = convert_to_list(getobjectlist(url, session_handler))

    print_object_header(container_name)
    for object_name in object_list:
        url = storage_url + '/' + container_name + '/' + object_name
        object_info = getobjectinfo(url, session_handler)

        if object_info['status_code'] == 200:
            oi_dict[object_name]['Last-Modified'] = object_info['headers'].get('Last-Modified')
            oi_dict[object_name]['Content-Length'] = object_info['headers'].get('Content-Length')

            pretty_object_output(oi_dict, object_name)


def bulkdeletecontainer(storage_url, container_name, session_handler, dir_path):
    """ Bulk Delete objects from a container. """
    file_extn = '.delete'
    file_name = os.path.join(dir_path, container_name + file_extn)

    # print file_name

    # Check if the file exists and delete it
    if os.path.isfile(file_name):
        os.remove(file_name)

    # Open file for writing
    f_handler = open(file_name, 'w')

    # Fetch object names of the objects in the container and write to the file

    url = storage_url + '/' + container_name
    object_list = convert_to_list(getobjectlist(url, session_handler))

    for item in object_list:

            object_name_with_full_path = container_name + '/' +item
            f_handler.write("%s\n" % object_name_with_full_path)

    f_handler.close()

    # make REST Call to Oracle Cloud to delete all objects of the container

    try:
        headers = {'Content-Type':'text/plain'}
        url = storage_url + '?bulk-delete'
        payload = open(file_name, 'rb')
        response = session_handler.delete(url, headers=headers, data=payload)
        payload.close()
        message = '{:30} {:30} {:20}'.format('Objects from container ', container_name, ' deleted...')
        log(message)
    except Exception as e:
        log('An error occurred : %s\n' % e)
        payload.close()
        raise


def createcontainer(storage_url, container_name, session_handler):
    """Create an empty container"""

    # Validate container name -- should not contain a slash (/)

    if re.search('/',container_name):
        log('Valid Container name should not have /...')
        log(' ')
        exit(1)
    else:
        url = storage_url + '/' + container_name
        response = session_handler.put(url)

        if response.status_code == 201:
            message = '{:30} {:30} {:20}'.format('Empty container ', container_name, 'created ...')
            log(message)


def deleteobject(storage_url, object_name, session_handler):
    """Delete an object from storage cloud service. Should pass FQN for object to be deleted"""

    # Validate that the object_name is not a container

    object_url = storage_url + '/' + object_name

    try:
        response_get = session_handler.head(object_url)
    except Exception as e_get:
        log('An error occurred : %\n' % e_get)
        raise
    if response_get.status_code == 200:
        try:
            response_del = session_handler.delete(object_url)
        except Exception as e_del:
            log('An error occurred :  %\n' % e_del)
            raise
        if response_del.status_code == 204:
            message = '{:30} {:30} {:20}'.format('Object ', object_name, 'deleted ...')
            log(message)
        elif response_del.status_code == 404:
            message = '{:30} {:30} {:20}'.format('Object ', object_name, 'not found ...')
            log(message)
        else:
            message = '{:30} {:30} {:20}'.format('Object not deleted', 'API call response code - ', response_del.status_code)
            log(message)
    else:
        message = '{:30} {:30} {:20}'.format('Object not found', ' Get request API call response code - ', response_get.status_code)
        log(message)
        message = '{:30} {:80}'.format('Object uri - ', object_url)
        log(message)


def opcexec(operation, identity_domain, object_name, storage_url, cert_file, username, password, download_dir):
    """Main function to get session object, validate input and call appropriate sub-function"""

    headers = {
        'X-ID-TENANT-NAME': identity_domain
    }

    session_handler = getsessionobject(username,password,cert_file)
    is_session_valid = validatesession(storage_url, session_handler)

    if is_session_valid == 401:
        log('Invalid authentication token ...  check credentials')
        exit(1)

    if operation == 'LIST':
        if object_name:

            listcontainer(storage_url, object_name, session_handler)

        else:

            listallcontainer(storage_url, session_handler)

    elif operation == 'LIST_EXT':

        listallobjectsincontainer(storage_url, object_name, session_handler)

    elif operation == 'BULK_DELETE':

        bulkdeletecontainer(storage_url, object_name, session_handler, download_dir)

    elif operation == 'CREATE':

        createcontainer(storage_url, object_name, session_handler)

    elif operation == 'DELETE':

        deleteobject(storage_url, object_name, session_handler)


if __name__ == "__main__":
    logfile = '/tmp/pythontest.log'
    loglevel = logging.INFO

    logsetting(logfile, loglevel)

    is_valid_ops_request('LIST_EXT','')

    xx = convert_to_list('abc\ndef')
    print xx


    # bulkdeletecontainer('https://em2.storage.oraclecloud.com/v1/Storage-gse00000379', 'test', 'session_handler', '/tmp')

