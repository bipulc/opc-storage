#!/usr/bin/python
'''Python Wrapper for OPC Standard Storage (Object Storage) RESTFul APIs
# ---  TO DO List --- #
# -- Add exception handling at all appropriate call -- #
'''

import sys, os, argparse, getpass, requests, time, logging, ConfigParser, json
from collections import defaultdict


def logsetting(logfile, loglevel):
    logging.basicConfig(level=loglevel,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename=logfile,
                        filemode='a')


def log(logmessage):
    logging.info(logmessage)
    print logmessage


def convertsize(B):
   'Return the given bytes as a human friendly KB, MB, GB, or TB string'

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
    if operation not in ('LIST','LIST_EXT','DELETE','BULK_DELETE','DOWNLOAD'):
        message = '{:50} {:40}'.format('Invalid Operation Request! Should be one of - ','LIST|LIST_EXT|DELETE|BULK_DELETE|DOWNLOAD')
        log(message)
        exit(1)
    if operation == 'LIST_EXT' and object_name is None:
        message = '{:80}'.format('Invalid Operation Request! Should specify container name for extended listing')
        log(message)
        exit(1)


def getsessionobject(username,password,cert_file):

    try:
        s = requests.Session()
        s.auth = (username, password)
        s.verify = cert_file
        return s
    except Exception as e:
        log('An error occurred : %s\n' % e)
        raise


def getcontainerinfo(url, session):

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

    header = '{:30} {:30} {:>20} {:>20}'.format('container name','last modified','number of objects','size of container')
    log(header)
    log(' ')


def print_object_header(container_name):

    header = '{:30} {:>30}'.format('container name : ',container_name)
    log(header)
    header = '{:50} {:>30} {:>10}'.format('object name','last modified','size of object')
    log(header)
    log(' ')


def pretty_output(ci_dict, container_name):

    last_modified = time.ctime(float(ci_dict[container_name]['X-Last-Modified-Timestamp']))
    size = convertsize(ci_dict[container_name]['X-Container-Bytes-Used'])
    num_object = ci_dict[container_name]['X-Container-Object-Count']

    detail = '{:30} {:30} {:>20} {:>20}'.format(container_name, last_modified, num_object, size)
    log(detail)


def pretty_object_output(oi_dict, object_name):

    last_modified = oi_dict[object_name]['Last-Modified']
    size = convertsize(oi_dict[object_name]['Content-Length'])

    detail = '{:50} {:>30} {:>10}'.format(object_name, last_modified, size)
    log(detail)


def convert_to_list(in_str):
    ' Convert output stream from REST CALL response to a list of elements breaking at new line '

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


def opcexec(operation, identity_domain, object_name, storage_url, cert_file, username, password):
    '''
    For LIST Operation,
        if a container name is passed to arg.n, then list all objects in that container
        if an object name is passed to arg.n, then list just that object
        if arg.n is not  supplied, then list all containers in the identity domain

    For DELETE Operation,
        if a conatiner name is passed to arg.n, then delete the container if it is empty.
        if an object name is passed to arg.n, then delete the object

    For BULK_DELETE Operation,
        arg.n should be name of a container. Generate list of objects within that container and Bulk Delete

    For DOWNLOAD Operation,
        arg.d should be directory
        If arg.n is an object, then download it.
        If arg.n is a container, then download all objects within that container.
        Downloaded filename should be same as name of object
    '''

    headers = {
        'X-ID-TENANT-NAME': identity_domain
    }

    session_handler = getsessionobject(username,password,cert_file)

    if operation == 'LIST':
        if object_name:

            listcontainer(storage_url, object_name, session_handler)

        else:

            listallcontainer(storage_url, session_handler)

    elif operation == 'LIST_EXT':

        listallobjectsincontainer(storage_url, object_name, session_handler)


if __name__ == "__main__":
    logfile = '/tmp/pythontest.log'
    loglevel = logging.INFO

    logsetting(logfile, loglevel)

    is_valid_ops_request('LIST_EXT','')

    xx = convert_to_list('abc\ndef')
    print xx


