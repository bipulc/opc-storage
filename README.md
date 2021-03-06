## Python API / CLI for Oracle Storage Cloud Service

#### About

opc-storage is a set of functions written in python using Requests module to enable interacting with Oracle Storage Cloud ( Object Storage). Currently the following operations are supported:

```
LISTING of containers and objects
CREATE new Containers
UPLOAD new object / UPDATE existing object
DELETE single object
DELETE all objects in a container (BULK DELETE)
DOWNLOAD an object to local machine
```

This repository contains a python CLI script, python module and a configuration file. The configuration file is used by wrapper script to build command line utility called `opc-obj-storage.py`. The python module `opcstorage.py` can be imported and its functions can be used should you choose to build your own wrapper or need to access OPC Object Storage from your python code. 
Note that this is __NOT__ Oracle official Python SDK. Check out [Oracle Documentation](http://docs.oracle.com/en/cloud/iaas/storage-cloud/cssto/index.html) for Storage Cloud Service Java SDK, CLI and RESTful API.

**It is developed using Python 2.7 on Mac OS X El Capitan (10.11.6), tested on Mac OS X El Capitan and Oracle Linux 7.2 and should work on any other OS using Python 2.7 with the dependent packages installed**

#### Package Dependencies ####
This tool requires the following Python packages.

```
sys, os, argparse, getpass, requests, time, logging, ConfigParser, json, re, collections
```

#### Directory structure of repository:
```
    bin —> contains wrapper script opc-obj-storage.py.
    etc —> contains configuration file with inline documentation for each item.
    lib —> contains the main module file opcstorage.py.  A selection of functions are listed below. Functions are documented and can be accessed using help(opcstorage).
```
#### opcstorage module documentation:

```
NAME
    opcstorage

DESCRIPTION
    Python Wrapper for OPC Standard Storage (Object Storage) RESTFul APIs

FUNCTIONS
    bulkdeletecontainer(storage_url, container_name, session_handler, dir_path)
        Bulk Delete objects from a container.
    
    createcontainer(storage_url, container_name, session_handler)
        Create an empty container
    
    deleteobject(storage_url, object_name, session_handler)
        Delete an object from storage cloud service. Should pass FQN for object to be deleted
    
    downloadobject(storage_url, object_name, session_handler, download_dir)
        Download object to download directory.
    
    listallcontainer(storage_url, session_handler)
        Return Last Modified, Size and Number of Objects in all containers in the account
    
    listallobjectsincontainer(storage_url, container_name, session_handler)
        Return Last Modified, Size of all Objects in a container

    listcontainer(url, object_name, session_handler)
        Return Last Modified, Size and Number of all Objects in a container
    
    listobject(object_name, url, session_handler)
        Return Last Modified and Size of object stored at input uri.
    
    opcexec(operation, identity_domain, object_name, storage_url, cert_file, username, password, download_dir, file_name)
        Main function to get session object, validate input and call appropriate sub-function
      
    uploadobject(storage_url, file_name, container_name, session_handler)
        Upload object to Storage Cloud. Pass FQN of the file to be uploaded. Object name will be same as file name

```

Note that these are supported on Oracle Public Cloud (OPC) and not on Oracle Bare Metal Cloud. Python SDK for interacting with Oracle Bare Metal Cloud is available at [Oracle BMC Storage Phython SDK](https://github.com/oracle/bmcs-python-sdk).


#### Usage:

```
  opc-obj-storage.py -h
  usage: opc-obj-storage.py [-h] -c C -o O [-n N] [-f F]

  optional arguments:
    -h, --help  show this help message and exit
    -c C        configuration file
    -o O        operations
                {BULK_DELETE|CREATE|DELETE|DOWNLOAD|LIST|LIST_EXT|UPLOAD}
    -n N        'container name' for BULK_DELETE, CREATE, UPLOAD and LIST
                operations or 'object name' for DELETE and DOWNLOAD operations
    -f F        filename to upload to Storage cloud

```
- LIST Operation

    List name, size and last modified for all containers in the identity domain if no container name is specified via argument -n|N
    List  size and last modified for the container specified via argument -n|N
    
- LIST_EXT Operation

    List name, size and last modified for all objects in container specified via argument -n|N. Container Name is mandatory for LIST_EXT operation.

- DELETE Operation

    Delete object specified via argument -n|N. Object name should have full path e.g. "MyContainer/MyFirstObject.txt"

- BULK_DELETE Operation

   Delete all objects in container specified via argument -n|N. Container name is mandatory for BULK_DELETE operation.

- DOWNLOAD Operation

    Download object specified via argument -n|N  to download_dir ( as specified in configuration file) in filename same as object name. Object name should have full path e.g. "MyContainer/MyFirstObject.txt” and downloaded file will be MyFirstObject.txt

- CREATE Operation

    Create an empty container specified via argument -n|N.

- UPLOAD Operation

    Upload a new object or update an existing one specified via argument -n|N. 
    Argument -f|F takes the name of the file to be uploaded from local machine.

#### Installation

1. Download source code from "Clone or Download" link.
2. Unzip in any directory on your computer.
3. Install certificate file as per instruction from [cURL Documentation site](https://curl.haxx.se/docs/caextract.html). Its as easy as download the cacert.pem file and store in a directory ( e.g. I have stored the cacert.pem file in /Users/bipul/keys directory)
4. Create configfile in etc directory. An example configfile is provided. Update the values as appropriate. 
5. Change directory to bin, and run ./opc-obj-storage.py -h to verify installation.

#### Example
```
1. LIST all containers
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o LIST

2. LIST container BIPUL
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o LIST -n BIPUL

3. LIST all objects in container BIPUL
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o LIST_EXT -n BIPUL

4. CREATE a Conatiner
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o CREATE -n NEW_CONTAINER

5. Upload an object to a container
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o UPLOAD -n NEW_CONTAINER -f /Users/bipul/Downloads/cnt2637221-6.pptx

6. Download an object to local machine
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o DOWNLOAD -n NEW_CONTAINER/cnt2637221-6.pptx

7. Delete an Object from a container
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o DELETE -n NEW_CONTAINER/cnt2637221-6.pptx

8. Bulk Delete all objects from a container
/Users/bipul/python/tools/opc-storage/bin/opc-obj-storage.py -c /Users/bipul/python/tools/opc-storage/etc/configfile -o BULK_DELETE -n BULK_DELETE_TEST

```

#### Limitations / workaround

- DELETE operation

   Does not include - "multipart-manifest=delete” option
   
   Impact - For static large objects, only manifest file is deleted but not the segment files.
   
   Workaround - Pass segment object name in a separate call to opc-storage tool Or use [Java based CLI](http://docs.oracle.com/en/cloud/iaas/storage-cloud/csclr/deleting-object.html)

- UPLOAD operation

    Uploading multiple objects from an archive is not supported.
    
    Doesn’t support objects larger than 5GB.
    
    Use [Java based CLI for static large objects](http://docs.oracle.com/en/cloud/iaas/storage-cloud/csclr/uploading-files.html)
    
- DOWNLOAD operation

     Download of multipart object is not supported
     
     Use [Java based CLI for multipart objects](http://docs.oracle.com/en/cloud/iaas/storage-cloud/csclr/downloading-object.html)


#### Known Issues:
Following error occurs occasionally on BULK_DELETE call. However, the delete operation succeeds.

An error occurred : ('Connection aborted.', error(54, 'Connection reset by peer’))
