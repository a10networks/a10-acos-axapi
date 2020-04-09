#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks objects
(c) 2016, Fadi Hafez <fhafez@a10networks.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: a10_aflex
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage extended aflex objects on A10 Networks devices via aXAPI
author: Fadi Hafez using works of Mischa Peters
notes:
    - Requires A10 Networks aXAPI 2.1
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    aliases: ['user', 'admin']
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    aliases: ['pass', 'pwd']
  partition:
    description:
      - L3V partition to upload/download/delete aflex from/to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create or remove aflex
    required: false
    default: present
    choices: ['present', 'absent']
  aflex_name:
    description:
      - aflex to upload/download
    required: false
    aliases: ['filename']
  method:
    description:
      - One of 'upload', 'download'
    required: false
    default: null
    choices: ['upload','download']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Upload an aflex
- a10_aflex: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: PART_A
    aflex: my_aflex
    method: upload
'''

CLRF = '\r\n'
Empty = ''

def clrf(writer, should):
    if should is True:
        writer.write(CLRF)

def saveFile(filename, data):

    try:
        f = open(filename, 'wb')
        try:
            f.write(data)
        finally:
            f.close()
    except Exception, e:
        raise e


def writeFile(name, filename, body, boundary, writer, needsCLRF):
    clrf(writer, needsCLRF)
    block = [boundary, 
        'Content-Disposition: form-data; name="%s"; filename="%s"' % (name, filename),
        'Content-Type: application/octet-stream'  + CLRF
    ]
    writer.write(CLRF.join(block))
    writer.write(CLRF)
    writer.write(body)
    writer.write(CLRF)

def buildPayload(filename):
    header_boundary = '--' + mimetools.choose_boundary()
    field_boundary = '--' + header_boundary
    payload = io.BytesIO()
    needsCLRF = False
    try:
        f = open(filename, 'rb')
        try:
            data = f.read()
            writeFile("upload", filename, data, field_boundary, payload, needsCLRF)
        finally:
            f.close()
    except Exception, e:
        raise e
    payload.write(CLRF + field_boundary + '--' + CLRF)
    return header_boundary,payload.getvalue()

def uploadAflex(url, name, filepath):
    boundary,data = buildPayload(filepath)
    response = None
    try:
        response = open_url(url, data, 
            {
                'Content-Type' : 'multipart/form-data; boundary=%s' % boundary, 
                'X-Requested-By' : 'ansible', 
                'User-Agent': 'ansible', 
                'Accept':'*/*'
            },
            validate_certs=False,
            method='POST')
        changed = response.getcode() == 200
    except Exception, e:
        e.args += (response,)
        raise e

    return changed, response.getcode()

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            file_name=dict(type='str', aliases=['filename'], required=False),
            method=dict(type='str', choices=['upload','download'], required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    part = module.params['partition']
    state = module.params['state']
    file_name = module.params['file_name']
    method = module.params['method']

  
    if method and method != 'upload' and method != 'download':
        module.fail_json(msg="method must be one of 'upload' or 'download'")

    axapi_base_url = 'http://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg=result['response']['err']['msg'])

    aflex_data = axapi_call(module, session_url + '&method=slb.aflex.search', json.dumps({'name': file_name}))
    aflex_exists = not axapi_failure(aflex_data)

    changed = False
    if state == 'present':

        if method == "upload":

            if not aflex_exists:

                if os.path.isfile(file_name) is False:
                    # log out of the session nicely and exit with an error
                    axapi_call(module, session_url + '&method=session.close')
                    module.fail_json(msg='File does not exist')
                else:
                    try:
                        result = uploadAflex(session_url + '&method=slb.aflex.upload&name=' + file_name, 'upload', file_name)
                    except Exception, e:
                        # log out of the session nicely and exit with an error
                        #err_result = e['changed']
                        axapi_call(module, session_url + '&method=session.close')
                        module.fail_json(msg=e)

                if axapi_failure(result):
                    # log out of the session nicely and exit with an error
                    axapi_call(module, session_url + '&method=session.close')
                    module.fail_json(msg="failed to upload the aflex: %s" % result['response']['err']['msg'])

                changed = True

        elif method == "download":

            result = axapi_call(module, session_url + '&method=slb.aflex.download&name=' + file_name, '')
            if ('response' in result and result['response']['status'] == 'fail' and 'failed' in result['response']['err']['msg']):
                # log out of the session nicely and exit with an error
                axapi_call(module, session_url + '&method=session.close')
                module.fail_json(msg=result['response']['err']['msg'])
            else:
                saveFile(file_name, result['response']['err']['msg'])

    elif state == 'absent':
        # does the aflex exist on the load balancer
        result = axapi_call(module, session_url + '&method=slb.aflex.search', json.dumps({'name': file_name}))
        if ('response' in result and result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg=result['response']['err']['msg'])

        result = axapi_call(module, session_url + '&method=slb.aflex.delete', json.dumps({'name': file_name}))
        if ('response' in result and result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            axapi_call(module, session_url + '&method=session.close')
            module.fail_json(msg=result['response']['err']['msg'])
        else:
            changed = True

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *
import mimetools
import mimetypes
import io

if __name__ == '__main__':
    main()
