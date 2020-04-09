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
    - Requires A10 Networks aXAPI 3.0
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
  overwrite:
    description:
      - If the cert is found, should you overwrite or just ignore it
        only applicable when state == present
    required: false
    default: 'no'
    choices: ['yes', 'no']    
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
- a10_aflex_v3: 
    host: "{{inventory_hostname}}"
    username: admin
    password: a10
    validate_certs: no
    partition: PARTNAME
    state: present
    file_name: abc
    method: upload
    overwrite: yes
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
        'Content-Disposition: form-data; name="json"; filename="blob"',
        'Content-Type: application/json'  + CLRF,
        '{"aflex": {"file": "%s", "file-handle": "%s", "action":"import"}}' % (name, filename), 
        boundary,
        'Content-Disposition: form-data; name="file"; filename="%s"' % filename,
        'Content-Type: text/plain'  + CLRF]
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
            writeFile(filename, filename, data, field_boundary, payload, needsCLRF)
        finally:
            f.close()
    except Exception, e:
        raise e
    payload.write(CLRF + field_boundary + '--' + CLRF)
    return header_boundary,payload.getvalue()

def uploadAflex(url, name, filepath, signature):
    boundary,data = buildPayload(filepath)
    response = None
    try:
        response = open_url(url, data, 
            {
                'Content-Type' : 'multipart/form-data; boundary=%s' % boundary, 
                'Authorization': 'A10 %s' % signature,
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
            overwrite=dict(type='bool', default=False, required=False),            
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
    overwrite = module.params['overwrite']    

  
    if method and method != 'upload' and method != 'download':
        module.fail_json(msg="method must be one of 'upload' or 'download'")

    # authenticate
    axapi_base_url = 'https://%s/axapi/v3/' % host
    signature = axapi_authenticate_v3(module, axapi_base_url + 'auth', username, password)

    # change partitions if we need to
    if part:
        part_change_result = axapi_call_v3(module, axapi_base_url + 'active-partition/' + part, method="POST", signature=signature, body="")
        if (part_change_result['response']['status'] == 'fail'):
            # log out of the session nicely and exit with an error
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=part_change_result['response']['err']['msg'])

    # look for the aflex script on the device
    aflex_data = axapi_call_v3(module, axapi_base_url + 'file/aflex/' + file_name, method="GET", signature=signature)
    aflex_content = ""
    
    if ('response' in aflex_data and aflex_data['response']['status'] == 'fail'):
        if (aflex_data['response']['code'] == 404):
            aflex_exists = False
        else:
            logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg=aflex_data['response']['err']['msg'])
    else:
        aflex_content = aflex_data['response']['data']
        aflex_exists = True
        
    changed = False
    if state == 'present':

        if (method == "upload" and aflex_exists and overwrite) or (method == "upload" and not aflex_exists):

            if os.path.isfile(file_name) is False:
                # log out of the session nicely and exit with an error
                result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg='File does not exist ' + file_name)
            else:
                try:
                    result = uploadAflex(axapi_base_url + 'file/aflex', file_name, file_name, signature=signature)
                except Exception, e:
                    # log out of the session nicely and exit with an error
                    #err_result = e['changed']
                    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                    module.fail_json(msg=e)

            if axapi_failure(result):
                # log out of the session nicely and exit with an error
                result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                module.fail_json(msg="failed to upload the aflex: %s" % result['response']['err']['msg'])

            changed = True

        elif method == "download" and aflex_exists:
            saveFile(file_name, aflex_content)
            
        elif method == "download" and not aflex_exists:
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg="aflex cannot be found the device")

    elif state == 'absent':
        # does the aflex exist on the load balancer
        if aflex_exists:
            result = axapi_call_v3(module, axapi_base_url + 'file/aflex', method="POST", signature=signature, body={"aflex": {"file": file_name, "action":"delete"}})
            
            if ('response' in result and result['response']['status'] == 'fail'):
                # log out of the session nicely and exit with an error
                logoff_result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
                #module.fail_json(msg=result['response']['err']['msg'])
                module.fail_json(msg=result['response'])
            else:
                changed = True
                
        else:
            result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
            module.fail_json(msg="aflex not found on device")


    # log out of the session nicely and exit
    result = axapi_call_v3(module, axapi_base_url + 'logoff', method="POST", signature=signature, body="")
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
