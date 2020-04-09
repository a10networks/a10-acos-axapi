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
module: a10_http_template
version_added: 2.2.0.0
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage http template objects on A10 Networks devices via aXAPI
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
      - L3V partition to add the template to.  Will be added to 'shared' if not specified
    required: false
    default: null
    choices: []
  state:
    description:
      - create, update or remove template
    required: false
    default: present
    choices: ['present', 'absent']
  failover_url:
    description: 
    - Specifies the fallback URL to send in an HTTP 302 response when all real servers are down.
    - length 0 to 255
    required: false
    default: ""
  strict_transaction_switching:
    description:
    - Strict transaction switching.
    required: false
    default: 0
  client_ip_insert:
    description:
      - Inserts the client’s source IP address into HTTP headers. "client_ip_insert" has sub elements.
    required: false
    default: {}
  retry_http_request:
    description:
      - retry the http requests given the response codes provided
    required: false
    default: {}
  log_retry:
    description:
      - logs https retries
    required: false
    default: 0
  terminate_http1_1_client_when_request_has_condition_close:
    description:
      - Enable ACOS device to terminate HTTP 1.1 client connections when the “Connection close” header exists in the HTTP request.
    required: false
    default: 0
  no_http_by_pass:
    description:
      - Redirects non-HTTP traffic to a specific service group.
      - length is 0 to 63 characters
    required: false
    default: ""
  logging_template:
    description:
      - Specifies a logging template to use for external logging of HTTP events of TCP
      - length is 0 to 63 characters
    required: false
    default: ""
  request_header_erase_list:
    description:
      - Erases the request header
      - length of each name is 0 to 63 characters
    required: false
    default: []
  response_header_erase_list:
    description:
      - Erases the response header
      - length of each name is 0 to 63 characters
    required: false
    default: []
  request_header_insert_list:
    description:
      - Inserts request header
    required: false
    default: []
  response_header_insert_list:
    description:
      - Inserts response header
    required: false
    default: []
  response_content_replace_list:
    description:
      - Replaces response content
    required: false
    default: []
  host_hits_enable:
    description:
      - Enables host hit counters.
    required: false
    default: 0
  url_switching_case_insensitive:
    description:
      - Enable case insensitive matching for URL switching rules.
    required: false
    default: 0
  url_switching_hits_enable:
    description:
      - Enable URL hits.
    required: false
    default: 0
  url_hash_persist:
    description:
      - Enables server stickiness based on has values.
    required: false
    default: {}
  redirect_rewrite_list:
    description:
      - Modifies redirects sent by servers by rewriting the matching URL string to the specified value before sending the redirects to clients.
    required: false
    default: []
  https_rewrite:
    description:
      - rewrite https
      - range is 0 to 65535
    required: false
    default: 0
  compression:
    description:
      - Offloads Web servers from CPU-intensive HTTP compression operations.
    required: false
    default: {}
  name:
    description:
      - name of the template
    required: true
  url_switching_list:
    description:
      - a list of url switching parameters, to switch traffic to a different service group if url startswith/contains/endswith a specified string
      - each list item must contain url, service_group, match_method
      - match_method can be 0=contains, 1=startswith, 2=endswith, 3=equals
    required: false
    default: null
  host_switching_list:
    description:
      - a list of host switching parameters, to switch traffic to a different service group if host startswith/contains/endswith a specified string
      - each list item must contain host, service_group, match_method
      - match_method can be 0=contains, 1=startswith, 2=endswith
    required: false
    default: null
  write_config:
    description:
      - If C(yes), any changes will cause a write of the running configuration
        to non-volatile memory. This will save I(all) configuration changes,
        including those that may have been made manually or through other modules,
        so care should be taken when specifying C(yes).
    required: false
    version_added: 2.2
    default: 'no'
    choices: ['yes', 'no']
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    version_added: 2.2.0.0
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new HTTP Template
- a10_http_template: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    name: my_http_templ
    url_switching_list:
      - url: english
        service_group: sg-80-tcp
        match_method: 0
'''


def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            partition=dict(type='str', aliases=['partition','part'], required=False),
            name=dict(type='str', required=True),
            failover_url=dict(type='str', required=False, default=None),
            strict_transaction_switching=dict(type='bool', required=False, default=False),
            client_ip_insert=dict(type='dict', required=False, default={}),
            retry_http_request=dict(type='dict', required=False, default={}),
            log_retry=dict(type='bool', required=False, default=False),
            terminate_http1_1_client_when_request_has_condition_close=dict(type='bool', required=False, default=False),
            no_http_by_pass=dict(type='str', required=False, default=None),
            logging_template=dict(type='str', required=False, default=None),
            request_header_erase_list=dict(type='list', required=False, default=[]),
            response_header_erase_list=dict(type='list', required=False, default=[]),
            request_header_insert_list=dict(type='list', required=False, default=[]),
            response_header_insert_list=dict(type='list', required=False, default=[]),
            response_content_replace_list=dict(type='list', required=False, default=[]),
            host_switching_list=dict(type='list', required=False, default=[]),
            host_hits_enable=dict(type='bool', required=False, default=False),
            url_switching_list=dict(type='list', required=False, default=[]),
            url_switching_case_insensitive=dict(type='bool', required=False, default=False),
            url_switching_hits_enable=dict(type='bool', required=False, default=False),
            url_hash_persist=dict(type='dict', required=False, default={}),
            redirect_rewrite_list=dict(type='dict', required=False, default={}),
            https_rewrite=dict(type='int', required=False, default=0),
            compression=dict(type='dict', required=False, default={}),
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
    write_config = module.params['write_config']

    # create a list of all possible parameters
    param_names = ['name',
        'failover_url',
        'strict_transaction_switching',
        'client_ip_insert',
        'retry_http_request',
        'log_retry',
        'terminate_http1_1_client_when_request_has_condition_close',
        'no_http_by_pass',
        'logging_template',
        'request_header_erase_list',
        'response_header_erase_list',
        'request_header_insert_list',
        'response_header_insert_list',
        'response_content_replace_list',
        'host_switching_list',
        'host_hits_enable',
        'url_switching_list',
        'url_switching_case_insensitive',
        'url_switching_hits_enable',
        'url_hash_persist',
        'redirect_rewrite_list',
        'https_rewrite',
        'compression']


    # put the parameters into a dictionary
    params = {}
    for curr_param_name in param_names:
        params[curr_param_name] =  module.params[curr_param_name]
    
    # http_template name is mandatory
    if params['name'] is None:
        module.fail_json(msg='name is required')

    axapi_base_url = 'https://%s/services/rest/V2.1/?format=json' % host
    session_url = axapi_authenticate(module, axapi_base_url, username, password)

    # change partitions if we need to
    if part:
        result = axapi_call(module, session_url + '&method=system.partition.active', json.dumps({'name': part}))
        if (result['response']['status'] == 'fail'):
            module.fail_json(msg=result['response']['err']['msg'])

        # need to prepend the service_group with the partition name in url and host switching templates
        if params['url_switching_list']:
            for item in params['url_switching_list']:
                item['service_group'] = '?' + part + '?' + item['service_group']

        if params['host_switching_list']:
            for item in params['url_switching_list']:
                item['service_group'] = '?' + part + '?' + item['service_group']


    # bare base json body for the creation of the http template
    json_post = {
        "http_template": {
            "name": params['name'],
            "failover_url": "",
            "strict_transaction_swiching": 0,
            "client_ip_insert": {
                "header": "",
                "replace": 0
            },
            "retry_http_request": {
                "http5xx": 0,
                "http5xx_pre_request": 0
            },
            "log_retry": 0,
            "terminate_http1_1_client_when_request_has_condition_close": 0,
            "no_http_by_pass": "",
            "logging_template": "",
            "request_header_erase_list": [],
            "response_header_erase_list": [],
            "request_header_insert_list": [],
            "response_header_insert_list": [],
            "response_content_replace_list": [],
            "host_switching_list": [],
            "host_hits_enable": 0,
            "url_switching_list": [],
            "url_switching_case_insensitive": 0,
            "url_switching_hits_enable": 0,
            "url_hash_persist": {
                "position": 1,
                "length": 0,
                "use_server_status": 0,
                "offset": 0
            },
            "redirect_rewrite_list": [],
            "https_rewrite": 0,
            "compression": {
                "status": 0,
                "keep_accept_encoding": 0,
                "level": 1,
                "min_content_len": 0,
                "content_type_list": [],
                "exclude_content_type_list": [],
                "exclude_url_list": [],
                "auto_disable_on_high_cpu": 0
            },
            "request_line_case_insensitive": 0,
            "keep_client_alive": 0,
            "req_hdr_wait_time": 0
        }
    }

    # modify the json body with only the parameters that have been passed in
    for pn in param_names:
        if params[pn]:
            json_post['http_template'][pn] = params[pn]

   
    # check to see if this http_template exists
    http_template_data = axapi_call(module, session_url + '&method=slb.template.http.search', json.dumps({'name': params['name']}))
    http_template_exists = not axapi_failure(http_template_data)

    changed = False
    if state == 'present':

        # if the template doesn't exist then create it, otherwise update it
        if not http_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.http.create', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to create the http template: %s" % result['response']['err']['msg'])

        else:
            result = axapi_call(module, session_url + '&method=slb.template.http.update', json.dumps(json_post))
            if axapi_failure(result):
                module.fail_json(msg="failed to update the http template: %s" % result['response']['err']['msg'])

        changed = True

    elif state == 'absent':
        if http_template_exists:
            result = axapi_call(module, session_url + '&method=slb.template.http.delete', json.dumps({'name': params['name']}))
            changed = True
        else:
            result = dict(msg="the http template was not present")

    # if the config has changed, save the config unless otherwise requested
    if changed and write_config:
        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
        if axapi_failure(write_result):
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    axapi_call(module, session_url + '&method=session.close')
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10 import *

if __name__ == '__main__':
    main()
