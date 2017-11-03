#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb virtual server objects
(c) 2017 A10 Networks
TODO(documentation): Apache license
"""

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: a10_virtual_server
version_added: 1.8
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' virtual servers.
description:
    - Manage SLB (Server Load Balancing) virtual server objects on A10 Networks devices via acos-client/AXAPI 
author: "A10 Networks"
notes:
    - Requires acos-client (available in PyPi or https://github.com/a10networks/acos-client 
extends_documentation_fragment: a10
options:
  virtual_server:
    description:
      - The SLB (Server Load Balancing) virtual server name.
    required: true
    default: null
    aliases: ['vip', 'virtual']
  virtual_server_ip:
    description:
      - The SLB virtual server IPv4 address.
    required: false
    default: null
    aliases: ['ip', 'address']
  virtual_server_status:
    description:
      - The SLB virtual server status, such as enabled or disabled.
    required: false
    default: enable
    aliases: ['status']
    choices: ['enabled', 'disabled']
  virtual_server_ports:
    description:
      - A list of ports to create for the virtual server. Each list item should be a
        dictionary which specifies the C(port:) and C(type:), but can also optionally
        specify the C(service_group:) as well as the C(status:). See the examples
        below for details. This parameter is required when C(state) is C(present).
    required: false
'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new virtual server
- a10_virtual_server: 
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    partition: mypartition
    virtual_server: vserver1
    virtual_server_ip: 1.1.1.1
    virtual_server_ports:
      - port: 80
        protocol: TCP
        service_group: sg-80-tcp
      - port: 443
        protocol: HTTPS
        service_group: sg-443-https
      - port: 8080
        protocol: http
        status: disabled

'''

RETURN = '''
content:
  description: the full info regarding the slb_virtual
  returned: success
  type: dict 
  sample: "mynewvirtualserver"
'''


from a10_base import * 
from crudbase import *

VALID_PORT_FIELDS = ['port', 'protocol', 'service_group', 'status']
ACTION_KEY_MAP[DEFAULT_GET] = {
    "name": "name"
}
ACTION_KEY_MAP[DEFAULT_CREATE] = {
    "name": "name",
    "ip_address": "ip_address"
}
ACTION_KEY_MAP[DEFAULT_DELETE] = {
    "name": "name"
}

def validate_ports(module, ports):
    for item in ports:
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port' in item:
            try:
                item['port'] = int(item['port'])
            except:
                module.fail_json(msg="port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port field")

        # validate the port protocol is present, and convert it to
        # the internal API integer value (and validate it)
        if 'protocol' in item:
            protocol = axapi_get_vport_protocol(item['protocol'])
            if not protocol:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_VPORT_PROTOCOLS))
            else:
                item['protocol'] = protocol
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_VPORT_PROTOCOLS))

        # convert the status to the internal API integer value
        if 'status' in item:
            item['status'] = axapi_enabled_disabled(item['status'])
        else:
            item['status'] = 1

        # ensure the service_group field is at least present
        if 'service_group' not in item:
            item['service_group'] = ''

def needs_update(src_ports, dst_ports):
    '''
    Checks to determine if the port definitions of the src_ports
    array are in or different from those in dst_ports. If there is
    a difference, this function returns true, otherwise false.
    '''
    for src_port in src_ports:
        found = False
        different = False
        for dst_port in dst_ports:
            if src_port['port'] == dst_port['port']:
                found = True
                for valid_field in VALID_PORT_FIELDS:
                    if src_port[valid_field] != dst_port[valid_field]:
                        different = True
                        break
	        if found or different:
	            break
        if not found or different:
	    return True
    # every port from the src exists in the dst, and none of them were different
    return False

def get_argspec():
    return get_default_argspec(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            name=dict(type='str', aliases=['vip', 'virtual', 'virtual_server'], required=True),
            ip_address=dict(type='str', aliases=['ip', 'address', "virtual_server_ip"], required=True),
            status=dict(type='str', default='enabled', aliases=['status', 'virtual_server_status'], choices=['enabled', 'disabled']),
            vports=dict(type='list', aliases=["virtual_server_ports"], required=False, default=[]),
        ))

def run_command(module):
    ports = module.params["vports"]
    validate_ports(module, ports)
    state = module.params["state"]
    status = module.params["status"]

    try: 
        slb_virtual_data = get(module, module.params)
        result = slb_virtual_data
    # Gotta keep things idempotent
    except acos_errors.NotFound:
        slb_virtual_data = None

    slb_virtual_exists = not axapi_failure(slb_virtual_data)

    changed = False
    if state == 'present' and not slb_virtual_exists:
        # before creating/updating we need to validate that any
        # service groups defined in the ports list exist since
        # since the API will still create port definitions for
        # them while indicating a failure occurred
        checked_service_groups = []
        for port in ports:
            if 'service_group' in port and port['service_group'] not in checked_service_groups:
                #(TODO: HT)- Original version has this. Check if it is still needed
                if port['service_group'] == '':
                    continue
                try:
                    result = module.client.slb.service_group.get(port['service_group'])
                except Exception:
                    module.fail_json(msg="the service group %s specified in the ports list does not exist" % port['service_group'])
                checked_service_groups.append(port['service_group'])

        if True:
            #(TODO: HT)- Check out what this does
            status = axapi_enabled_disabled(status)
            try:
                result = create(module, module.params)
            except acos_errors.Exists:
                if axapi_failure(result):
                    module.fail_json(msg="failed to create the virtual server: %s" % result['response']['err']['msg'])
                changed = True
        else:
            defined_ports = slb_virtual_data.get('virtual_server', {}).get('vport_list', [])

            # we check for a needed update both ways, in case ports
            # are missing from either the ones specified by the user
            # or from those on the device
            if needs_update(defined_ports, ports) or needs_update(ports, defined_ports):
                result = module.update(module, params)
                if axapi_failure(result):
                    module.fail_json(msg="failed to create the virtual server: %s" % result['response']['err']['msg'])
                changed = True

        # if we changed things, get the full info regarding
        # the service group for the return data below
        if changed:
            result = get(module, module.params)
        else:
            result = slb_virtual_data
    elif state == 'absent':
        if slb_virtual_exists:
            result = delete(module, module.params)
            changed = True
        else:
            result = dict(msg="the virtual server was not present")

    # log out of the session nicely and exit
    module.exit_json(changed=changed, content=result)

# standard ansible module imports
def main():
    module = a10_module(argument_spec=get_argspec())
    module.mod_path = module.client.slb.virtual_server 
    result = run_command(module)
    module.exit_json(changed=False, content=result)

if __name__ == '__main__':
    main()
