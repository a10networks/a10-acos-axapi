#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging as LOG
LOG.basicConfig(filename=".debug", level=LOG.DEBUG)

from a10_base import *
from crudbase import *

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = ''' '''

VALID_SERVICE_GROUP_FIELDS = ['name', 'service_group', 'protocol', 'lb_method']
VALID_SERVER_FIELDS = ['server', 'port', 'status']


VALID_PORT_FIELDS = ['port', 'protocol', 'service_group', 'status']
ACTION_KEY_MAP[DEFAULT_GET] = {
    "name": "name"
}
ACTION_KEY_MAP[DEFAULT_CREATE] = {
    "name": "name",
    "protocol": "protocol",
    
}
ACTION_KEY_MAP[DEFAULT_DELETE] = {
    "name": "name",
    "protocol": "protocol",
    "lb-method": "lb-method",
    "lc-method": "lc-method"
}


def standardize_members(members):
    for member in members:
        if member.get("state") == "disabled":
            member["state"] = 1
        else:
            member["state"] = 0
    return members

def get_member_server(client, sg_name, member_name, port):
    try:
        return client.slb.service_group.member.get(sg_name,
                member_name,
                port)
    except acos_errors.NotFound:
        pass

def get_member_list(client, sg_name):
    try:
        return client.slb.service_group.member.get_list(sg_name)
    except acos_errors.NotFound:
        pass

def check_update_member(client, member, slb_member):
    member["member-state"] = member.pop("state")
    if member["member-state"] == 1:
        member["member-state"] = "disable"
    else:
        member["member-state"] = "enable"
    for k,v in member.items():
        if not slb_member["member"].get(k) == v:
            return True
    return False

def get_service_group(client, sg_name):
    try:
        return client.slb.service_group.get(sg_name)
    except acos_errors.NotFound:
        return None

def check_update_sg(client, service_group, slb_sg):
        for k,v in service_group.items():
            if not slb_sg["service-group"].get(k) == v:
                return True
        return False

def get_argspec():
    return get_default_argspec(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            name=dict(type='str', required=True, aliases=['service_group', 'pool', 'group']),
            protocol=dict(type='str', default='tcp', aliases=['proto', 'service_group_protocol'],
                          choices=['tcp', 'udp']),
            lb_method=dict(type='str', aliases=['lb-method'],
                                       choices=['round-robin',
                                                'weighted-rr',
                                                'fastest-response',
                                                'round-robin-strict',
                                                'src-ip-only-hash',
                                                'src-ip-hash']),
            lc_method=dict(type='str', aliases=['lc-method'],
                                       choices=['least-connection',
                                               'weighted-least-connection',
                                               'service-least-connection',
                                               'service-weighted-least-connection']),
            members=dict(type='list', aliases=['member'], default=[], required=False),
        )
    )

def main():
    module = a10_module(argument_spec=get_argspec())
    module.mod_path = module.client.slb.service_group
    result = run_command(module)
    module.exit_json(changed=False, content=result)


def run_command(module):
    # Get this from host data
    state = module.params['state']
    members = module.params['members']

    sg_name = module.params.get("name") or module.params.get("service_group")
    lb_method = module.params["lb_method"]
    lc_method = module.params["lc_method"]
    protocol = module.params["protocol"]

    members = standardize_members(members)

    if sg_name is None:
        module.fail_json(msg='service_group is required')

    if lc_method and lb_method:
        module.fail_json(msg='only one load balancing method allowed')

    service_group = dict(name=sg_name, protocol=protocol)

    if lb_method:
        service_group['lb-method'] = lb_method

    if lc_method:
        service_group['lc-method'] = lc_method
        lb_method = lc_method

    changed = False
    result = None

    if state == 'absent':
        member_list = {} # get_member_list(module.client, sg_name)
        if member_list:
            for member in member_list['member-list']:
                result = module.client.slb.service_group.member.delete(sg_name,
                                                                       member['name'],
                                                                       member['port'])
                changed = True
            LOG.debug("Deleted members")

        try:
            result = module.client.slb.service_group.delete(sg_name)
            changed = False 
            LOG.debug("Deleted service group")
        except acos_errors.NotFound:
            result="service group does not exist"
       
    elif state == 'present':
        slb_sg = get_service_group(module.client, sg_name)
        
        if slb_sg:
            update = check_update_sg(module.client, service_group, slb_sg)
            if update:
                result = update(module, module.params)
                changed = True
                LOG.debug("Updated service group")

        else:
            result = create(module, module.params)
            changed = True
            LOG.debug("Created service group")

        for member in members:
            slb_member = get_member_server(module.client, sg_name, member["name"], member["port"])
            if slb_member:
                update = check_update_member(module.client, member, slb_member)
                if update:
                    result = module.client.slb.service_group.member.update(sg_name,
                                                                           member["name"],
                                                                           member["port"])
                                                                          #member_state=member["member-state"])
                    changed = True
                    LOG.debug("Updated member server")
                else:
                   result = module.client.slb.service_group.member.associate(sg_name,
                                                                           member["name"],
                                                                           member["port"])
                                                                           #member_state=member["state"])
                   changed = True
                   LOG.debug("Associated member server")


    module.exit_json(changed=changed, content=result)


if __name__ == '__main__':
    main()
