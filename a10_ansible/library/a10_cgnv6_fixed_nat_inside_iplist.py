#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_iplist
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    inside_ip_list:
        description:
            - Name of IP List used to specify Inside Users
    
    partition:
        description:
            - Inside User Partition (Partition Name)
    
    nat_ip_list:
        description:
            - Name of IP List used to specify NAT addresses
    
    nat_start_address:
        description:
            - Start NAT Address
    
    nat_end_address:
        description:
            - IPv4 End NAT Address
    
    nat_netmask:
        description:
            - NAT Addresses IP Netmask
    
    vrid:
        description:
            - VRRP-A vrid (Specify ha VRRP-A vrid)
    
    dest_rule_list:
        description:
            - Bind destination based Rule-List (Fixed NAT Rule-List Name)
    
    dynamic_pool_size:
        description:
            - Configure size of Dynamic pool (Default: 0)
    
    method:
        description:
            - 'use-all-nat-ips': Use all the NAT IP addresses configured; 'use-least-nat-ips': Use the least number of NAT IP addresses required (default); choices:['use-all-nat-ips', 'use-least-nat-ips']
    
    offset:
        
    
    ports_per_user:
        description:
            - Configure Ports per Inside User (ports-per-user)
    
    respond_to_user_mac:
        description:
            - Use the user's source MAC for the next hop rather than the routing table (Default: off)
    
    session_quota:
        description:
            - Configure per user quota on sessions
    
    usable_nat_ports:
        
    
    uuid:
        description:
            - uuid of the object
    

"""

EXAMPLES = """
- name: Create fixed-nat with  ip-lsit
  a10_cgnv6_fixed_nat_inside_iplist.py:
        a10_host: "{{ inventory_hostname }}"
        a10_username: admin
        a10_password: a10
        state: present
        inside_ip_list: "NAT44-INSIDE1"
        nat_ip_list: "NAT44-OUTSIDE1"
        ports_per_user: 256
        session_quota: 6000
        method: use-all-nat-ips

"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"dest_rule_list","dynamic_pool_size","inside_ip_list","method","nat_end_address","nat_ip_list","nat_netmask","nat_start_address","offset","partition","ports_per_user","respond_to_user_mac","session_quota","usable_nat_ports","uuid","vrid",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        dest_rule_list=dict(
            type='str' 
        ),
        dynamic_pool_size=dict(
            type='str' 
        ),
        inside_ip_list=dict(
            type='str' , required=True
        ),
        method=dict(
            type='str' , choices=['use-all-nat-ips', 'use-least-nat-ips']
        ),
        nat_end_address=dict(
            type='str' 
        ),
        nat_ip_list=dict(
            type='str' 
        ),
        nat_netmask=dict(
            type='str' 
        ),
        nat_start_address=dict(
            type='str' 
        ),
        offset=dict(
            type='str' 
        ),
        partition=dict(
            type='str' 
        ),
        ports_per_user=dict(
            type='str' 
        ),
        respond_to_user_mac=dict(
            type='str' 
        ),
        session_quota=dict(
            type='str' 
        ),
        usable_nat_ports=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        vrid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/iplist/"
    f_dict = {}
    
    f_dict["inside_ip_list"] = ""
#    f_dict["partition"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/inside/iplist/{inside_ip_list}"
    f_dict = {}
    
    f_dict["inside_ip_list"] = module.params["inside_ip_list"]
#    f_dict["partition"] = module.params["partition"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("iplist", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result):
    payload = build_json("iplist", module)
    try:
        delete(module, result)
        post_result = module.client.post(new_url(module), payload)
        #post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)



def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
