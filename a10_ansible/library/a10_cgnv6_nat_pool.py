#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_pool
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    pool_name:
        description:
            - Specify pool name or pool group
    
    start_address:
        description:
            - Configure start IP address of NAT pool
    
    end_address:
        description:
            - Configure end IP address of NAT pool
    
    netmask:
        description:
            - Configure mask for pool
    
    exclude_ip:
        
    
    vrid:
        description:
            - Configure VRRP-A vrid (Specify ha VRRP-A vrid)
    
    max_users_per_ip:
        description:
            - Number of users that can be assigned to a NAT IP
    
    shared:
        description:
            - Share this pool with other partitions (default: not shared)
    
    group:
        description:
            - Share with a partition group (Partition Group Name)
    
    partition:
        description:
            - Share with a single partition (Partition Name)
    
    all:
        description:
            - Share with all partitions
    
    port_batch_v2_size:
        description:
            - '64': Allocate 64 ports at a time; '128': Allocate 128 ports at a time; '256': Allocate 256 ports at a time; '512': Allocate 512 ports at a time; '1024': Allocate 1024 ports at a time; '2048': Allocate 2048 ports at a time; '4096': Allocate 4096 ports at a time; choices:['64', '128', '256', '512', '1024', '2048', '4096']
    
    simultaneous_batch_allocation:
        description:
            - Allocate same TCP and UDP batches at once
    
    per_batch_port_usage_warning_threshold:
        description:
            - Configure warning log threshold for per batch port usage (default: disabled) (Number of ports)
    
    tcp_time_wait_interval:
        description:
            - Minutes before TCP NAT ports can be reused
    
    usable_nat_ports:
        description:
            - Configure usable NAT ports
    
    usable_nat_ports_start:
        description:
            - Start Port of Usable NAT Ports (needs to be even)
    
    usable_nat_ports_end:
        description:
            - End Port of Usable NAT Ports
    
    uuid:
        description:
            - uuid of the object
    

"""

EXAMPLES = """
- name: Create a10_cgnv6_nat_pool
  a10_cgnv6_nat_pool:
      a10_host: "{{ inventory_hostname }}"
      a10_username: admin
      a10_password: a10
      pool_name: "POOL3"
      start_address: "172.21.21.1"
      end_address: "172.21.21.254"
      netmask: "/24"

"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"all","end_address","exclude_ip","group","max_users_per_ip","netmask","partition","per_batch_port_usage_warning_threshold","pool_name","port_batch_v2_size","shared","simultaneous_batch_allocation","start_address","tcp_time_wait_interval","usable_nat_ports","usable_nat_ports_end","usable_nat_ports_start","uuid","vrid",}

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
        
        all=dict(
            type='str' 
        ),
        end_address=dict(
            type='str' 
        ),
        exclude_ip=dict(
            type='str' 
        ),
        group=dict(
            type='str' 
        ),
        max_users_per_ip=dict(
            type='str' 
        ),
        netmask=dict(
            type='str' 
        ),
        partition=dict(
            type='str' 
        ),
        per_batch_port_usage_warning_threshold=dict(
            type='str' 
        ),
        pool_name=dict(
            type='str' , required=True
        ),
        port_batch_v2_size=dict(
            type='str' , choices=['64', '128', '256', '512', '1024', '2048', '4096']
        ),
        shared=dict(
            type='str' 
        ),
        simultaneous_batch_allocation=dict(
            type='str' 
        ),
        start_address=dict(
            type='str' 
        ),
        tcp_time_wait_interval=dict(
            type='str' 
        ),
        usable_nat_ports=dict(
            type='str' 
        ),
        usable_nat_ports_end=dict(
            type='str' 
        ),
        usable_nat_ports_start=dict(
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
    url_base = "/axapi/v3/cgnv6/nat/pool/"
    f_dict = {}
    
    f_dict["pool_name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/nat/pool/{pool_name}"
    f_dict = {}
    
    f_dict["pool_name"] = module.params["pool_name"]

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
    payload = build_json("pool", module)
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
    payload = build_json("pool", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
