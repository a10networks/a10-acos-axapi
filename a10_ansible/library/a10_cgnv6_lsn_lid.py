#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_lsn-lid
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    lid_number:
        description:
            - LSN Lid
    
    drop_on_nat_pool_mismatch:
        description:
            - Drop traffic from users if their current NAT pool does not match the lid's (default: off)
    
    name:
        description:
            - LSN Lid Name
    
    respond_to_user_mac:
        description:
            - Use the user's source MAC for the next hop rather than the routing table (default: off)
    
    override:
        description:
            - 'none': Apply source NAT if configured (default); 'drop': Drop packets that match this LSN lid; 'pass-through': Layer-3 route packets that match this LSN lid and do not apply source NAT; choices:['none', 'drop', 'pass-through']
    
    user_quota_prefix_length:
        description:
            - NAT64/DS-Lite user quota prefix length (Prefix Length (Default: Uses the global NAT64/DS-Lite configured value))
    
    ds_lite:
        
    
    lsn_rule_list:
        
    
    source_nat_pool:
        
    
    extended_user_quota:
        
    
    conn_rate_limit:
        
    
    user_quota:
        
    
    uuid:
        description:
            - uuid of the object
    
    user_tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
- name: Create a10_cgnv6_lsn_lid instance
  a10_cgnv6_lsn_lid:
      a10_host: "{{ inventory_hostname }}"
      a10_username: admin
      a10_password: a10
      lid_number: 2
      state: present
      source_nat_pool:
            "pool-name":
               "POOL3"
      user_quota: {
          "quota-udp": {
            "udp-quota":200
          },
          "quota-tcp": {
            "tcp-quota":100,
            "tcp-reserve":10
          }
          }
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"conn_rate_limit","drop_on_nat_pool_mismatch","ds_lite","extended_user_quota","lid_number","lsn_rule_list","name","override","respond_to_user_mac","source_nat_pool","user_quota","user_quota_prefix_length","user_tag","uuid",}

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
        
        conn_rate_limit=dict(
            type='str' 
        ),
        drop_on_nat_pool_mismatch=dict(
            type='str' 
        ),
        ds_lite=dict(
            type='str' 
        ),
        extended_user_quota=dict(
            type='str' 
        ),
        lid_number=dict(
            type='str' , required=True
        ),
        lsn_rule_list=dict(
            type='str' 
        ),
        name=dict(
            type='str' 
        ),
        override=dict(
            type='str' , choices=['none', 'drop', 'pass-through']
        ),
        respond_to_user_mac=dict(
            type='str' 
        ),
        source_nat_pool=dict(
            type='dict' 
        ),
        user_quota=dict(
            type='dict' 
        ),
        user_quota_prefix_length=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn-lid/"
    f_dict = {}
    
    f_dict["lid_number"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn-lid/{lid_number}"
    f_dict = {}
    
    f_dict["lid_number"] = module.params["lid_number"]

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
            rx = rx.replace("\"", "")
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
    payload = build_json("lsn-lid", module)
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
    payload = build_json("lsn-lid", module)
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
