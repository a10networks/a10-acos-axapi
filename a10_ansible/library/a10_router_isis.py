#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_isis
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    tag:
        description:
            - ISO routing area tag
    
    adjacency-check:
        description:
            - Check ISIS neighbor protocol support
    
    area-password-cfg:
        
    
    authentication:
        
    
    bfd:
        description:
            - 'all-interfaces': Enable BFD on all interfaces; choices:['all-interfaces']
    
    default-information:
        description:
            - 'originate': Distribute a default route; choices:['originate']
    
    distance-list:
        
    
    domain-password-cfg:
        
    
    ha-standby-extra-cost:
        
    
    ignore-lsp-errors:
        description:
            - Ignore LSPs with bad checksums
    
    is-type:
        description:
            - 'level-1': Act as a station router only; 'level-1-2': Act as both a station router and an area router; 'level-2-only': Act as an area router only; choices:['level-1', 'level-1-2', 'level-2-only']
    
    log-adjacency-changes-cfg:
        
    
    lsp-gen-interval-list:
        
    
    lsp-refresh-interval:
        description:
            - Set LSP refresh interval (LSP refresh time in seconds)
    
    max-lsp-lifetime:
        description:
            - Set maximum LSP lifetime (Maximum LSP lifetime in seconds)
    
    metric-style-list:
        
    
    passive-interface-list:
        
    
    protocol-list:
        
    
    set-overload-bit-cfg:
        
    
    spf-interval-exp-list:
        
    
    summary-address-list:
        
    
    net-list:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    redistribute:
        
    
    address-family:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"address_family","adjacency_check","area_password_cfg","authentication","bfd","default_information","distance_list","domain_password_cfg","ha_standby_extra_cost","ignore_lsp_errors","is_type","log_adjacency_changes_cfg","lsp_gen_interval_list","lsp_refresh_interval","max_lsp_lifetime","metric_style_list","net_list","passive_interface_list","protocol_list","redistribute","set_overload_bit_cfg","spf_interval_exp_list","summary_address_list","tag","user_tag","uuid",}

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
        
        address_family=dict(
            type='str' 
        ),
        adjacency_check=dict(
            type='str' 
        ),
        area_password_cfg=dict(
            type='str' 
        ),
        authentication=dict(
            type='str' 
        ),
        bfd=dict(
            type='enum' , choices=['all-interfaces']
        ),
        default_information=dict(
            type='enum' , choices=['originate']
        ),
        distance_list=dict(
            type='str' 
        ),
        domain_password_cfg=dict(
            type='str' 
        ),
        ha_standby_extra_cost=dict(
            type='str' 
        ),
        ignore_lsp_errors=dict(
            type='str' 
        ),
        is_type=dict(
            type='enum' , choices=['level-1', 'level-1-2', 'level-2-only']
        ),
        log_adjacency_changes_cfg=dict(
            type='str' 
        ),
        lsp_gen_interval_list=dict(
            type='str' 
        ),
        lsp_refresh_interval=dict(
            type='str' 
        ),
        max_lsp_lifetime=dict(
            type='str' 
        ),
        metric_style_list=dict(
            type='str' 
        ),
        net_list=dict(
            type='str' 
        ),
        passive_interface_list=dict(
            type='str' 
        ),
        protocol_list=dict(
            type='str' 
        ),
        redistribute=dict(
            type='str' 
        ),
        set_overload_bit_cfg=dict(
            type='str' 
        ),
        spf_interval_exp_list=dict(
            type='str' 
        ),
        summary_address_list=dict(
            type='str' 
        ),
        tag=dict(
            type='str' , required=True
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
    url_base = "/axapi/v3/router/isis/{tag}"
    f_dict = {}
    
    f_dict["tag"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/isis/{tag}"
    f_dict = {}
    
    f_dict["tag"] = module.params["tag"]

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
    payload = build_json("isis", module)
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
    payload = build_json("isis", module)
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