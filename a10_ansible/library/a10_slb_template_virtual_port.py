#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_virtual-port
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Virtual port template name
    
    aflow:
        description:
            - Use aFlow to eliminate the traffic surge
    
    allow-syn-otherflags:
        description:
            - Allow initial SYN packet with other flags
    
    conn-limit:
        description:
            - Connection limit
    
    conn-limit-reset:
        description:
            - Send client reset when connection over limit
    
    conn-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    conn-rate-limit:
        description:
            - Connection rate limit
    
    rate-interval:
        description:
            - '100ms': Use 100 ms as sampling interval; 'second': Use 1 second as sampling interval; choices:['100ms', 'second']
    
    conn-rate-limit-reset:
        description:
            - Send client reset when connection rate over limit
    
    conn-rate-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    pkt-rate-type:
        description:
            - 'src-ip-port': Source IP and port rate limit; 'src-port': Source port rate limit; choices:['src-ip-port', 'src-port']
    
    rate:
        description:
            - Source IP and port rate limit (Packet rate limit)
    
    pkt-rate-interval:
        description:
            - '100ms': Source IP and port rate limit per 100ms; 'second': Source IP and port rate limit per second (default); choices:['100ms', 'second']
    
    pkt-rate-limit-reset:
        description:
            - send client-side reset (reset after packet limit)
    
    log-options:
        description:
            - 'no-logging': Do not log over limit event; 'no-repeat-logging': log once for over limit event. Default is log once per minute; choices:['no-logging', 'no-repeat-logging']
    
    when-rr-enable:
        description:
            - Only do rate limit if CPU RR triggered
    
    allow-vip-to-rport-mapping:
        description:
            - Allow mapping of VIP to real port
    
    dscp:
        description:
            - Differentiated Services Code Point (DSCP to Real Server IP Mapping Value)
    
    drop-unknown-conn:
        description:
            - Drop conection if receives TCP packet without SYN or RST flag and it does not belong to any existing connections
    
    reset-unknown-conn:
        description:
            - Send reset back if receives TCP packet without SYN or RST flag and it does not belong to any existing connections
    
    reset-l7-on-failover:
        description:
            - Send reset to L7 client and server connection upon a failover
    
    ignore-tcp-msl:
        description:
            - reclaim TCP resource immediately without MSL
    
    snat-msl:
        description:
            - Source NAT MSL (Source NAT MSL value)
    
    snat-port-preserve:
        description:
            - Source NAT Port Preservation
    
    non-syn-initiation:
        description:
            - Allow initial TCP packet to be non-SYN
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"aflow","allow_syn_otherflags","allow_vip_to_rport_mapping","conn_limit","conn_limit_no_logging","conn_limit_reset","conn_rate_limit","conn_rate_limit_no_logging","conn_rate_limit_reset","drop_unknown_conn","dscp","ignore_tcp_msl","log_options","name","non_syn_initiation","pkt_rate_interval","pkt_rate_limit_reset","pkt_rate_type","rate","rate_interval","reset_l7_on_failover","reset_unknown_conn","snat_msl","snat_port_preserve","user_tag","uuid","when_rr_enable",}

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
        
        aflow=dict(
            type='str' 
        ),
        allow_syn_otherflags=dict(
            type='str' 
        ),
        allow_vip_to_rport_mapping=dict(
            type='str' 
        ),
        conn_limit=dict(
            type='str' 
        ),
        conn_limit_no_logging=dict(
            type='str' 
        ),
        conn_limit_reset=dict(
            type='str' 
        ),
        conn_rate_limit=dict(
            type='str' 
        ),
        conn_rate_limit_no_logging=dict(
            type='str' 
        ),
        conn_rate_limit_reset=dict(
            type='str' 
        ),
        drop_unknown_conn=dict(
            type='str' 
        ),
        dscp=dict(
            type='str' 
        ),
        ignore_tcp_msl=dict(
            type='str' 
        ),
        log_options=dict(
            type='enum' , choices=['no-logging', 'no-repeat-logging']
        ),
        name=dict(
            type='str' , required=True
        ),
        non_syn_initiation=dict(
            type='str' 
        ),
        pkt_rate_interval=dict(
            type='enum' , choices=['100ms', 'second']
        ),
        pkt_rate_limit_reset=dict(
            type='str' 
        ),
        pkt_rate_type=dict(
            type='enum' , choices=['src-ip-port', 'src-port']
        ),
        rate=dict(
            type='str' 
        ),
        rate_interval=dict(
            type='enum' , choices=['100ms', 'second']
        ),
        reset_l7_on_failover=dict(
            type='str' 
        ),
        reset_unknown_conn=dict(
            type='str' 
        ),
        snat_msl=dict(
            type='str' 
        ),
        snat_port_preserve=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        when_rr_enable=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"
    f_dict = {}
    
    f_dict["name"] = module.params["name"]

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
    payload = build_json("virtual-port", module)
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
    payload = build_json("virtual-port", module)
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