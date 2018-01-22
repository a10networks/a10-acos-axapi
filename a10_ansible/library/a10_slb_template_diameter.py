#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_diameter
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - diameter template Name
    
    customize-cea:
        description:
            - customizing cea response
    
    avp-code:
        description:
            - avp code
    
    avp-string:
        description:
            - pattern to be matched in the avp string name, max length 127 bytes
    
    service-group-name:
        description:
            - service group name, this is the service group that the message needs to be copied to
    
    dwr-time:
        description:
            - dwr health-check timer interval (in 100 milli second unit, default is 100, 0 means unset this option)
    
    idle-timeout:
        description:
            - user sesison idle timeout (in minutes, default is 5)
    
    multiple-origin-host:
        description:
            - allowing multiple origin-host to a single server
    
    origin-realm:
        description:
            - origin-realm name avp
    
    product-name:
        description:
            - product name avp
    
    vendor-id:
        description:
            - vendor-id avp (Vendor Id)
    
    session-age:
        description:
            - user session age allowed (default 10), this is not idle-time (in minutes)
    
    dwr-up-retry:
        description:
            - number of successful dwr health-check before declaring target up
    
    terminate-on-cca-t:
        description:
            - remove diameter session when receiving CCA-T message
    
    forward-unknown-session-id:
        description:
            - Forward server message even it has unknown session id
    
    forward-to-latest-server:
        description:
            - Forward client message to the latest server that sends message with the same session id
    
    load-balance-on-session-id:
        description:
            - Load balance based on the session id
    
    message-code-list:
        
    
    avp-list:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    origin-host:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"avp_code","avp_list","avp_string","customize_cea","dwr_time","dwr_up_retry","forward_to_latest_server","forward_unknown_session_id","idle_timeout","load_balance_on_session_id","message_code_list","multiple_origin_host","name","origin_host","origin_realm","product_name","service_group_name","session_age","terminate_on_cca_t","user_tag","uuid","vendor_id",}

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
        
        avp_code=dict(
            type='str' 
        ),
        avp_list=dict(
            type='str' 
        ),
        avp_string=dict(
            type='str' 
        ),
        customize_cea=dict(
            type='str' 
        ),
        dwr_time=dict(
            type='str' 
        ),
        dwr_up_retry=dict(
            type='str' 
        ),
        forward_to_latest_server=dict(
            type='str' 
        ),
        forward_unknown_session_id=dict(
            type='str' 
        ),
        idle_timeout=dict(
            type='str' 
        ),
        load_balance_on_session_id=dict(
            type='str' 
        ),
        message_code_list=dict(
            type='str' 
        ),
        multiple_origin_host=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        origin_host=dict(
            type='str' 
        ),
        origin_realm=dict(
            type='str' 
        ),
        product_name=dict(
            type='str' 
        ),
        service_group_name=dict(
            type='str' 
        ),
        session_age=dict(
            type='str' 
        ),
        terminate_on_cca_t=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        vendor_id=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/diameter/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/diameter/{name}"
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
    payload = build_json("diameter", module)
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
    payload = build_json("diameter", module)
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