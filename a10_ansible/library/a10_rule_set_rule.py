#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_rule
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Rule name
    
    remark:
        description:
            - Rule entry comment (Notes for this rule)
    
    status:
        description:
            - 'enable': Enable rule; 'disable': Disable rule; choices:['enable', 'disable']
    
    action:
        description:
            - 'permit': permit; 'deny': deny; 'reset': reset; choices:['permit', 'deny', 'reset']
    
    log:
        description:
            - Enable logging
    
    listen-on-port:
        description:
            - Listen on port
    
    policy:
        description:
            - 'cgnv6': Apply CGNv6 policy; 'forward': Forward packet; choices:['cgnv6', 'forward']
    
    forward-listen-on-port:
        description:
            - Listen on port
    
    fw-log:
        description:
            - Enable logging
    
    fwlog:
        description:
            - Enable logging
    
    cgnv6-log:
        description:
            - Enable logging
    
    forward-log:
        description:
            - Enable logging
    
    cgnv6-policy:
        description:
            - 'lsn-lid': Apply specified CGNv6 LSN LID; 'fixed-nat': Apply CGNv6 Fixed NAT; 'static-nat': Apply CGNv6 Static NAT; choices:['lsn-lid', 'fixed-nat', 'static-nat']
    
    cgnv6-fixed-nat-log:
        description:
            - Enable logging
    
    cgnv6-lsn-lid:
        description:
            - LSN LID
    
    cgnv6-lsn-log:
        description:
            - Enable logging
    
    ip-version:
        description:
            - 'v4': IPv4 rule; 'v6': IPv6 rule; choices:['v4', 'v6']
    
    src-class-list:
        description:
            - Match source IP against class-list
    
    src-ipv4-any:
        description:
            - 'any': Any IPv4 address; choices:['any']
    
    src-ipv6-any:
        description:
            - 'any': Any IPv6 address; choices:['any']
    
    source-list:
        
    
    src-zone:
        description:
            - Zone name
    
    src-zone-any:
        description:
            - 'any': any; choices:['any']
    
    src-threat-list:
        description:
            - Bind threat-list for source IP based filtering
    
    dst-class-list:
        description:
            - Match destination IP against class-list
    
    dst-ipv4-any:
        description:
            - 'any': Any IPv4 address; choices:['any']
    
    dst-ipv6-any:
        description:
            - 'any': Any IPv6 address; choices:['any']
    
    dest-list:
        
    
    dst-zone:
        description:
            - Zone name
    
    dst-zone-any:
        description:
            - 'any': any; choices:['any']
    
    dst-threat-list:
        description:
            - Bind threat-list for destination IP based filtering
    
    service-any:
        description:
            - 'any': any; choices:['any']
    
    service-list:
        
    
    idle-timeout:
        description:
            - TCP/UDP idle-timeout
    
    application-any:
        description:
            - 'any': any; choices:['any']
    
    app-list:
        
    
    track-application:
        description:
            - Enable application statistic
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    move-rule:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"action","app_list","application_any","cgnv6_fixed_nat_log","cgnv6_log","cgnv6_lsn_lid","cgnv6_lsn_log","cgnv6_policy","dest_list","dst_class_list","dst_ipv4_any","dst_ipv6_any","dst_threat_list","dst_zone","dst_zone_any","forward_listen_on_port","forward_log","fw_log","fwlog","idle_timeout","ip_version","listen_on_port","log","move_rule","name","policy","remark","sampling_enable","service_any","service_list","source_list","src_class_list","src_ipv4_any","src_ipv6_any","src_threat_list","src_zone","src_zone_any","status","track_application","user_tag","uuid",}

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
        
        action=dict(
            type='enum' , choices=['permit', 'deny', 'reset']
        ),
        app_list=dict(
            type='str' 
        ),
        application_any=dict(
            type='enum' , choices=['any']
        ),
        cgnv6_fixed_nat_log=dict(
            type='str' 
        ),
        cgnv6_log=dict(
            type='str' 
        ),
        cgnv6_lsn_lid=dict(
            type='str' 
        ),
        cgnv6_lsn_log=dict(
            type='str' 
        ),
        cgnv6_policy=dict(
            type='enum' , choices=['lsn-lid', 'fixed-nat', 'static-nat']
        ),
        dest_list=dict(
            type='str' 
        ),
        dst_class_list=dict(
            type='str' 
        ),
        dst_ipv4_any=dict(
            type='enum' , choices=['any']
        ),
        dst_ipv6_any=dict(
            type='enum' , choices=['any']
        ),
        dst_threat_list=dict(
            type='str' 
        ),
        dst_zone=dict(
            type='str' 
        ),
        dst_zone_any=dict(
            type='enum' , choices=['any']
        ),
        forward_listen_on_port=dict(
            type='str' 
        ),
        forward_log=dict(
            type='str' 
        ),
        fw_log=dict(
            type='str' 
        ),
        fwlog=dict(
            type='str' 
        ),
        idle_timeout=dict(
            type='str' 
        ),
        ip_version=dict(
            type='enum' , choices=['v4', 'v6']
        ),
        listen_on_port=dict(
            type='str' 
        ),
        log=dict(
            type='str' 
        ),
        move_rule=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        policy=dict(
            type='enum' , choices=['cgnv6', 'forward']
        ),
        remark=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        service_any=dict(
            type='enum' , choices=['any']
        ),
        service_list=dict(
            type='str' 
        ),
        source_list=dict(
            type='str' 
        ),
        src_class_list=dict(
            type='str' 
        ),
        src_ipv4_any=dict(
            type='enum' , choices=['any']
        ),
        src_ipv6_any=dict(
            type='enum' , choices=['any']
        ),
        src_threat_list=dict(
            type='str' 
        ),
        src_zone=dict(
            type='str' 
        ),
        src_zone_any=dict(
            type='enum' , choices=['any']
        ),
        status=dict(
            type='enum' , choices=['enable', 'disable']
        ),
        track_application=dict(
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
    url_base = "/axapi/v3/rule-set/{name}/rule/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{name}/rule/{name}"
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
    payload = build_json("rule", module)
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
    payload = build_json("rule", module)
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