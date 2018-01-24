#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_server_port
description:
    - Real Server Port
author: A10 Networks 2018 
version_added: 1.8

options:
    
    port-number:
        description:
            - Port Number
    
    protocol:
        description:
            - 'tcp': TCP Port; 'udp': UDP Port; choices:['tcp', 'udp']
    
    range:
        description:
            - Port range (Port range value - used for vip-to-rport-mapping and vport-rport range mapping)
    
    template-port:
        description:
            - Port template (Port template name)
    
    template-server-ssl:
        description:
            - Server side SSL template (Server side SSL Name)
    
    action:
        description:
            - 'enable': enable; 'disable': disable; 'disable-with-health-check': disable port, but health check work; choices:['enable', 'disable', 'disable-with-health-check']
    
    no-ssl:
        description:
            - No SSL
    
    health-check:
        description:
            - Health Check (Monitor Name)
    
    health-check-follow-port:
        description:
            - Specify which port to follow for health status (Port Number)
    
    follow-port-protocol:
        description:
            - 'tcp': TCP Port; 'udp': UDP Port; choices:['tcp', 'udp']
    
    health-check-disable:
        description:
            - Disable health check
    
    weight:
        description:
            - Port Weight (Connection Weight)
    
    conn-limit:
        description:
            - Connection Limit
    
    no-logging:
        description:
            - Do not log connection over limit event
    
    conn-resume:
        description:
            - Connection Resume
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for real server port; 'stats-data-disable': Disable statistical data collection for real server port; choices:['stats-data-enable', 'stats-data-disable']
    
    extended-stats:
        description:
            - Enable extended statistics on real server port
    
    alternate-port:
        
    
    auth-cfg:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","alternate_port","auth_cfg","conn_limit","conn_resume","extended_stats","follow_port_protocol","health_check","health_check_disable","health_check_follow_port","no_logging","no_ssl","port_number","protocol","range","sampling_enable","stats_data_action","template_port","template_server_ssl","user_tag","uuid","weight",]

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
            type='str' , choices=['enable', 'disable', 'disable-with-health-check']
        ),
        alternate_port=dict(
            type='list' 
        ),
        auth_cfg=dict(
            type='str' 
        ),
        conn_limit=dict(
            type='int' 
        ),
        conn_resume=dict(
            type='int' 
        ),
        extended_stats=dict(
            type='bool' 
        ),
        follow_port_protocol=dict(
            type='str' , choices=['tcp', 'udp']
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_disable=dict(
            type='bool' 
        ),
        health_check_follow_port=dict(
            type='int' 
        ),
        no_logging=dict(
            type='bool' 
        ),
        no_ssl=dict(
            type='bool' 
        ),
        port_number=dict(
            type='int' , required=True
        ),
        protocol=dict(
            type='str' , required=True, choices=['tcp', 'udp']
        ),
        range=dict(
            type='int' 
        ),
        sampling_enable=dict(
            type='list' 
        ),
        stats_data_action=dict(
            type='str' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        template_port=dict(
            type='str' 
        ),
        template_server_ssl=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        weight=dict(
            type='int' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    
    f_dict["port-number"] = module.params["port-number"]
    f_dict["protocol"] = module.params["protocol"]

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
        # else:
        #     del module.params[x]

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
    payload = build_json("port", module)
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
    payload = build_json("port", module)
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

    valid = True

    if state == 'present':
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