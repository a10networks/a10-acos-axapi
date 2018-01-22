#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_server
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Server Name
    
    server-ipv6-addr:
        description:
            - IPV6 address
    
    host:
        description:
            - IP Address
    
    fqdn-name:
        description:
            - Server hostname
    
    action:
        description:
            - 'enable': Enable this Real Server; 'disable': Disable this Real Server; 'disable-with-health-check': disable real server, but health check work; choices:['enable', 'disable', 'disable-with-health-check']
    
    external-ip:
        description:
            - External IP address for NAT of GSLB
    
    ipv6:
        description:
            - IPv6 address Mapping of GSLB
    
    template-server:
        description:
            - Server template (Server template name)
    
    health-check:
        description:
            - Health Check Monitor (Health monitor name)
    
    health-check-disable:
        description:
            - Disable configured health check configuration
    
    conn-limit:
        description:
            - Connection Limit
    
    no-logging:
        description:
            - Do not log connection over limit event
    
    conn-resume:
        description:
            - Connection Resume (Connection Resume (min active conn before resume taking new conn))
    
    weight:
        description:
            - Weight for this Real Server (Connection Weight)
    
    slow-start:
        description:
            - Slowly ramp up the connection number after server is up (start from 128, then double every 10 sec till 4096)
    
    spoofing-cache:
        description:
            - This server is a spoofing cache
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for real server; 'stats-data-disable': Disable statistical data collection for real server; choices:['stats-data-enable', 'stats-data-disable']
    
    extended-stats:
        description:
            - Enable extended statistics on real server
    
    alternate-server:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    port-list:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"action","alternate_server","conn_limit","conn_resume","extended_stats","external_ip","fqdn_name","health_check","health_check_disable","host","ipv6","name","no_logging","port_list","sampling_enable","server_ipv6_addr","slow_start","spoofing_cache","stats_data_action","template_server","user_tag","uuid","weight",}

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
            type='enum' , choices=['enable', 'disable', 'disable-with-health-check']
        ),
        alternate_server=dict(
            type='str' 
        ),
        conn_limit=dict(
            type='str' 
        ),
        conn_resume=dict(
            type='str' 
        ),
        extended_stats=dict(
            type='str' 
        ),
        external_ip=dict(
            type='str' 
        ),
        fqdn_name=dict(
            type='str' 
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_disable=dict(
            type='str' 
        ),
        host=dict(
            type='str' 
        ),
        ipv6=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        no_logging=dict(
            type='str' 
        ),
        port_list=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        server_ipv6_addr=dict(
            type='str' 
        ),
        slow_start=dict(
            type='str' 
        ),
        spoofing_cache=dict(
            type='str' 
        ),
        stats_data_action=dict(
            type='enum' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        template_server=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        weight=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{name}"
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
    requires_one_of = sorted(['host','fqdn_host',])
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
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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