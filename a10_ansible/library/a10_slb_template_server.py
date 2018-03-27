#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_template_server
description:
    - Server template
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Server template name
    
    conn-limit:
        description:
            - Connection limit
    
    resume:
        description:
            - Resume accepting new connection after connection number drops below threshold (Connection resume threshold)
    
    conn-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    conn-rate-limit:
        description:
            - Connection rate limit
    
    rate-interval:
        description:
            - '100ms': Use 100 ms as sampling interval; 'second': Use 1 second as sampling interval; choices:['100ms', 'second']
    
    conn-rate-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    dns-query-interval:
        description:
            - The interval to query DNS server for the hostname (DNS query interval (in minute, default is 10))
    
    dynamic-server-prefix:
        description:
            - Prefix of dynamic server (Prefix of dynamic server (default is "DRS"))
    
    extended-stats:
        description:
            - Enable extended statistics on real server
    
    log-selection-failure:
        description:
            - Enable real-time logging for server selection failure event
    
    health-check:
        description:
            - Health Check Monitor (Health monitor name)
    
    health-check-disable:
        description:
            - Disable configured health check configuration
    
    max-dynamic-server:
        description:
            - Maximum dynamic server number (Maximum dynamic server number (default is 255))
    
    min-ttl-ratio:
        description:
            - Minimum TTL to DNS query interval ratio (Minimum TTL ratio (default is 2))
    
    weight:
        description:
            - Weight for the Real Servers (Connection Weight (default is 1))
    
    spoofing-cache:
        description:
            - Servers under the template are spoofing cache
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for real server; 'stats-data-disable': Disable statistical data collection for real server; choices:['stats-data-enable', 'stats-data-disable']
    
    slow-start:
        description:
            - Slowly ramp up the connection number after server is up
    
    initial-slow-start:
        description:
            - Initial slow start connection limit (default 128)
    
    add:
        description:
            - Slow start connection limit add by a number every interval (Add by this number every interval)
    
    times:
        description:
            - Slow start connection limit multiply by a number every interval (default 2) (Multiply by this number every interval)
    
    every:
        description:
            - Slow start connection limit increment interval (default 10)
    
    till:
        description:
            - Slow start ends when slow start connection limit reaches a number (default 4096) (Slow start ends when connection limit reaches this number)
    
    bw-rate-limit-acct:
        description:
            - 'to-server-only': Only account for traffic sent to server; 'from-server-only': Only account for traffic received from server; 'all': Account for all traffic sent to and received from server; choices:['to-server-only', 'from-server-only', 'all']
    
    bw-rate-limit:
        description:
            - Configure bandwidth rate limit on real server (Bandwidth rate limit in Kbps)
    
    bw-rate-limit-resume:
        description:
            - Resume server selection after bandwidth drops below this threshold (in Kbps) (Bandwidth rate limit resume threshold (in Kbps))
    
    bw-rate-limit-duration:
        description:
            - Duration in seconds the observed rate needs to honor
    
    bw-rate-limit-no-logging:
        description:
            - Do not log bandwidth rate limit related state transitions
    
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
AVAILABLE_PROPERTIES = ["add","bw_rate_limit","bw_rate_limit_acct","bw_rate_limit_duration","bw_rate_limit_no_logging","bw_rate_limit_resume","conn_limit","conn_limit_no_logging","conn_rate_limit","conn_rate_limit_no_logging","dns_query_interval","dynamic_server_prefix","every","extended_stats","health_check","health_check_disable","initial_slow_start","log_selection_failure","max_dynamic_server","min_ttl_ratio","name","rate_interval","resume","slow_start","spoofing_cache","stats_data_action","till","times","user_tag","uuid","weight",]

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
        
        add=dict(
            type='int' 
        ),
        bw_rate_limit=dict(
            type='int' 
        ),
        bw_rate_limit_acct=dict(
            type='str' , choices=['to-server-only', 'from-server-only', 'all']
        ),
        bw_rate_limit_duration=dict(
            type='int' 
        ),
        bw_rate_limit_no_logging=dict(
            type='bool' 
        ),
        bw_rate_limit_resume=dict(
            type='int' 
        ),
        conn_limit=dict(
            type='int' 
        ),
        conn_limit_no_logging=dict(
            type='bool' 
        ),
        conn_rate_limit=dict(
            type='int' 
        ),
        conn_rate_limit_no_logging=dict(
            type='bool' 
        ),
        dns_query_interval=dict(
            type='int' 
        ),
        dynamic_server_prefix=dict(
            type='str' 
        ),
        every=dict(
            type='int' 
        ),
        extended_stats=dict(
            type='bool' 
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_disable=dict(
            type='bool' 
        ),
        initial_slow_start=dict(
            type='int' 
        ),
        log_selection_failure=dict(
            type='bool' 
        ),
        max_dynamic_server=dict(
            type='int' 
        ),
        min_ttl_ratio=dict(
            type='int' 
        ),
        name=dict(
            type='str' , required=True
        ),
        rate_interval=dict(
            type='str' , choices=['100ms', 'second']
        ),
        resume=dict(
            type='int' 
        ),
        slow_start=dict(
            type='bool' 
        ),
        spoofing_cache=dict(
            type='bool' 
        ),
        stats_data_action=dict(
            type='str' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        till=dict(
            type='int' 
        ),
        times=dict(
            type='int' 
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
    url_base = "/axapi/v3/slb/template/server/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server/{name}"
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