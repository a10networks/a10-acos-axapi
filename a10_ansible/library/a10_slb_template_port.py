#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_port
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Port template name
    
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
    
    request-rate-limit:
        description:
            - Request rate limit
    
    request-rate-interval:
        description:
            - '100ms': Use 100 ms as sampling interval; 'second': Use 1 second as sampling interval; choices:['100ms', 'second']
    
    reset:
        description:
            - Send client reset when connection rate over limit
    
    request-rate-no-logging:
        description:
            - Do not log connection over limit event
    
    dest-nat:
        description:
            - Destination NAT
    
    down-grace-period:
        description:
            - Port down grace period (Down grace period in seconds)
    
    del-session-on-server-down:
        description:
            - Delete session if the server/port goes down (either disabled/hm down)
    
    dscp:
        description:
            - Differentiated Services Code Point (DSCP to Real Server IP Mapping Value)
    
    dynamic-member-priority:
        description:
            - Set dynamic member's priority (Initial priority (default is 16))
    
    decrement:
        description:
            - Decrease after every round of DNS query (default is 0)
    
    extended-stats:
        description:
            - Enable extended statistics on real server port
    
    no-ssl:
        description:
            - No SSL
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for real server port; 'stats-data-disable': Disable statistical data collection for real server port; choices:['stats-data-enable', 'stats-data-disable']
    
    health-check:
        description:
            - Health Check Monitor (Health monitor name)
    
    health-check-disable:
        description:
            - Disable configured health check configuration
    
    inband-health-check:
        description:
            - Use inband traffic to detect port's health status
    
    retry:
        description:
            - Maximum retry times before reassign this connection to another server/port (default is 2) (The maximum retry number)
    
    reassign:
        description:
            - Maximum reassign times before declear the server/port down (default is 25) (The maximum reassign number)
    
    down-timer:
        description:
            - The timer to bring the marked down server/port to up (default is 0, never bring up) (The timer to bring up server (in second, default is 0))
    
    resel-on-reset:
        description:
            - When receiving reset from server, do the server/port reselection (default is 0, don't do reselection)
    
    source-nat:
        description:
            - Source NAT (IP NAT Pool or pool group name)
    
    weight:
        description:
            - Weight (port weight)
    
    sub-group:
        description:
            - Divide service group members into different sub groups (Sub group ID (default is 0))
    
    slow-start:
        description:
            - Slowly ramp up the connection number after port is up
    
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
    
    bw-rate-limit:
        description:
            - Configure bandwidth rate limit on real server port (Bandwidth rate limit in Kbps)
    
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
AVAILABLE_PROPERTIES = {"add","bw_rate_limit","bw_rate_limit_duration","bw_rate_limit_no_logging","bw_rate_limit_resume","conn_limit","conn_limit_no_logging","conn_rate_limit","conn_rate_limit_no_logging","decrement","del_session_on_server_down","dest_nat","down_grace_period","down_timer","dscp","dynamic_member_priority","every","extended_stats","health_check","health_check_disable","inband_health_check","initial_slow_start","name","no_ssl","rate_interval","reassign","request_rate_interval","request_rate_limit","request_rate_no_logging","resel_on_reset","reset","resume","retry","slow_start","source_nat","stats_data_action","sub_group","till","times","user_tag","uuid","weight",}

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
            type='str' 
        ),
        bw_rate_limit=dict(
            type='str' 
        ),
        bw_rate_limit_duration=dict(
            type='str' 
        ),
        bw_rate_limit_no_logging=dict(
            type='str' 
        ),
        bw_rate_limit_resume=dict(
            type='str' 
        ),
        conn_limit=dict(
            type='str' 
        ),
        conn_limit_no_logging=dict(
            type='str' 
        ),
        conn_rate_limit=dict(
            type='str' 
        ),
        conn_rate_limit_no_logging=dict(
            type='str' 
        ),
        decrement=dict(
            type='str' 
        ),
        del_session_on_server_down=dict(
            type='str' 
        ),
        dest_nat=dict(
            type='str' 
        ),
        down_grace_period=dict(
            type='str' 
        ),
        down_timer=dict(
            type='str' 
        ),
        dscp=dict(
            type='str' 
        ),
        dynamic_member_priority=dict(
            type='str' 
        ),
        every=dict(
            type='str' 
        ),
        extended_stats=dict(
            type='str' 
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_disable=dict(
            type='str' 
        ),
        inband_health_check=dict(
            type='str' 
        ),
        initial_slow_start=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        no_ssl=dict(
            type='str' 
        ),
        rate_interval=dict(
            type='enum' , choices=['100ms', 'second']
        ),
        reassign=dict(
            type='str' 
        ),
        request_rate_interval=dict(
            type='enum' , choices=['100ms', 'second']
        ),
        request_rate_limit=dict(
            type='str' 
        ),
        request_rate_no_logging=dict(
            type='str' 
        ),
        resel_on_reset=dict(
            type='str' 
        ),
        reset=dict(
            type='str' 
        ),
        resume=dict(
            type='str' 
        ),
        retry=dict(
            type='str' 
        ),
        slow_start=dict(
            type='str' 
        ),
        source_nat=dict(
            type='str' 
        ),
        stats_data_action=dict(
            type='enum' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        sub_group=dict(
            type='str' 
        ),
        till=dict(
            type='str' 
        ),
        times=dict(
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
    url_base = "/axapi/v3/slb/template/port/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/port/{name}"
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