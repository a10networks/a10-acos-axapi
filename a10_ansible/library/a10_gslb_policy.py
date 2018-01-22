#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_policy
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Specify policy name
    
    health-check:
        description:
            - Select Service-IP by health status
    
    health-check-preference-enable:
        description:
            - Check health preference
    
    health-preference-top:
        description:
            - Only keep top n
    
    amount-first:
        description:
            - Select record based on the amount of available service-ip
    
    weighted-ip-enable:
        description:
            - Enable Select Service-IP by weighted preference
    
    weighted-ip-total-hits:
        description:
            - Weighted by total hits
    
    weighted-site-enable:
        description:
            - Enable Select Service-IP by weighted site preference
    
    weighted-site-total-hits:
        description:
            - Weighted by total hits
    
    weighted-alias:
        description:
            - Select alias name by weighted preference
    
    active-servers-enable:
        description:
            - Enable Select Service-IP with the highest number of active servers
    
    active-servers-fail-break:
        description:
            - Break when no active server
    
    bw-cost-enable:
        description:
            - Enable bw cost
    
    bw-cost-fail-break:
        description:
            - Break when exceed limit
    
    geographic:
        description:
            - Select Service-IP by geographic
    
    num-session-enable:
        description:
            - Enable Select Service-IP for device having maximum number of available sessions
    
    num-session-tolerance:
        description:
            - The difference between the available sessions, default is 10 (Tolerance)
    
    admin-preference:
        description:
            - Select Service-IP for the device having maximum admin preference
    
    alias-admin-preference:
        description:
            - Select alias name having maximum admin preference
    
    least-response:
        description:
            - Least response selection
    
    admin-ip-enable:
        description:
            - Enable admin ip
    
    admin-ip-top-only:
        description:
            - Return highest priority server only
    
    ordered-ip-top-only:
        description:
            - Return highest priority server only
    
    round-robin:
        description:
            - Round robin selection, enabled by default
    
    metric-force-check:
        description:
            - Always check Service-IP for all enabled metrics
    
    metric-fail-break:
        description:
            - Break if no valid Service-IP
    
    ip-list:
        description:
            - Specify IP List (IP List Name)
    
    metric-order:
        description:
            - Specify order of metric
    
    metric-type:
        choices:['health-check', 'weighted-ip', 'weighted-site', 'capacity', 'active-servers', 'active-rdt', 'geographic', 'connection-load', 'num-session', 'admin-preference', 'bw-cost', 'least-response', 'admin-ip']
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    capacity:
        
    
    connection-load:
        
    
    dns:
        
    
    geo-location-list:
        
    
    geo-location-match:
        
    
    active-rdt:
        
    
    auto-map:
        
    
    edns:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"active_rdt","active_servers_enable","active_servers_fail_break","admin_ip_enable","admin_ip_top_only","admin_preference","alias_admin_preference","amount_first","auto_map","bw_cost_enable","bw_cost_fail_break","capacity","connection_load","dns","edns","geo_location_list","geo_location_match","geographic","health_check","health_check_preference_enable","health_preference_top","ip_list","least_response","metric_fail_break","metric_force_check","metric_order","metric_type","name","num_session_enable","num_session_tolerance","ordered_ip_top_only","round_robin","user_tag","uuid","weighted_alias","weighted_ip_enable","weighted_ip_total_hits","weighted_site_enable","weighted_site_total_hits",}

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
        
        active_rdt=dict(
            type='str' 
        ),
        active_servers_enable=dict(
            type='str' 
        ),
        active_servers_fail_break=dict(
            type='str' 
        ),
        admin_ip_enable=dict(
            type='str' 
        ),
        admin_ip_top_only=dict(
            type='str' 
        ),
        admin_preference=dict(
            type='str' 
        ),
        alias_admin_preference=dict(
            type='str' 
        ),
        amount_first=dict(
            type='str' 
        ),
        auto_map=dict(
            type='str' 
        ),
        bw_cost_enable=dict(
            type='str' 
        ),
        bw_cost_fail_break=dict(
            type='str' 
        ),
        capacity=dict(
            type='str' 
        ),
        connection_load=dict(
            type='str' 
        ),
        dns=dict(
            type='str' 
        ),
        edns=dict(
            type='str' 
        ),
        geo_location_list=dict(
            type='str' 
        ),
        geo_location_match=dict(
            type='str' 
        ),
        geographic=dict(
            type='str' 
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_preference_enable=dict(
            type='str' 
        ),
        health_preference_top=dict(
            type='str' 
        ),
        ip_list=dict(
            type='str' 
        ),
        least_response=dict(
            type='str' 
        ),
        metric_fail_break=dict(
            type='str' 
        ),
        metric_force_check=dict(
            type='str' 
        ),
        metric_order=dict(
            type='str' 
        ),
        metric_type=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        num_session_enable=dict(
            type='str' 
        ),
        num_session_tolerance=dict(
            type='str' 
        ),
        ordered_ip_top_only=dict(
            type='str' 
        ),
        round_robin=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        weighted_alias=dict(
            type='str' 
        ),
        weighted_ip_enable=dict(
            type='str' 
        ),
        weighted_ip_total_hits=dict(
            type='str' 
        ),
        weighted_site_enable=dict(
            type='str' 
        ),
        weighted_site_total_hits=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{name}"
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
    payload = build_json("policy", module)
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
    payload = build_json("policy", module)
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