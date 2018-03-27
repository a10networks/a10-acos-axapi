#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_service-group
description:
    - Service Group
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - SLB Service Name
    
    protocol:
        description:
            - 'tcp': TCP LB service; 'udp': UDP LB service; choices:['tcp', 'udp']
    
    template-port:
        description:
            - Port template (Port template name)
    
    template-server:
        description:
            - Server template (Server template name)
    
    template-policy:
        description:
            - Policy template (Policy template name)
    
    lb-method:
        description:
            - 'dst-ip-hash': Load-balancing based on only Dst IP and Port hash; 'dst-ip-only-hash': Load-balancing based on only Dst IP hash; 'fastest-response': Fastest response time on service port level; 'least-request': Least request on service port level; 'src-ip-hash': Load-balancing based on only Src IP and Port hash; 'src-ip-only-hash': Load-balancing based on only Src IP hash; 'weighted-rr': Weighted round robin on server level; 'round-robin': Round robin on server level; 'round-robin-strict': Strict mode round robin on server level; 'odd-even-hash': odd/even hash based of client src-ip; choices:['dst-ip-hash', 'dst-ip-only-hash', 'fastest-response', 'least-request', 'src-ip-hash', 'src-ip-only-hash', 'weighted-rr', 'round-robin', 'round-robin-strict', 'odd-even-hash']
    
    lc-method:
        description:
            - 'least-connection': Least connection on server level; 'service-least-connection': Least connection on service port level; 'weighted-least-connection': Weighted least connection on server level; 'service-weighted-least-connection': Weighted least connection on service port level; choices:['least-connection', 'service-least-connection', 'weighted-least-connection', 'service-weighted-least-connection']
    
    stateless-lb-method:
        description:
            - 'stateless-dst-ip-hash': Stateless load-balancing based on Dst IP and Dst port hash; 'stateless-per-pkt-round-robin': Stateless load-balancing using per-packet round-robin; 'stateless-src-dst-ip-hash': Stateless load-balancing based on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash': Stateless load-balancing based on only IP hash for both Src and Dst; 'stateless-src-ip-hash': Stateless load-balancing based on Src IP and Src port hash; 'stateless-src-ip-only-hash': Stateless load-balancing based on only Src IP hash; choices:['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']
    
    pseudo-round-robin:
        description:
            - PRR, select the oldest node for sub-select
    
    stateless-auto-switch:
        description:
            - Enable auto stateless method
    
    stateless-lb-method2:
        description:
            - 'stateless-dst-ip-hash': Stateless load-balancing based on Dst IP and Dst port hash; 'stateless-per-pkt-round-robin': Stateless load-balancing using per-packet round-robin; 'stateless-src-dst-ip-hash': Stateless load-balancing based on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash': Stateless load-balancing based on only IP hash for both Src and Dst; 'stateless-src-ip-hash': Stateless load-balancing based on Src IP and Src port hash; 'stateless-src-ip-only-hash': Stateless load-balancing based on only Src IP hash; choices:['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']
    
    conn-rate:
        description:
            - Dynamically enable stateless method by conn-rate (Rate to trigger stateless method(conn/sec))
    
    conn-rate-duration:
        description:
            - Period that trigger condition consistently happens(seconds)
    
    conn-revert-rate:
        description:
            - Rate to revert to statelful method (conn/sec)
    
    conn-rate-revert-duration:
        description:
            - Period that revert condition consistently happens(seconds)
    
    conn-rate-grace-period:
        description:
            - Define the grace period during transition (Define the grace period during transition(seconds))
    
    conn-rate-log:
        description:
            - Send log if transition happens
    
    l4-session-usage:
        description:
            - Dynamically enable stateless method by session usage (Usage to trigger stateless method)
    
    l4-session-usage-duration:
        description:
            - Period that trigger condition consistently happens(seconds)
    
    l4-session-usage-revert-rate:
        description:
            - Usage to revert to statelful method
    
    l4-session-revert-duration:
        description:
            - Period that revert condition consistently happens(seconds)
    
    l4-session-usage-grace-period:
        description:
            - Define the grace period during transition (Define the grace period during transition(seconds))
    
    l4-session-usage-log:
        description:
            - Send log if transition happens
    
    min-active-member:
        description:
            - Minimum Active Member Per Priority (Minimum Active Member before Action)
    
    min-active-member-action:
        description:
            - 'dynamic-priority': dynamic change member priority to met the min-active-member requirement; 'skip-pri-set': Skip Current Priority Set If Min not met; choices:['dynamic-priority', 'skip-pri-set']
    
    reset-on-server-selection-fail:
        description:
            - Send reset to client if server selection fails
    
    priority-affinity:
        description:
            - Priority affinity. Persist to the same priority if possible.
    
    reset-priority-affinity:
        description:
            - Reset
    
    backup-server-event-log:
        description:
            - Send log info on back up server events
    
    strict-select:
        description:
            - strict selection
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for service group; 'stats-data-disable': Disable statistical data collection for service group; choices:['stats-data-enable', 'stats-data-disable']
    
    extended-stats:
        description:
            - Enable extended statistics on service group
    
    traffic-replication-mirror:
        description:
            - Mirror Bi-directional Packet
    
    traffic-replication-mirror-da-repl:
        description:
            - Replace Destination MAC
    
    traffic-replication-mirror-ip-repl:
        description:
            - Replaces IP with server-IP
    
    traffic-replication-mirror-sa-da-repl:
        description:
            - Replace Source MAC and Destination MAC
    
    traffic-replication-mirror-sa-repl:
        description:
            - Replace Source MAC
    
    health-check:
        description:
            - Health Check (Monitor Name)
    
    health-check-disable:
        description:
            - Disable health check
    
    priorities:
        
    
    sample-rsp-time:
        description:
            - sample server response time
    
    rpt-ext-server:
        description:
            - Report top 10 fastest/slowest servers
    
    report-delay:
        description:
            - Reporting frequency (in minutes)
    
    top-slowest:
        description:
            - Report top 10 slowest servers
    
    top-fastest:
        description:
            - Report top 10 fastest servers
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    reset:
        
    
    member-list:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["backup_server_event_log","conn_rate","conn_rate_duration","conn_rate_grace_period","conn_rate_log","conn_rate_revert_duration","conn_revert_rate","extended_stats","health_check","health_check_disable","l4_session_revert_duration","l4_session_usage","l4_session_usage_duration","l4_session_usage_grace_period","l4_session_usage_log","l4_session_usage_revert_rate","lb_method","lc_method","member_list","min_active_member","min_active_member_action","name","priorities","priority_affinity","protocol","pseudo_round_robin","report_delay","reset","reset_on_server_selection_fail","reset_priority_affinity","rpt_ext_server","sample_rsp_time","sampling_enable","stateless_auto_switch","stateless_lb_method","stateless_lb_method2","stats_data_action","strict_select","template_policy","template_port","template_server","top_fastest","top_slowest","traffic_replication_mirror","traffic_replication_mirror_da_repl","traffic_replication_mirror_ip_repl","traffic_replication_mirror_sa_da_repl","traffic_replication_mirror_sa_repl","user_tag","uuid",]

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
        
        backup_server_event_log=dict(
            type='bool' 
        ),
        conn_rate=dict(
            type='int' 
        ),
        conn_rate_duration=dict(
            type='int' 
        ),
        conn_rate_grace_period=dict(
            type='int' 
        ),
        conn_rate_log=dict(
            type='bool' 
        ),
        conn_rate_revert_duration=dict(
            type='int' 
        ),
        conn_revert_rate=dict(
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
        l4_session_revert_duration=dict(
            type='int' 
        ),
        l4_session_usage=dict(
            type='int' 
        ),
        l4_session_usage_duration=dict(
            type='int' 
        ),
        l4_session_usage_grace_period=dict(
            type='int' 
        ),
        l4_session_usage_log=dict(
            type='bool' 
        ),
        l4_session_usage_revert_rate=dict(
            type='int' 
        ),
        lb_method=dict(
            type='str' , choices=['dst-ip-hash', 'dst-ip-only-hash', 'fastest-response', 'least-request', 'src-ip-hash', 'src-ip-only-hash', 'weighted-rr', 'round-robin', 'round-robin-strict', 'odd-even-hash']
        ),
        lc_method=dict(
            type='str' , choices=['least-connection', 'service-least-connection', 'weighted-least-connection', 'service-weighted-least-connection']
        ),
        member_list=dict(
            type='list' 
        ),
        min_active_member=dict(
            type='int' 
        ),
        min_active_member_action=dict(
            type='str' , choices=['dynamic-priority', 'skip-pri-set']
        ),
        name=dict(
            type='str' , required=True
        ),
        priorities=dict(
            type='list' 
        ),
        priority_affinity=dict(
            type='bool' 
        ),
        protocol=dict(
            type='str' , choices=['tcp', 'udp']
        ),
        pseudo_round_robin=dict(
            type='bool' 
        ),
        report_delay=dict(
            type='int' 
        ),
        reset=dict(
            type='str' 
        ),
        reset_on_server_selection_fail=dict(
            type='bool' 
        ),
        reset_priority_affinity=dict(
            type='bool' 
        ),
        rpt_ext_server=dict(
            type='bool' 
        ),
        sample_rsp_time=dict(
            type='bool' 
        ),
        sampling_enable=dict(
            type='list' 
        ),
        stateless_auto_switch=dict(
            type='bool' 
        ),
        stateless_lb_method=dict(
            type='str' , choices=['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']
        ),
        stateless_lb_method2=dict(
            type='str' , choices=['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']
        ),
        stats_data_action=dict(
            type='str' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        strict_select=dict(
            type='bool' 
        ),
        template_policy=dict(
            type='str' 
        ),
        template_port=dict(
            type='str' 
        ),
        template_server=dict(
            type='str' 
        ),
        top_fastest=dict(
            type='bool' 
        ),
        top_slowest=dict(
            type='bool' 
        ),
        traffic_replication_mirror=dict(
            type='bool' 
        ),
        traffic_replication_mirror_da_repl=dict(
            type='bool' 
        ),
        traffic_replication_mirror_ip_repl=dict(
            type='bool' 
        ),
        traffic_replication_mirror_sa_da_repl=dict(
            type='bool' 
        ),
        traffic_replication_mirror_sa_repl=dict(
            type='bool' 
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
    url_base = "/axapi/v3/slb/service-group/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/service-group/{name}"
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
    requires_one_of = sorted(['lb_method','stateless-lb-method','lc_method',])
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
    payload = build_json("service-group", module)
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
    payload = build_json("service-group", module)
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