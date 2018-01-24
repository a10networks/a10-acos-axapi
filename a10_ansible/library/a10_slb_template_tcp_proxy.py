#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_template_tcp-proxy
description:
    - TCP Proxy
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - TCP Proxy Template Name
    
    ack-aggressiveness:
        description:
            - 'low': Delayed ACK; 'medium': Delayed ACK, with ACK on each packet with PUSH flag; 'high': ACK on each packet; choices:['low', 'medium', 'high']
    
    backend-wscale:
        description:
            - The TCP window scale used for the server side, default is off (number)
    
    dynamic-buffer-allocation:
        description:
            - Optimally adjust the transmit and receive buffer sizes of TCP proxy while keeping their sum constant
    
    fin-timeout:
        description:
            - FIN timeout (sec), default is 5 (number)
    
    force-delete-timeout:
        description:
            - The maximum time that a session can stay in the system before being deleted, default is off (number (second))
    
    force-delete-timeout-100ms:
        description:
            - The maximum time that a session can stay in the system before being deleted, default is off (number in 100ms)
    
    alive-if-active:
        description:
            - keep connection alive if active traffic
    
    idle-timeout:
        description:
            - Idle Timeout (Interval of 60 seconds), default is 600 (idle timeout in second, default 600)
    
    server-down-action:
        description:
            - 'FIN': FIN Connection; 'RST': Reset Connection; choices:['FIN', 'RST']
    
    half-open-idle-timeout:
        description:
            - TCP Half Open Idle Timeout (sec), default is off (number)
    
    half-close-idle-timeout:
        description:
            - TCP Half Close Idle Timeout (sec), default is off (number)
    
    init-cwnd:
        description:
            - The initial congestion control window size (packets), default is 10 (number)
    
    initial-window-size:
        description:
            - Set the initial window size, default is off (number)
    
    keepalive-interval:
        description:
            - Interval between keepalive probes (sec), default is off (number)
    
    keepalive-probes:
        description:
            - Number of keepalive probes sent, default is off
    
    mss:
        description:
            - Responding MSS to use if client MSS is large, default is off (number)
    
    nagle:
        description:
            - Enable Nagle Algorithm
    
    qos:
        description:
            - QOS level (number)
    
    receive-buffer:
        description:
            - TCP Receive Buffer (default 200k) (number)
    
    reno:
        description:
            - Enable Reno Congestion Control Algorithm
    
    transmit-buffer:
        description:
            - TCP Transmit Buffer (default 200k) (number)
    
    reset-fwd:
        description:
            - send reset to server if error happens
    
    reset-rev:
        description:
            - send reset to client if error happens
    
    disable:
        description:
            - send reset to client when server is disabled
    
    down:
        description:
            - send reset to client when server is down
    
    del-session-on-server-down:
        description:
            - Delete session if the server/port goes down (either disabled/hm down)
    
    retransmit-retries:
        description:
            - Number of Retries for Retransmit, default is 5
    
    insert-client-ip:
        description:
            - Insert client ip into TCP option
    
    syn-retries:
        description:
            - SYN Retry Numbers, default is 5
    
    timewait:
        description:
            - Timewait Threshold (sec), default 5 (number)
    
    disable-tcp-timestamps:
        description:
            - disable TCP Timestamps Option
    
    disable-window-scale:
        description:
            - disable TCP Window-Scale Option
    
    disable-sack:
        description:
            - disable Selective Ack Option
    
    invalid-rate-limit:
        description:
            - Invalid Packet Response Rate Limit (ms), default is 500 (number)
    
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
AVAILABLE_PROPERTIES = ["ack_aggressiveness","alive_if_active","backend_wscale","del_session_on_server_down","disable","disable_sack","disable_tcp_timestamps","disable_window_scale","down","dynamic_buffer_allocation","fin_timeout","force_delete_timeout","force_delete_timeout_100ms","half_close_idle_timeout","half_open_idle_timeout","idle_timeout","init_cwnd","initial_window_size","insert_client_ip","invalid_rate_limit","keepalive_interval","keepalive_probes","mss","nagle","name","qos","receive_buffer","reno","reset_fwd","reset_rev","retransmit_retries","server_down_action","syn_retries","timewait","transmit_buffer","user_tag","uuid",]

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
        
        ack_aggressiveness=dict(
            type='str' , choices=['low', 'medium', 'high']
        ),
        alive_if_active=dict(
            type='bool' 
        ),
        backend_wscale=dict(
            type='int' 
        ),
        del_session_on_server_down=dict(
            type='bool' 
        ),
        disable=dict(
            type='bool' 
        ),
        disable_sack=dict(
            type='bool' 
        ),
        disable_tcp_timestamps=dict(
            type='bool' 
        ),
        disable_window_scale=dict(
            type='bool' 
        ),
        down=dict(
            type='bool' 
        ),
        dynamic_buffer_allocation=dict(
            type='bool' 
        ),
        fin_timeout=dict(
            type='int' 
        ),
        force_delete_timeout=dict(
            type='int' 
        ),
        force_delete_timeout_100ms=dict(
            type='int' 
        ),
        half_close_idle_timeout=dict(
            type='int' 
        ),
        half_open_idle_timeout=dict(
            type='int' 
        ),
        idle_timeout=dict(
            type='int' 
        ),
        init_cwnd=dict(
            type='int' 
        ),
        initial_window_size=dict(
            type='int' 
        ),
        insert_client_ip=dict(
            type='bool' 
        ),
        invalid_rate_limit=dict(
            type='int' 
        ),
        keepalive_interval=dict(
            type='int' 
        ),
        keepalive_probes=dict(
            type='int' 
        ),
        mss=dict(
            type='int' 
        ),
        nagle=dict(
            type='bool' 
        ),
        name=dict(
            type='str' , required=True
        ),
        qos=dict(
            type='int' 
        ),
        receive_buffer=dict(
            type='int' 
        ),
        reno=dict(
            type='bool' 
        ),
        reset_fwd=dict(
            type='bool' 
        ),
        reset_rev=dict(
            type='bool' 
        ),
        retransmit_retries=dict(
            type='int' 
        ),
        server_down_action=dict(
            type='str' , choices=['FIN', 'RST']
        ),
        syn_retries=dict(
            type='int' 
        ),
        timewait=dict(
            type='int' 
        ),
        transmit_buffer=dict(
            type='int' 
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
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/tcp-proxy/{name}"
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
    payload = build_json("tcp-proxy", module)
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
    payload = build_json("tcp-proxy", module)
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