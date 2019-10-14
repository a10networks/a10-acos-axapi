#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_tcp_proxy
description:
    - TCP Proxy
short_description: Configures A10 slb.template.tcp-proxy
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    qos:
        description:
        - "QOS level (number)"
        required: False
    init_cwnd:
        description:
        - "The initial congestion control window size (packets), default is 10 (init-cwnd in packets, default 10)"
        required: False
    idle_timeout:
        description:
        - "Idle Timeout (Interval of 60 seconds), default is 600 (idle timeout in second, default 600)"
        required: False
    fin_timeout:
        description:
        - "FIN timeout (sec), default is disabled (number)"
        required: False
    half_open_idle_timeout:
        description:
        - "TCP Half Open Idle Timeout (sec), default is off (number)"
        required: False
    reno:
        description:
        - "Enable Reno Congestion Control Algorithm"
        required: False
    down:
        description:
        - "send reset to client when server is down"
        required: False
    early_retransmit:
        description:
        - "Configure the Early-Retransmit Algorithm (RFC 5827) (Early-Retransmit is disabled by default)"
        required: False
    server_down_action:
        description:
        - "'FIN'= FIN Connection; 'RST'= Reset Connection; "
        required: False
    timewait:
        description:
        - "Timewait Threshold (sec), default 5 (number)"
        required: False
    min_rto:
        description:
        - "The minmum retransmission timeout, default is 200ms (number)"
        required: False
    dynamic_buffer_allocation:
        description:
        - "Optimally adjust the transmit and receive buffer sizes of TCP proxy while keeping their sum constant"
        required: False
    limited_slowstart:
        description:
        - "RFC 3742 Limited Slow-Start for TCP with Large Congestion Windows (number)"
        required: False
    disable_sack:
        description:
        - "disable Selective Ack Option"
        required: False
    disable_window_scale:
        description:
        - "disable TCP Window-Scale Option"
        required: False
    alive_if_active:
        description:
        - "keep connection alive if active traffic"
        required: False
    mss:
        description:
        - "Responding MSS to use if client MSS is large, default is off (number)"
        required: False
    keepalive_interval:
        description:
        - "Interval between keepalive probes (sec), default is off (number (seconds))"
        required: False
    retransmit_retries:
        description:
        - "Number of Retries for Retransmit, default is 5"
        required: False
    insert_client_ip:
        description:
        - "Insert client ip into TCP option"
        required: False
    transmit_buffer:
        description:
        - "TCP Transmit Buffer (default 200k) (number default 200000 bytes)"
        required: False
    nagle:
        description:
        - "Enable Nagle Algorithm"
        required: False
    force_delete_timeout_100ms:
        description:
        - "The maximum time that a session can stay in the system before being deleted, default is off (number in 100ms)"
        required: False
    initial_window_size:
        description:
        - "Set the initial window size, default is off (number)"
        required: False
    keepalive_probes:
        description:
        - "Number of keepalive probes sent, default is off"
        required: False
    psh_flag_optimization:
        description:
        - "Enable Optimized PSH Flag Use"
        required: False
    ack_aggressiveness:
        description:
        - "'low'= Delayed ACK; 'medium'= Delayed ACK, with ACK on each packet with PUSH flag; 'high'= ACK on each packet; "
        required: False
    backend_wscale:
        description:
        - "The TCP window scale used for the server side, default is off (number)"
        required: False
    disable:
        description:
        - "send reset to client when server is disabled"
        required: False
    reset_rev:
        description:
        - "send reset to client if error happens"
        required: False
    maxburst:
        description:
        - "The max packet count sent per transmission event (number)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    receive_buffer:
        description:
        - "TCP Receive Buffer (default 200k) (number default 200000 bytes)"
        required: False
    del_session_on_server_down:
        description:
        - "Delete session if the server/port goes down (either disabled/hm down)"
        required: False
    name:
        description:
        - "TCP Proxy Template Name"
        required: True
    reassembly_timeout:
        description:
        - "The reassembly timeout, default is 30sec (number)"
        required: False
    reset_fwd:
        description:
        - "send reset to server if error happens"
        required: False
    disable_tcp_timestamps:
        description:
        - "disable TCP Timestamps Option"
        required: False
    syn_retries:
        description:
        - "SYN Retry Numbers, default is 5"
        required: False
    force_delete_timeout:
        description:
        - "The maximum time that a session can stay in the system before being deleted, default is off (number (second))"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    reassembly_limit:
        description:
        - "The reassembly queuing limit, default is 25 segments (number)"
        required: False
    invalid_rate_limit:
        description:
        - "Invalid Packet Response Rate Limit (ms), default is 500 (number default 500 challenges)"
        required: False
    disable_abc:
        description:
        - "Appropriate Byte Counting RFC 3465 Disabled, default is enabled (Appropriate Byte Counting (ABC) is enabled by default)"
        required: False
    half_close_idle_timeout:
        description:
        - "TCP Half Close Idle Timeout (sec), default is off (cmd is deprecated, use fin-timeout instead) (number)"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["ack_aggressiveness","alive_if_active","backend_wscale","del_session_on_server_down","disable","disable_abc","disable_sack","disable_tcp_timestamps","disable_window_scale","down","dynamic_buffer_allocation","early_retransmit","fin_timeout","force_delete_timeout","force_delete_timeout_100ms","half_close_idle_timeout","half_open_idle_timeout","idle_timeout","init_cwnd","initial_window_size","insert_client_ip","invalid_rate_limit","keepalive_interval","keepalive_probes","limited_slowstart","maxburst","min_rto","mss","nagle","name","psh_flag_optimization","qos","reassembly_limit","reassembly_timeout","receive_buffer","reno","reset_fwd","reset_rev","retransmit_retries","server_down_action","syn_retries","timewait","transmit_buffer","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        qos=dict(type='int',),
        init_cwnd=dict(type='int',),
        idle_timeout=dict(type='int',),
        fin_timeout=dict(type='int',),
        half_open_idle_timeout=dict(type='int',),
        reno=dict(type='bool',),
        down=dict(type='bool',),
        early_retransmit=dict(type='bool',),
        server_down_action=dict(type='str',choices=['FIN','RST']),
        timewait=dict(type='int',),
        min_rto=dict(type='int',),
        dynamic_buffer_allocation=dict(type='bool',),
        limited_slowstart=dict(type='int',),
        disable_sack=dict(type='bool',),
        disable_window_scale=dict(type='bool',),
        alive_if_active=dict(type='bool',),
        mss=dict(type='int',),
        keepalive_interval=dict(type='int',),
        retransmit_retries=dict(type='int',),
        insert_client_ip=dict(type='bool',),
        transmit_buffer=dict(type='int',),
        nagle=dict(type='bool',),
        force_delete_timeout_100ms=dict(type='int',),
        initial_window_size=dict(type='int',),
        keepalive_probes=dict(type='int',),
        psh_flag_optimization=dict(type='bool',),
        ack_aggressiveness=dict(type='str',choices=['low','medium','high']),
        backend_wscale=dict(type='int',),
        disable=dict(type='bool',),
        reset_rev=dict(type='bool',),
        maxburst=dict(type='int',),
        uuid=dict(type='str',),
        receive_buffer=dict(type='int',),
        del_session_on_server_down=dict(type='bool',),
        name=dict(type='str',required=True,),
        reassembly_timeout=dict(type='int',),
        reset_fwd=dict(type='bool',),
        disable_tcp_timestamps=dict(type='bool',),
        syn_retries=dict(type='int',),
        force_delete_timeout=dict(type='int',),
        user_tag=dict(type='str',),
        reassembly_limit=dict(type='int',),
        invalid_rate_limit=dict(type='int',),
        disable_abc=dict(type='bool',),
        half_close_idle_timeout=dict(type='int',)
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

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["tcp-proxy"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["tcp-proxy"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["tcp-proxy"][k] = v
        result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
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

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result, existing_config):
    payload = build_json("tcp-proxy", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()