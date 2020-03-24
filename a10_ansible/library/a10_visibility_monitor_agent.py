#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_visibility_monitor_agent
description:
    - Configure xflow agent
short_description: Configures A10 visibility.monitor.agent
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            netflow_v10_packets_received:
                description:
                - "Netflow v10 Packets Received"
            netflow_v9_sample_records_bad_len:
                description:
                - "Netflow v9 Sample Records Bad Length"
            sflow_disabled:
                description:
                - "sFlow Packet Samples Processing Disabled"
            sflow_sample_record_bad_len:
                description:
                - "sFlow Sample Records Bad Length"
            netflow_v5_sample_records_bad_len:
                description:
                - "Netflow v5 Sample Records Bad Length"
            netflow_tcp_sample_received:
                description:
                - "Netflow TCP Samples Received"
            agent_name:
                description:
                - "Specify name for the agent"
            netflow_v10_samples_received:
                description:
                - "Netflow v10 Samples Received"
            netflow_record_rse_invalid:
                description:
                - "Netflow Data Record Reduced Size Invalid"
            sflow_samples_skipped:
                description:
                - "sFlow Samples Skipped"
            netflow_disabled:
                description:
                - "Netflow Flow Samples Processing Disabled"
            netflow_v9_samples_received:
                description:
                - "Netflow v9 Samples Received"
            sflow_samples_received:
                description:
                - "sFlow Samples Received"
            sflow_sample_record_invalid_layer2:
                description:
                - "sFlow Sample Records Unknown Layer-2"
            netflow_v10_sample_records_bad_len:
                description:
                - "Netflow v10 Sample Records Bad Length"
            netflow_icmp_sample_received:
                description:
                - "Netflow ICMP Samples Received"
            netflow_udp_sample_received:
                description:
                - "Netflow UDP Samples received"
            netflow_v9_packets_received:
                description:
                - "Netflow v9 Packets Received"
            netflow_v10_samples_sent_for_detection:
                description:
                - "Netflow v10 Samples Procssed For Detection"
            sflow_packets_received:
                description:
                - "sFlow Packets Received"
            sflow_samples_sent_for_detection:
                description:
                - "sFlow Samples Processed For Detection"
            netflow_v9_max_records_exceed:
                description:
                - "Netflow v9 Sample Max Records Error"
            netflow_v5_samples_received:
                description:
                - "Netflow v5 Samples Received"
            netflow_sample_flow_dur_error:
                description:
                - "Netflow Sample Flow Duration Error"
            sflow_samples_non_std:
                description:
                - "sFlow Samples Non-standard"
            netflow_other_sample_received:
                description:
                - "Netflow OTHER Samples Received"
            netflow_v5_packets_received:
                description:
                - "Netflow v5 Packets Received"
            netflow_v5_max_records_exceed:
                description:
                - "Netflow v5 Sample Max Records Error"
            sflow_sample_ipv6_hdr_parse_fail:
                description:
                - "sFlow Sample IPv6 Record Header Parse Failures"
            netflow_v10_max_records_exceed:
                description:
                - "Netflow v10 Sample Max records Error"
            netflow_v5_samples_sent_for_detection:
                description:
                - "Netflow v5 Samples Processed For Detection"
            sflow_samples_bad_len:
                description:
                - "sFlow Samples Bad Length"
            netflow_record_copy_oom_error:
                description:
                - "Netflow Data Record Copy Fail OOM"
            netflow_v9_samples_sent_for_detection:
                description:
                - "Netflow v9 Samples Processed For Detection"
    uuid:
        description:
        - "uuid of the object"
        required: False
    agent_v4_addr:
        description:
        - "Configure agent's IPv4 address"
        required: False
    agent_v6_addr:
        description:
        - "Configure agent's IPv6 address"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'sflow-packets-received'= sFlow Packets Received; 'sflow-samples-received'= sFlow Samples Received; 'sflow-samples-bad-len'= sFlow Samples Bad Length; 'sflow-samples-non-std'= sFlow Samples Non-standard; 'sflow-samples-skipped'= sFlow Samples Skipped; 'sflow-sample-record-bad-len'= sFlow Sample Records Bad Length; 'sflow-samples-sent-for-detection'= sFlow Samples Processed For Detection; 'sflow-sample-record-invalid-layer2'= sFlow Sample Records Unknown Layer-2; 'sflow-sample-ipv6-hdr-parse-fail'= sFlow Sample IPv6 Record Header Parse Failures; 'sflow-disabled'= sFlow Packet Samples Processing Disabled; 'netflow-disabled'= Netflow Flow Samples Processing Disabled; 'netflow-v5-packets-received'= Netflow v5 Packets Received; 'netflow-v5-samples-received'= Netflow v5 Samples Received; 'netflow-v5-samples-sent-for-detection'= Netflow v5 Samples Processed For Detection; 'netflow-v5-sample-records-bad-len'= Netflow v5 Sample Records Bad Length; 'netflow-v5-max-records-exceed'= Netflow v5 Sample Max Records Error; 'netflow-v9-packets-received'= Netflow v9 Packets Received; 'netflow-v9-samples-received'= Netflow v9 Samples Received; 'netflow-v9-samples-sent-for-detection'= Netflow v9 Samples Processed For Detection; 'netflow-v9-sample-records-bad-len'= Netflow v9 Sample Records Bad Length; 'netflow-v9-max-records-exceed'= Netflow v9 Sample Max Records Error; 'netflow-v10-packets-received'= Netflow v10 Packets Received; 'netflow-v10-samples-received'= Netflow v10 Samples Received; 'netflow-v10-samples-sent-for-detection'= Netflow v10 Samples Procssed For Detection; 'netflow-v10-sample-records-bad-len'= Netflow v10 Sample Records Bad Length; 'netflow-v10-max-records-exceed'= Netflow v10 Sample Max records Error; 'netflow-tcp-sample-received'= Netflow TCP Samples Received; 'netflow-udp-sample-received'= Netflow UDP Samples received; 'netflow-icmp-sample-received'= Netflow ICMP Samples Received; 'netflow-other-sample-received'= Netflow OTHER Samples Received; 'netflow-record-copy-oom-error'= Netflow Data Record Copy Fail OOM; 'netflow-record-rse-invalid'= Netflow Data Record Reduced Size Invalid; 'netflow-sample-flow-dur-error'= Netflow Sample Flow Duration Error; "
    agent_name:
        description:
        - "Specify name for the agent"
        required: True


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["agent_name","agent_v4_addr","agent_v6_addr","sampling_enable","stats","user_tag","uuid",]

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
        stats=dict(type='dict',netflow_v10_packets_received=dict(type='str',),netflow_v9_sample_records_bad_len=dict(type='str',),sflow_disabled=dict(type='str',),sflow_sample_record_bad_len=dict(type='str',),netflow_v5_sample_records_bad_len=dict(type='str',),netflow_tcp_sample_received=dict(type='str',),agent_name=dict(type='str',required=True,),netflow_v10_samples_received=dict(type='str',),netflow_record_rse_invalid=dict(type='str',),sflow_samples_skipped=dict(type='str',),netflow_disabled=dict(type='str',),netflow_v9_samples_received=dict(type='str',),sflow_samples_received=dict(type='str',),sflow_sample_record_invalid_layer2=dict(type='str',),netflow_v10_sample_records_bad_len=dict(type='str',),netflow_icmp_sample_received=dict(type='str',),netflow_udp_sample_received=dict(type='str',),netflow_v9_packets_received=dict(type='str',),netflow_v10_samples_sent_for_detection=dict(type='str',),sflow_packets_received=dict(type='str',),sflow_samples_sent_for_detection=dict(type='str',),netflow_v9_max_records_exceed=dict(type='str',),netflow_v5_samples_received=dict(type='str',),netflow_sample_flow_dur_error=dict(type='str',),sflow_samples_non_std=dict(type='str',),netflow_other_sample_received=dict(type='str',),netflow_v5_packets_received=dict(type='str',),netflow_v5_max_records_exceed=dict(type='str',),sflow_sample_ipv6_hdr_parse_fail=dict(type='str',),netflow_v10_max_records_exceed=dict(type='str',),netflow_v5_samples_sent_for_detection=dict(type='str',),sflow_samples_bad_len=dict(type='str',),netflow_record_copy_oom_error=dict(type='str',),netflow_v9_samples_sent_for_detection=dict(type='str',)),
        uuid=dict(type='str',),
        agent_v4_addr=dict(type='str',),
        agent_v6_addr=dict(type='str',),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sflow-packets-received','sflow-samples-received','sflow-samples-bad-len','sflow-samples-non-std','sflow-samples-skipped','sflow-sample-record-bad-len','sflow-samples-sent-for-detection','sflow-sample-record-invalid-layer2','sflow-sample-ipv6-hdr-parse-fail','sflow-disabled','netflow-disabled','netflow-v5-packets-received','netflow-v5-samples-received','netflow-v5-samples-sent-for-detection','netflow-v5-sample-records-bad-len','netflow-v5-max-records-exceed','netflow-v9-packets-received','netflow-v9-samples-received','netflow-v9-samples-sent-for-detection','netflow-v9-sample-records-bad-len','netflow-v9-max-records-exceed','netflow-v10-packets-received','netflow-v10-samples-received','netflow-v10-samples-sent-for-detection','netflow-v10-sample-records-bad-len','netflow-v10-max-records-exceed','netflow-tcp-sample-received','netflow-udp-sample-received','netflow-icmp-sample-received','netflow-other-sample-received','netflow-record-copy-oom-error','netflow-record-rse-invalid','netflow-sample-flow-dur-error'])),
        agent_name=dict(type='str',required=True,)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/monitor/agent/{agent-name}"

    f_dict = {}
    f_dict["agent-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/monitor/agent/{agent-name}"

    f_dict = {}
    f_dict["agent-name"] = module.params["agent_name"]

    return url_base.format(**f_dict)

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
        if v is not None:
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

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["agent"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["agent"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["agent"][k] = v
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
    payload = build_json("agent", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
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