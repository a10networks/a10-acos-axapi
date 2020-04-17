#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_ip_frag
description:
    - IP fragmentation parameters
short_description: Configures A10 ip.frag
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            cpu_threshold_drop:
                description:
                - "High CPU Drop"
            tcp_rcv:
                description:
                - "TCP Received"
            other_rcv:
                description:
                - "Other Received"
            udp_dropped:
                description:
                - "UDP Dropped"
            bad_ip_len:
                description:
                - "Bad IP Length"
            first_l4_too_small:
                description:
                - "First L4 Fragment Too Small Drop"
            no_session_memory:
                description:
                - "Out of Session Memory"
            unaligned_len:
                description:
                - "Payload Length Unaligned"
            icmp_dropped:
                description:
                - "ICMP Dropped"
            udp_rcv:
                description:
                - "UDP Received"
            exceeded_len:
                description:
                - "Payload Length Out of Bounds"
            fragment_queue_success:
                description:
                - "Fragment Queue Success"
            fragment_queue_failure:
                description:
                - "Fragment Queue Failure"
            tcp_dropped:
                description:
                - "TCP Dropped"
            low_cpu_threshold:
                description:
                - "Low CPU Threshold Reached"
            ipip_dropped:
                description:
                - "IP-in-IP Dropped"
            total_sessions_exceeded:
                description:
                - "Total Sessions Exceeded Drop"
            error_drop:
                description:
                - "Fragment Processing Drop"
            icmp_rcv:
                description:
                - "ICMP Received"
            ipv6ip_rcv:
                description:
                - "IPv6-in-IP Received"
            total_fragments_exceeded:
                description:
                - "Total Queued Fragments Exceeded"
            icmpv6_rcv:
                description:
                - "ICMPv6 Received"
            sctp_rcv:
                description:
                - "SCTP Received"
            policy_drop:
                description:
                - "MTU Exceeded Policy Drop"
            overlap_error:
                description:
                - "Overlapping Fragment Dropped"
            session_packets_exceeded:
                description:
                - "Session Max Packets Exceeded"
            duplicate_first_frag:
                description:
                - "Duplicate First Fragment"
            reassembly_success:
                description:
                - "Fragment Reassembly Success"
            sctp_dropped:
                description:
                - "SCTP Dropped"
            ipd_entry_drop:
                description:
                - "DDoS Protection Drop"
            too_small:
                description:
                - "Fragment Too Small Drop"
            session_expired:
                description:
                - "Session Expired"
            session_inserted:
                description:
                - "Session Inserted"
            max_len_exceeded:
                description:
                - "Fragment Max Data Length Exceeded"
            max_packets_exceeded:
                description:
                - "Too Many Packets Per Reassembly Drop"
            other_dropped:
                description:
                - "Other Dropped"
            ipv6ip_dropped:
                description:
                - "IPv6-in-IP Dropped"
            first_tcp_too_small:
                description:
                - "First TCP Fragment Too Small Drop"
            high_cpu_threshold:
                description:
                - "High CPU Threshold Reached"
            fast_aging_set:
                description:
                - "Fragmentation Fast Aging Set"
            ipip_rcv:
                description:
                - "IP-in-IP Received"
            icmpv6_dropped:
                description:
                - "ICMPv6 Dropped"
            fast_aging_unset:
                description:
                - "Fragmentation Fast Aging Unset"
            reassembly_failure:
                description:
                - "Fragment Reassembly Failure"
            duplicate_last_frag:
                description:
                - "Duplicate Last Fragment"
    uuid:
        description:
        - "uuid of the object"
        required: False
    max_reassembly_sessions:
        description:
        - "Max number of pending reassembly sessions allowed (default 100000)"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'session-inserted'= Session Inserted; 'session-expired'= Session Expired; 'icmp-rcv'= ICMP Received; 'icmpv6-rcv'= ICMPv6 Received; 'udp-rcv'= UDP Received; 'tcp-rcv'= TCP Received; 'ipip-rcv'= IP-in-IP Received; 'ipv6ip-rcv'= IPv6-in-IP Received; 'other-rcv'= Other Received; 'icmp-dropped'= ICMP Dropped; 'icmpv6-dropped'= ICMPv6 Dropped; 'udp-dropped'= UDP Dropped; 'tcp-dropped'= TCP Dropped; 'ipip-dropped'= IP-in-IP Dropped; 'ipv6ip-dropped'= IPv6-in-IP Dropped; 'other-dropped'= Other Dropped; 'overlap-error'= Overlapping Fragment Dropped; 'bad-ip-len'= Bad IP Length; 'too-small'= Fragment Too Small Drop; 'first-tcp-too-small'= First TCP Fragment Too Small Drop; 'first-l4-too-small'= First L4 Fragment Too Small Drop; 'total-sessions-exceeded'= Total Sessions Exceeded Drop; 'no-session-memory'= Out of Session Memory; 'fast-aging-set'= Fragmentation Fast Aging Set; 'fast-aging-unset'= Fragmentation Fast Aging Unset; 'fragment-queue-success'= Fragment Queue Success; 'unaligned-len'= Payload Length Unaligned; 'exceeded-len'= Payload Length Out of Bounds; 'duplicate-first-frag'= Duplicate First Fragment; 'duplicate-last-frag'= Duplicate Last Fragment; 'total-fragments-exceeded'= Total Queued Fragments Exceeded; 'fragment-queue-failure'= Fragment Queue Failure; 'reassembly-success'= Fragment Reassembly Success; 'max-len-exceeded'= Fragment Max Data Length Exceeded; 'reassembly-failure'= Fragment Reassembly Failure; 'policy-drop'= MTU Exceeded Policy Drop; 'error-drop'= Fragment Processing Drop; 'high-cpu-threshold'= High CPU Threshold Reached; 'low-cpu-threshold'= Low CPU Threshold Reached; 'cpu-threshold-drop'= High CPU Drop; 'ipd-entry-drop'= DDoS Protection Drop; 'max-packets-exceeded'= Too Many Packets Per Reassembly Drop; 'session-packets-exceeded'= Session Max Packets Exceeded; 'frag-session-count'= Fragmentation Session Count; 'sctp-rcv'= SCTP Received; 'sctp-dropped'= SCTP Dropped; "
    cpu_threshold:
        description:
        - "Field cpu_threshold"
        required: False
        suboptions:
            high:
                description:
                - "When CPU usage reaches this value, it will stop processing fragments (default= 75%)"
            low:
                description:
                - "When CPU usage remains under this value, it will resume processing fragments (default= 60%)"
    timeout:
        description:
        - "Fragmentation timeout (in milliseconds 4 - 65535 (default is 60000))"
        required: False
    max_packets_per_reassembly:
        description:
        - "Max number of fragmented packets allowed per reassembly(0 is unlimited) (default 0)"
        required: False
    buff:
        description:
        - "Max buff used for fragmentation (Buffer Value(10000-3000000))"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["buff","cpu_threshold","max_packets_per_reassembly","max_reassembly_sessions","sampling_enable","stats","timeout","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        stats=dict(type='dict',cpu_threshold_drop=dict(type='str',),tcp_rcv=dict(type='str',),other_rcv=dict(type='str',),udp_dropped=dict(type='str',),bad_ip_len=dict(type='str',),first_l4_too_small=dict(type='str',),no_session_memory=dict(type='str',),unaligned_len=dict(type='str',),icmp_dropped=dict(type='str',),udp_rcv=dict(type='str',),exceeded_len=dict(type='str',),fragment_queue_success=dict(type='str',),fragment_queue_failure=dict(type='str',),tcp_dropped=dict(type='str',),low_cpu_threshold=dict(type='str',),ipip_dropped=dict(type='str',),total_sessions_exceeded=dict(type='str',),error_drop=dict(type='str',),icmp_rcv=dict(type='str',),ipv6ip_rcv=dict(type='str',),total_fragments_exceeded=dict(type='str',),icmpv6_rcv=dict(type='str',),sctp_rcv=dict(type='str',),policy_drop=dict(type='str',),overlap_error=dict(type='str',),session_packets_exceeded=dict(type='str',),duplicate_first_frag=dict(type='str',),reassembly_success=dict(type='str',),sctp_dropped=dict(type='str',),ipd_entry_drop=dict(type='str',),too_small=dict(type='str',),session_expired=dict(type='str',),session_inserted=dict(type='str',),max_len_exceeded=dict(type='str',),max_packets_exceeded=dict(type='str',),other_dropped=dict(type='str',),ipv6ip_dropped=dict(type='str',),first_tcp_too_small=dict(type='str',),high_cpu_threshold=dict(type='str',),fast_aging_set=dict(type='str',),ipip_rcv=dict(type='str',),icmpv6_dropped=dict(type='str',),fast_aging_unset=dict(type='str',),reassembly_failure=dict(type='str',),duplicate_last_frag=dict(type='str',)),
        uuid=dict(type='str',),
        max_reassembly_sessions=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','session-inserted','session-expired','icmp-rcv','icmpv6-rcv','udp-rcv','tcp-rcv','ipip-rcv','ipv6ip-rcv','other-rcv','icmp-dropped','icmpv6-dropped','udp-dropped','tcp-dropped','ipip-dropped','ipv6ip-dropped','other-dropped','overlap-error','bad-ip-len','too-small','first-tcp-too-small','first-l4-too-small','total-sessions-exceeded','no-session-memory','fast-aging-set','fast-aging-unset','fragment-queue-success','unaligned-len','exceeded-len','duplicate-first-frag','duplicate-last-frag','total-fragments-exceeded','fragment-queue-failure','reassembly-success','max-len-exceeded','reassembly-failure','policy-drop','error-drop','high-cpu-threshold','low-cpu-threshold','cpu-threshold-drop','ipd-entry-drop','max-packets-exceeded','session-packets-exceeded','frag-session-count','sctp-rcv','sctp-dropped'])),
        cpu_threshold=dict(type='dict',high=dict(type='int',),low=dict(type='int',)),
        timeout=dict(type='int',),
        max_packets_per_reassembly=dict(type='int',),
        buff=dict(type='int',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ip/frag"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ip/frag"

    f_dict = {}

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
        for k, v in payload["frag"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["frag"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["frag"][k] = v
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
    payload = build_json("frag", module)
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

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