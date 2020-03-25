#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_counter_vtep
description:
    - Virtual Tunnel End Point
short_description: Configures A10 counter.vtep
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'cfg_vtep_error'= Config Error= Drop Packet; 'tx_flood_pkts'= Out Flooded Packets; 'tx_encap_unresolved_pkts'= Remote Vtep unreachable= Drop Tx; 'tx_encap_missing_pkts'= Remote Vtep unreachable= Drop Tx; 'tx_encap_bad_pkts'= Remote Vtep unreachable= Drop Tx; 'tx_arp_req_sent_pkts'= Number of Arp Requests Sent; 'rx_host_learned'= Number of Host =; 'rx_host_learn_error'= Number of Host =; 'rx_lif_invalid'= Invalid Lif= Drop Rx; 'tx_lif_invalid'= Invalid Lif= Drop Tx; 'tx_vtep_unknown'= Vtep unknown= Drop Tx; 'rx_vtep_unknown'= Vtep unknown= Drop Rx; 'rx_unhandled_pkts'= Unhandled Packets= Drop Rx; 'tx_unhandled_pkts'= Unhandled Packets= Drop Tx; 'rx_pkts'= In Total Packets; 'rx_bytes'= In Total Octets; 'rx_ucast_pkts'= In Unicast Packets; 'rx_bcast_pkts'= In Broadcast Packets; 'rx_mcast_pkts'= Out Multicast Packets; 'rx_dropped_pkts'= In Dropped Packets; 'rx_encap_miss_pkts'= Remote Vtep unreachable= Drop Tx; 'rx_bad_checksum_pkts'= Packet reveived with Bad Inner checksum; 'rx_requeued_pkts'= Packets requeued to another CPU; 'tx_pkts'= Out Total Packets; 'tx_bytes'= Out Total Octets; 'tx_ucast_pkts'= Out Unicast Packets; 'tx_bcast_pkts'= Out Broadcast Packets; 'tx_mcast_pkts'= Out Multicast Packets; 'tx_dropped_pkts'= Out Dropped Packets; 'rx_pkts_too_large'= Packet too large= Drop Rx; 'rx_dot1q_ptks'= Dot1q Packet= Drop Rx; 'tx_fragmented_pkts'= Fragmented Packets; 'rx_reassembled_pkts'= Reassembled Packets; 'rx_bad_inner_ipv4_len_pkts'= Packets received with Bad Inner IPv4 Payload length; 'rx_bad_inner_ipv6_len_pkts'= Packets received with Bad Inner IPv6 Payload length; 'rx_lif_uninit'= Lif not UP= Drop Rx; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            rx_bad_inner_ipv4_len_pkts:
                description:
                - "Packets received with Bad Inner IPv4 Payload length"
            rx_pkts:
                description:
                - "In Total Packets"
            tx_encap_missing_pkts:
                description:
                - "Remote Vtep unreachable= Drop Tx"
            tx_arp_req_sent_pkts:
                description:
                - "Number of Arp Requests Sent"
            cfg_vtep_error:
                description:
                - "Config Error= Drop Packet"
            rx_reassembled_pkts:
                description:
                - "Reassembled Packets"
            rx_ucast_pkts:
                description:
                - "In Unicast Packets"
            rx_lif_uninit:
                description:
                - "Lif not UP= Drop Rx"
            rx_lif_invalid:
                description:
                - "Invalid Lif= Drop Rx"
            rx_encap_miss_pkts:
                description:
                - "Remote Vtep unreachable= Drop Tx"
            rx_bad_checksum_pkts:
                description:
                - "Packet reveived with Bad Inner checksum"
            tx_bcast_pkts:
                description:
                - "Out Broadcast Packets"
            rx_host_learned:
                description:
                - "Number of Host ="
            rx_unhandled_pkts:
                description:
                - "Unhandled Packets= Drop Rx"
            rx_mcast_pkts:
                description:
                - "Out Multicast Packets"
            rx_host_learn_error:
                description:
                - "Number of Host ="
            rx_dot1q_ptks:
                description:
                - "Dot1q Packet= Drop Rx"
            tx_fragmented_pkts:
                description:
                - "Fragmented Packets"
            tx_lif_invalid:
                description:
                - "Invalid Lif= Drop Tx"
            rx_requeued_pkts:
                description:
                - "Packets requeued to another CPU"
            rx_dropped_pkts:
                description:
                - "In Dropped Packets"
            tx_flood_pkts:
                description:
                - "Out Flooded Packets"
            rx_bad_inner_ipv6_len_pkts:
                description:
                - "Packets received with Bad Inner IPv6 Payload length"
            rx_pkts_too_large:
                description:
                - "Packet too large= Drop Rx"
            tx_bytes:
                description:
                - "Out Total Octets"
            tx_mcast_pkts:
                description:
                - "Out Multicast Packets"
            tx_vtep_unknown:
                description:
                - "Vtep unknown= Drop Tx"
            tx_encap_unresolved_pkts:
                description:
                - "Remote Vtep unreachable= Drop Tx"
            rx_vtep_unknown:
                description:
                - "Vtep unknown= Drop Rx"
            tx_encap_bad_pkts:
                description:
                - "Remote Vtep unreachable= Drop Tx"
            tx_unhandled_pkts:
                description:
                - "Unhandled Packets= Drop Tx"
            rx_bcast_pkts:
                description:
                - "In Broadcast Packets"
            tx_ucast_pkts:
                description:
                - "Out Unicast Packets"
            tx_pkts:
                description:
                - "Out Total Packets"
            rx_bytes:
                description:
                - "In Total Octets"
            tx_dropped_pkts:
                description:
                - "Out Dropped Packets"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","stats",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','cfg_vtep_error','tx_flood_pkts','tx_encap_unresolved_pkts','tx_encap_missing_pkts','tx_encap_bad_pkts','tx_arp_req_sent_pkts','rx_host_learned','rx_host_learn_error','rx_lif_invalid','tx_lif_invalid','tx_vtep_unknown','rx_vtep_unknown','rx_unhandled_pkts','tx_unhandled_pkts','rx_pkts','rx_bytes','rx_ucast_pkts','rx_bcast_pkts','rx_mcast_pkts','rx_dropped_pkts','rx_encap_miss_pkts','rx_bad_checksum_pkts','rx_requeued_pkts','tx_pkts','tx_bytes','tx_ucast_pkts','tx_bcast_pkts','tx_mcast_pkts','tx_dropped_pkts','rx_pkts_too_large','rx_dot1q_ptks','tx_fragmented_pkts','rx_reassembled_pkts','rx_bad_inner_ipv4_len_pkts','rx_bad_inner_ipv6_len_pkts','rx_lif_uninit'])),
        stats=dict(type='dict',rx_bad_inner_ipv4_len_pkts=dict(type='str',),rx_pkts=dict(type='str',),tx_encap_missing_pkts=dict(type='str',),tx_arp_req_sent_pkts=dict(type='str',),cfg_vtep_error=dict(type='str',),rx_reassembled_pkts=dict(type='str',),rx_ucast_pkts=dict(type='str',),rx_lif_uninit=dict(type='str',),rx_lif_invalid=dict(type='str',),rx_encap_miss_pkts=dict(type='str',),rx_bad_checksum_pkts=dict(type='str',),tx_bcast_pkts=dict(type='str',),rx_host_learned=dict(type='str',),rx_unhandled_pkts=dict(type='str',),rx_mcast_pkts=dict(type='str',),rx_host_learn_error=dict(type='str',),rx_dot1q_ptks=dict(type='str',),tx_fragmented_pkts=dict(type='str',),tx_lif_invalid=dict(type='str',),rx_requeued_pkts=dict(type='str',),rx_dropped_pkts=dict(type='str',),tx_flood_pkts=dict(type='str',),rx_bad_inner_ipv6_len_pkts=dict(type='str',),rx_pkts_too_large=dict(type='str',),tx_bytes=dict(type='str',),tx_mcast_pkts=dict(type='str',),tx_vtep_unknown=dict(type='str',),tx_encap_unresolved_pkts=dict(type='str',),rx_vtep_unknown=dict(type='str',),tx_encap_bad_pkts=dict(type='str',),tx_unhandled_pkts=dict(type='str',),rx_bcast_pkts=dict(type='str',),tx_ucast_pkts=dict(type='str',),tx_pkts=dict(type='str',),rx_bytes=dict(type='str',),tx_dropped_pkts=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/counter/vtep/{sampling-enable}"

    f_dict = {}
    f_dict["sampling-enable"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/counter/vtep/{sampling-enable}"

    f_dict = {}
    f_dict["sampling-enable"] = module.params["sampling_enable"]

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
        for k, v in payload["vtep"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["vtep"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["vtep"][k] = v
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
    payload = build_json("vtep", module)
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