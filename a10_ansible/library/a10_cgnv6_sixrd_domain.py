#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_sixrd_domain
description:
    - sixrd Domain
short_description: Configures A10 cgnv6.sixrd.domain
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
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
    ipv6_prefix:
        description:
        - "IPv6 prefix"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            inbound_icmp_packets_received:
                description:
                - "Inbound ICMP packets received"
            outbound_udp_packets_received:
                description:
                - "Outbound UDP packets received"
            vport_matched:
                description:
                - "Traffic match SLB virtual port"
            inbound_ipv4_dest_unreachable:
                description:
                - "Inbound IPv4 destination unreachable"
            outbound_packets_drop:
                description:
                - "Outbound packets dropped"
            outbound_fragment_ipv6:
                description:
                - "Outbound Fragmented IPv6"
            not_local_ip:
                description:
                - "Not local IP"
            inbound_tcp_packets_received:
                description:
                - "Inbound TCP packets received"
            fragment_error:
                description:
                - "Fragment processing errors"
            other_error:
                description:
                - "Other errors"
            unknown_delegated_prefix:
                description:
                - "Unknown 6rd delegated prefix"
            outbound_tcp_packets_received:
                description:
                - "Outbound TCP packets received"
            outbound_icmp_packets_received:
                description:
                - "Outbound ICMP packets received"
            name:
                description:
                - "6rd Domain name"
            packet_too_big:
                description:
                - "Packet too big"
            inbound_fragment_ipv4:
                description:
                - "Inbound Fragmented IPv4"
            inbound_tunnel_fragment_ipv6:
                description:
                - "Inbound Fragmented IPv6 in tunnel"
            outbound_ipv6_dest_unreachable:
                description:
                - "Outbound IPv6 destination unreachable"
            inbound_packets_drop:
                description:
                - "Inbound packets dropped"
            inbound_other_packets_received:
                description:
                - "Inbound other packets received"
            inbound_udp_packets_received:
                description:
                - "Inbound UDP packets received"
            outbound_other_packets_received:
                description:
                - "Outbound other packets received"
    name:
        description:
        - "6rd Domain name"
        required: True
    ce_ipv4_network:
        description:
        - "Customer Edge IPv4 network"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    mtu:
        description:
        - "Tunnel MTU"
        required: False
    ce_ipv4_netmask:
        description:
        - "Mask length"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'outbound-tcp-packets-received'= Outbound TCP packets received; 'outbound-udp-packets-received'= Outbound UDP packets received; 'outbound-icmp-packets-received'= Outbound ICMP packets received; 'outbound-other-packets-received'= Outbound other packets received; 'outbound-packets-drop'= Outbound packets dropped; 'outbound-ipv6-dest-unreachable'= Outbound IPv6 destination unreachable; 'outbound-fragment-ipv6'= Outbound Fragmented IPv6; 'inbound-tcp-packets-received'= Inbound TCP packets received; 'inbound-udp-packets-received'= Inbound UDP packets received; 'inbound-icmp-packets-received'= Inbound ICMP packets received; 'inbound-other-packets-received'= Inbound other packets received; 'inbound-packets-drop'= Inbound packets dropped; 'inbound-ipv4-dest-unreachable'= Inbound IPv4 destination unreachable; 'inbound-fragment-ipv4'= Inbound Fragmented IPv4; 'inbound-tunnel-fragment-ipv6'= Inbound Fragmented IPv6 in tunnel; 'vport-matched'= Traffic match SLB virtual port; 'unknown-delegated-prefix'= Unknown 6rd delegated prefix; 'packet-too-big'= Packet too big; 'not-local-ip'= Not local IP; 'fragment-error'= Fragment processing errors; 'other-error'= Other errors; "
    br_ipv4_address:
        description:
        - "6rd BR IPv4 address"
        required: False
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["br_ipv4_address","ce_ipv4_netmask","ce_ipv4_network","ipv6_prefix","mtu","name","sampling_enable","stats","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        ipv6_prefix=dict(type='str', ),
        stats=dict(type='dict', inbound_icmp_packets_received=dict(type='str', ), outbound_udp_packets_received=dict(type='str', ), vport_matched=dict(type='str', ), inbound_ipv4_dest_unreachable=dict(type='str', ), outbound_packets_drop=dict(type='str', ), outbound_fragment_ipv6=dict(type='str', ), not_local_ip=dict(type='str', ), inbound_tcp_packets_received=dict(type='str', ), fragment_error=dict(type='str', ), other_error=dict(type='str', ), unknown_delegated_prefix=dict(type='str', ), outbound_tcp_packets_received=dict(type='str', ), outbound_icmp_packets_received=dict(type='str', ), name=dict(type='str', required=True, ), packet_too_big=dict(type='str', ), inbound_fragment_ipv4=dict(type='str', ), inbound_tunnel_fragment_ipv6=dict(type='str', ), outbound_ipv6_dest_unreachable=dict(type='str', ), inbound_packets_drop=dict(type='str', ), inbound_other_packets_received=dict(type='str', ), inbound_udp_packets_received=dict(type='str', ), outbound_other_packets_received=dict(type='str', )),
        name=dict(type='str', required=True, ),
        ce_ipv4_network=dict(type='str', ),
        user_tag=dict(type='str', ),
        mtu=dict(type='int', ),
        ce_ipv4_netmask=dict(type='str', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'outbound-tcp-packets-received', 'outbound-udp-packets-received', 'outbound-icmp-packets-received', 'outbound-other-packets-received', 'outbound-packets-drop', 'outbound-ipv6-dest-unreachable', 'outbound-fragment-ipv6', 'inbound-tcp-packets-received', 'inbound-udp-packets-received', 'inbound-icmp-packets-received', 'inbound-other-packets-received', 'inbound-packets-drop', 'inbound-ipv4-dest-unreachable', 'inbound-fragment-ipv4', 'inbound-tunnel-fragment-ipv6', 'vport-matched', 'unknown-delegated-prefix', 'packet-too-big', 'not-local-ip', 'fragment-error', 'other-error'])),
        br_ipv4_address=dict(type='str', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/sixrd/domain/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/sixrd/domain/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["domain"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["domain"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["domain"][k] = v
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
    payload = build_json("domain", module)
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