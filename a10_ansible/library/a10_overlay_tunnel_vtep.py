#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_overlay_tunnel_vtep
description:
    - Virtual Tunnel end point Configuration
short_description: Configures A10 overlay-tunnel.vtep
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            total_bytes_rx:
                description:
                - "Total packet bytes in"
            dropped_pkt_rx:
                description:
                - "Dropped received packets"
            pkts_out:
                description:
                - "Packets out"
            unhandled_pkt_rx:
                description:
                - "Unhandled packets in"
            unknown_encap_tx_pkt:
                description:
                - "Encap miss tx pkts"
            reassembled_pkts_rx:
                description:
                - "Reassembled packets in"
            id:
                description:
                - "VTEP Identifier"
            frag_pkts_tx:
                description:
                - "Frag packets out"
            dropped_pkts_tx:
                description:
                - "Dropped packets out"
            mcast_pkt_tx:
                description:
                - "Multicast packets out"
            large_pkts_rx:
                description:
                - "Too large packets in"
            invalid_lif_tx:
                description:
                - "Invalid Lif pkts out"
            total_bytes_tx:
                description:
                - "Packet bytes out"
            invalid_lif_rx:
                description:
                - "Invalid Lif pkts in"
            unicast_pkt_rx:
                description:
                - "Total unicast packets in"
            dot1q_pkts_rx:
                description:
                - "Dot1q packets in"
            vtep_host_learned:
                description:
                - "Hosts learned"
            unhandled_pkt_tx:
                description:
                - "Unhandled packets out"
            unknown_vtep_rx:
                description:
                - "Vtep Unkown rx"
            encap_miss_pkts_rx:
                description:
                - "Encap missed in received packets"
            unknown_encap_rx_pkt:
                description:
                - "Encap miss rx pkts"
            bad_chksum_pks_rx:
                description:
                - "Bad checksum in received packets"
            encap_unresolved_count:
                description:
                - "Encap unresolved failures"
            bad_inner_ipv6_len_rx:
                description:
                - "Bad inner ipv6 packet len"
            cfg_err_count:
                description:
                - "Config errors"
            unknown_vtep_tx:
                description:
                - "Vtep unknown tx"
            flooded_pkt_count:
                description:
                - "Flooded packet count"
            total_pkts_rx:
                description:
                - "Total packets out"
            vtep_host_learn_error:
                description:
                - "Host learn error"
            requeue_pkts_in:
                description:
                - "Requeued packets in"
            lif_un_init_rx:
                description:
                - "Lif uninitialized packets in"
            mcast_pkt_rx:
                description:
                - "Total multicast packets in"
            bcast_pkt_tx:
                description:
                - "Broadcast packets out"
            bcast_pkt_rx:
                description:
                - "Total broadcast packets in"
            unicast_pkt_tx:
                description:
                - "Unicast packets out"
            bad_inner_ipv4_len_rx:
                description:
                - "bad inner ipv4 packet len"
            arp_req_sent:
                description:
                - "Arp request sent"
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'cfg_err_count'= Config errors; 'flooded_pkt_count'= Flooded packet count; 'encap_unresolved_count'= Encap unresolved failures; 'unknown_encap_rx_pkt'= Encap miss rx pkts; 'unknown_encap_tx_pkt'= Encap miss tx pkts; 'arp_req_sent'= Arp request sent; 'vtep_host_learned'= Hosts learned; 'vtep_host_learn_error'= Host learn error; 'invalid_lif_rx'= Invalid Lif pkts in; 'invalid_lif_tx'= Invalid Lif pkts out; 'unknown_vtep_tx'= Vtep unknown tx; 'unknown_vtep_rx'= Vtep Unkown rx; 'unhandled_pkt_rx'= Unhandled packets in; 'unhandled_pkt_tx'= Unhandled packets out; 'total_pkts_rx'= Total packets out; 'total_bytes_rx'= Total packet bytes in; 'unicast_pkt_rx'= Total unicast packets in; 'bcast_pkt_rx'= Total broadcast packets in; 'mcast_pkt_rx'= Total multicast packets in; 'dropped_pkt_rx'= Dropped received packets; 'encap_miss_pkts_rx'= Encap missed in received packets; 'bad_chksum_pks_rx'= Bad checksum in received packets; 'requeue_pkts_in'= Requeued packets in; 'pkts_out'= Packets out; 'total_bytes_tx'= Packet bytes out; 'unicast_pkt_tx'= Unicast packets out; 'bcast_pkt_tx'= Broadcast packets out; 'mcast_pkt_tx'= Multicast packets out; 'dropped_pkts_tx'= Dropped packets out; 'large_pkts_rx'= Too large packets in; 'dot1q_pkts_rx'= Dot1q packets in; 'frag_pkts_tx'= Frag packets out; 'reassembled_pkts_rx'= Reassembled packets in; 'bad_inner_ipv4_len_rx'= bad inner ipv4 packet len; 'bad_inner_ipv6_len_rx'= Bad inner ipv6 packet len; 'lif_un_init_rx'= Lif uninitialized packets in; "
    source_ip_address:
        description:
        - "Field source_ip_address"
        required: False
        suboptions:
            ip_address:
                description:
                - "Source Tunnel End Point IPv4 address"
            uuid:
                description:
                - "uuid of the object"
            vni_list:
                description:
                - "Field vni_list"
    encap:
        description:
        - "'nvgre'= Tunnel Encapsulation Type is NVGRE; 'vxlan'= Tunnel Encapsulation Type is VXLAN; "
        required: False
    host_list:
        description:
        - "Field host_list"
        required: False
        suboptions:
            destination_vtep:
                description:
                - "Configure the VTEP IP address (IPv4 address of the VTEP for the remote host)"
            ip_addr:
                description:
                - "IPv4 address of the overlay host"
            overlay_mac_addr:
                description:
                - "MAC Address of the overlay host"
            vni:
                description:
                - " Configure the segment id ( VNI of the remote host)"
            uuid:
                description:
                - "uuid of the object"
    id:
        description:
        - "VTEP Identifier"
        required: True
    destination_ip_address_list:
        description:
        - "Field destination_ip_address_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            ip_address:
                description:
                - "IP Address of the remote VTEP"
            vni_list:
                description:
                - "Field vni_list"
            user_tag:
                description:
                - "Customized tag"
            encap:
                description:
                - "'nvgre'= Tunnel Encapsulation Type is NVGRE; 'vxlan'= Tunnel Encapsulation Type is VXLAN; "


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["destination_ip_address_list","encap","host_list","id","sampling_enable","source_ip_address","stats","user_tag","uuid",]

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
        stats=dict(type='dict', total_bytes_rx=dict(type='str', ), dropped_pkt_rx=dict(type='str', ), pkts_out=dict(type='str', ), unhandled_pkt_rx=dict(type='str', ), unknown_encap_tx_pkt=dict(type='str', ), reassembled_pkts_rx=dict(type='str', ), id=dict(type='int', required=True, ), frag_pkts_tx=dict(type='str', ), dropped_pkts_tx=dict(type='str', ), mcast_pkt_tx=dict(type='str', ), large_pkts_rx=dict(type='str', ), invalid_lif_tx=dict(type='str', ), total_bytes_tx=dict(type='str', ), invalid_lif_rx=dict(type='str', ), unicast_pkt_rx=dict(type='str', ), dot1q_pkts_rx=dict(type='str', ), vtep_host_learned=dict(type='str', ), unhandled_pkt_tx=dict(type='str', ), unknown_vtep_rx=dict(type='str', ), encap_miss_pkts_rx=dict(type='str', ), unknown_encap_rx_pkt=dict(type='str', ), bad_chksum_pks_rx=dict(type='str', ), encap_unresolved_count=dict(type='str', ), bad_inner_ipv6_len_rx=dict(type='str', ), cfg_err_count=dict(type='str', ), unknown_vtep_tx=dict(type='str', ), flooded_pkt_count=dict(type='str', ), total_pkts_rx=dict(type='str', ), vtep_host_learn_error=dict(type='str', ), requeue_pkts_in=dict(type='str', ), lif_un_init_rx=dict(type='str', ), mcast_pkt_rx=dict(type='str', ), bcast_pkt_tx=dict(type='str', ), bcast_pkt_rx=dict(type='str', ), unicast_pkt_tx=dict(type='str', ), bad_inner_ipv4_len_rx=dict(type='str', ), arp_req_sent=dict(type='str', )),
        uuid=dict(type='str', ),
        user_tag=dict(type='str', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'cfg_err_count', 'flooded_pkt_count', 'encap_unresolved_count', 'unknown_encap_rx_pkt', 'unknown_encap_tx_pkt', 'arp_req_sent', 'vtep_host_learned', 'vtep_host_learn_error', 'invalid_lif_rx', 'invalid_lif_tx', 'unknown_vtep_tx', 'unknown_vtep_rx', 'unhandled_pkt_rx', 'unhandled_pkt_tx', 'total_pkts_rx', 'total_bytes_rx', 'unicast_pkt_rx', 'bcast_pkt_rx', 'mcast_pkt_rx', 'dropped_pkt_rx', 'encap_miss_pkts_rx', 'bad_chksum_pks_rx', 'requeue_pkts_in', 'pkts_out', 'total_bytes_tx', 'unicast_pkt_tx', 'bcast_pkt_tx', 'mcast_pkt_tx', 'dropped_pkts_tx', 'large_pkts_rx', 'dot1q_pkts_rx', 'frag_pkts_tx', 'reassembled_pkts_rx', 'bad_inner_ipv4_len_rx', 'bad_inner_ipv6_len_rx', 'lif_un_init_rx'])),
        source_ip_address=dict(type='dict', ip_address=dict(type='str', ), uuid=dict(type='str', ), vni_list=dict(type='list', lif=dict(type='int', ), partition=dict(type='str', ), segment=dict(type='int', required=True, ), gateway=dict(type='bool', ), uuid=dict(type='str', ))),
        encap=dict(type='str', choices=['nvgre', 'vxlan']),
        host_list=dict(type='list', destination_vtep=dict(type='str', required=True, ), ip_addr=dict(type='str', required=True, ), overlay_mac_addr=dict(type='str', required=True, ), vni=dict(type='int', required=True, ), uuid=dict(type='str', )),
        id=dict(type='int', required=True, ),
        destination_ip_address_list=dict(type='list', uuid=dict(type='str', ), ip_address=dict(type='str', required=True, ), vni_list=dict(type='list', segment=dict(type='int', required=True, ), uuid=dict(type='str', )), user_tag=dict(type='str', ), encap=dict(type='str', choices=['nvgre', 'vxlan']))
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/overlay-tunnel/vtep/{id}"

    f_dict = {}
    f_dict["id"] = module.params["id"]

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
    url_base = "/axapi/v3/overlay-tunnel/vtep/{id}"

    f_dict = {}
    f_dict["id"] = ""

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