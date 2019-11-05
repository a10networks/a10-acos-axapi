#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vrrp_a_state
description:
    - HA VRRP-A Global Commands
short_description: Configures A10 vrrp.a.state
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
                - "'all'= all; 'sync_pkt_tx_counter'= Conn Sync Sent counter; 'sync_pkt_rcv_counter'= Conn Sync Received counter; 'sync_rx_create_counter'= Conn Sync Create Session Received counter; 'sync_rx_del_counter'= Conn Sync Del Session Received counter; 'sync_rx_update_age_counter'= Conn Sync Update Age Received counter; 'sync_tx_create_counter'= Conn Sync Create Session Sent counter; 'sync_tx_del_counter'= Conn Sync Del Session Sent counter; 'sync_tx_update_age_counter'= Conn Sync Update Age Sent counter; 'sync_rx_persist_create_counter'= Conn Sync Create Persist Session Pkts Received counter; 'sync_rx_persist_del_counter'= Conn Sync Delete Persist Session Pkts Received counter; 'sync_rx_persist_update_age_counter'= Conn Sync Update Persist Age Pkts Received counter; 'sync_tx_persist_create_counter'= Conn Sync Create Persist Session Pkts Sent counter; 'sync_tx_persist_del_counter'= Conn Sync Delete Persist Session Pkts Sent counter; 'sync_tx_persist_update_age_counter'= Conn Sync Update Persist Age Pkts Sent counter; 'query_pkt_tx_counter'= Conn Query sent counter; 'query_pkt_rcv_counter'= Conn Query Received counter; 'sync_tx_smp_radius_table_counter'= Conn Sync Update LSN RADIUS Sent counter; 'sync_rx_smp_radius_table_counter'= Conn Sync Update LSN RADIUS Received counter; 'query_tx_max_packed'= Max Query Msg Per Packet; 'query_tx_min_packed'= Min Query Msg Per Packet; 'query_pkt_invalid_idx_counter'= Conn Query Invalid Interface; 'query_tx_get_buff_failed'= Conn Query Get Buff Failure; 'query_rx_zero_info_counter'= Conn Query Packet Empty; 'query_rx_full_info_counter'= Conn Query Packet Full; 'query_rx_unk_counter'= Conn Query Unknown Type; 'sync_pkt_invalid_idx_counter'= Conn Sync Invalid Interface; 'sync_tx_get_buff_failed'= Conn Sync Get Buff Failure; 'sync_tx_total_info_counter'= Conn Sync Total Info Pkts Sent counter; 'sync_tx_create_ext_bit_counter'= Conn Sync Create with Ext Sent counter; 'sync_tx_update_seqnos_counter'= Conn Sync Update Seq Num Sent counter; 'sync_tx_min_packed'= Max Sync Msg Per Packet; 'sync_tx_max_packed'= Min Sync Msg Per Packet; 'sync_rx_len_invalid'= Conn Sync Length Invalid; 'sync_persist_rx_len_invalid'= Persist Conn Sync Length Invalid; 'sync_persist_rx_proto_not_supported'= Persist Conn Sync Protocol Invalid; 'sync_persist_rx_type_invalid'= Persist Conn Sync Type Invalid; 'sync_persist_rx_cannot_process_mandatory'= Persist Conn Sync Process Mandatory Invalid; 'sync_persist_rx_ext_bit_process_error'= Persist Conn Sync Proc Ext Bit Failure; 'sync_persist_rx_no_such_vport'= Persist Conn Sync Virt Port Not Found; 'sync_persist_rx_vporttype_not_supported'= Persist Conn Sync Virt Port Type Invalid; 'sync_persist_rx_no_such_rport'= Persist Conn Sync Real Port Not Found; 'sync_persist_rx_no_such_sg_group'= Persist Conn Sync No Service Group Found; 'sync_persist_rx_no_sg_group_info'= Persist Conn Sync No Service Group Info Found; 'sync_persist_rx_conn_get_failed'= Persist Conn Sync Get Conn Failure; 'sync_rx_no_such_vport'= Conn Sync Virt Port Not Found; 'sync_rx_no_such_rport'= Conn Sync Real Port Not Found; 'sync_rx_cannot_process_mandatory'= Conn Sync Process Mandatory Invalid; 'sync_rx_ext_bit_process_error'= Conn Sync Proc Ext Bit Failure; 'sync_rx_create_ext_bit_counter'= Conn Sync Create with Ext Received counter; 'sync_rx_conn_exists'= Conn Sync Create Conn Exists; 'sync_rx_conn_get_failed'= Conn Sync Get Conn Failure; 'sync_rx_proto_not_supported'= Conn Sync Protocol Invalid; 'sync_rx_no_dst_for_vport_inline'= Conn Sync 'dst' not found for vport inline; 'sync_rx_no_such_nat_pool'= Conn Sync NAT Pool Error; 'sync_rx_no_such_sg_node'= Conn Sync no SG node found; 'sync_rx_del_no_such_session'= Conn Sync Del Conn not Found; 'sync_rx_type_invalid'= Conn Sync Type Invalid; 'sync_rx_zero_info_counter'= Conn Sync Packet Empty; 'sync_rx_dcmsg_counter'= Conn Sync forward CPU; 'sync_rx_total_info_counter'= Conn Sync Total Info Pkts Received counter; 'sync_rx_update_seqnos_counter'= Conn Sync Update Seq Num Received counter; 'sync_rx_unk_counter'= Conn Sync Unknown Type; 'sync_rx_apptype_not_supported'= Conn Sync App Type Invalid; 'sync_query_dcmsg_counter'= Conn Sync query forward CPU; 'sync_get_buff_failed_rt'= Conn Sync Get Buff Failure No Route; 'sync_get_buff_failed_port'= Conn Sync Get Buff Failure Wrong Port; 'sync_rx_lsn_create_sby'= Conn Sync LSN Create Standby; 'sync_rx_nat_create_sby'= Conn Sync NAT Create Standby; 'sync_rx_nat_alloc_sby'= Conn Sync NAT Alloc Standby; 'sync_rx_insert_tuple'= Conn Sync Insert Tuple; 'sync_rx_sfw'= Conn Sync SFW; 'sync_rx_create_static_sby'= Conn Sync Create Static Standby; 'sync_rx_ext_pptp'= Conn Sync Ext PPTP; 'sync_rx_ext_rtsp'= Conn Sync Ext RTSP; 'sync_rx_reserve_ha'= Conn Sync Reserve HA Conn; 'sync_rx_seq_deltas'= Conn Sync Seq Deltas Failure; 'sync_rx_ftp_control'= Conn Sync FTP Control Failure; 'sync_rx_ext_lsn_acl'= Conn Sync LSN ACL Failure; 'sync_rx_ext_lsn_ac_idle_timeout'= Conn Sync LSN ACL Idle Timeout Failure; 'sync_rx_ext_sip_alg'= Conn Sync SIP TCP ALG Failure; 'sync_rx_ext_h323_alg'= Conn Sync H323 TCP ALG Failure; 'sync_rx_ext_nat_mac'= Conn Sync NAT MAC Failure; 'sync_tx_lsn_fullcone'= Conn Sync Update LSN Fullcone Sent counter; 'sync_rx_lsn_fullcone'= Conn Sync Update LSN Fullcone Received counter; 'sync_err_lsn_fullcone'= Conn Sync LSN Fullcone Failure; 'sync_tx_update_sctp_conn_addr'= Update SCTP Addresses Sent; 'sync_rx_update_sctp_conn_addr'= Update SCTP Addresses Received; 'sync_rx_ext_nat_alg_tcp_info'= Conn Sync NAT ALG TCP Information; 'sync_rx_ext_dcfw_rule_id'= Conn Sync FIREWALL session rule ID information Failure; 'sync_rx_ext_dcfw_log'= Conn Sync FIREWALL session logging information Failure; 'sync_rx_estab_counter'= Conn Sync rcv established state; 'sync_tx_estab_counter'= Conn Sync send established state; 'sync_rx_zone_failure_counter'= Conn Sync Zone Failure; 'sync_rx_ext_fw_http_logging'= FW HTTP Logging Sync Failures; 'sync_rx_ext_dcfw_rule_idle_timeout'= Conn Sync FIREWALL session rule idle timeout information Failure; 'sync_rx_ext_fw_gtp_info'= FW GTP Info Received; 'sync_rx_not_expect_sync_pkt'= unexpected session sync packets; 'sync_rx_ext_fw_apps'= Conn Sync FIREWALL application information Failure; 'sync_tx_mon_entity'= Acos Monitoring Entities Sync Messages Sent; 'sync_rx_mon_entity'= Acos monitoring Entities Sync Messages Received; 'sync_rx_ext_fw_gtp_log_info'= FW GTP Log Info Received; 'sync_rx_ddos_drop_counter'= Conn Sync receive ddos protect packet; 'sync_rx_invalid_sync_packet_counter'= Conn Sync receive invalid packet; 'sync_rx_bad_protocol_counter'= Conn Sync receive packet with bad protocol; 'sync_rx_no_vgrp_counter'= Conn Sync receive packet with non-existing group; 'sync_rx_by_inactive_peer_counter'= Conn Sync receive packet by inactive peer; "
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sync_pkt_tx_counter','sync_pkt_rcv_counter','sync_rx_create_counter','sync_rx_del_counter','sync_rx_update_age_counter','sync_tx_create_counter','sync_tx_del_counter','sync_tx_update_age_counter','sync_rx_persist_create_counter','sync_rx_persist_del_counter','sync_rx_persist_update_age_counter','sync_tx_persist_create_counter','sync_tx_persist_del_counter','sync_tx_persist_update_age_counter','query_pkt_tx_counter','query_pkt_rcv_counter','sync_tx_smp_radius_table_counter','sync_rx_smp_radius_table_counter','query_tx_max_packed','query_tx_min_packed','query_pkt_invalid_idx_counter','query_tx_get_buff_failed','query_rx_zero_info_counter','query_rx_full_info_counter','query_rx_unk_counter','sync_pkt_invalid_idx_counter','sync_tx_get_buff_failed','sync_tx_total_info_counter','sync_tx_create_ext_bit_counter','sync_tx_update_seqnos_counter','sync_tx_min_packed','sync_tx_max_packed','sync_rx_len_invalid','sync_persist_rx_len_invalid','sync_persist_rx_proto_not_supported','sync_persist_rx_type_invalid','sync_persist_rx_cannot_process_mandatory','sync_persist_rx_ext_bit_process_error','sync_persist_rx_no_such_vport','sync_persist_rx_vporttype_not_supported','sync_persist_rx_no_such_rport','sync_persist_rx_no_such_sg_group','sync_persist_rx_no_sg_group_info','sync_persist_rx_conn_get_failed','sync_rx_no_such_vport','sync_rx_no_such_rport','sync_rx_cannot_process_mandatory','sync_rx_ext_bit_process_error','sync_rx_create_ext_bit_counter','sync_rx_conn_exists','sync_rx_conn_get_failed','sync_rx_proto_not_supported','sync_rx_no_dst_for_vport_inline','sync_rx_no_such_nat_pool','sync_rx_no_such_sg_node','sync_rx_del_no_such_session','sync_rx_type_invalid','sync_rx_zero_info_counter','sync_rx_dcmsg_counter','sync_rx_total_info_counter','sync_rx_update_seqnos_counter','sync_rx_unk_counter','sync_rx_apptype_not_supported','sync_query_dcmsg_counter','sync_get_buff_failed_rt','sync_get_buff_failed_port','sync_rx_lsn_create_sby','sync_rx_nat_create_sby','sync_rx_nat_alloc_sby','sync_rx_insert_tuple','sync_rx_sfw','sync_rx_create_static_sby','sync_rx_ext_pptp','sync_rx_ext_rtsp','sync_rx_reserve_ha','sync_rx_seq_deltas','sync_rx_ftp_control','sync_rx_ext_lsn_acl','sync_rx_ext_lsn_ac_idle_timeout','sync_rx_ext_sip_alg','sync_rx_ext_h323_alg','sync_rx_ext_nat_mac','sync_tx_lsn_fullcone','sync_rx_lsn_fullcone','sync_err_lsn_fullcone','sync_tx_update_sctp_conn_addr','sync_rx_update_sctp_conn_addr','sync_rx_ext_nat_alg_tcp_info','sync_rx_ext_dcfw_rule_id','sync_rx_ext_dcfw_log','sync_rx_estab_counter','sync_tx_estab_counter','sync_rx_zone_failure_counter','sync_rx_ext_fw_http_logging','sync_rx_ext_dcfw_rule_idle_timeout','sync_rx_ext_fw_gtp_info','sync_rx_not_expect_sync_pkt','sync_rx_ext_fw_apps','sync_tx_mon_entity','sync_rx_mon_entity','sync_rx_ext_fw_gtp_log_info','sync_rx_ddos_drop_counter','sync_rx_invalid_sync_packet_counter','sync_rx_bad_protocol_counter','sync_rx_no_vgrp_counter','sync_rx_by_inactive_peer_counter'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vrrp-a/state"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vrrp-a/state"

    f_dict = {}

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
        for k, v in payload["state"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["state"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["state"][k] = v
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
    payload = build_json("state", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
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