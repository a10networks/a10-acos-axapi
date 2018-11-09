#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vrrp_a_state
description:
    - None
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    uuid:
        description:
        - "None"
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sync_pkt_tx_counter','sync_pkt_rcv_counter','sync_rx_create_counter','sync_rx_del_counter','sync_rx_update_age_counter','sync_tx_create_counter','sync_tx_del_counter','sync_tx_update_age_counter','sync_rx_persist_create_counter','sync_rx_persist_del_counter','sync_rx_persist_update_age_counter','sync_tx_persist_create_counter','sync_tx_persist_del_counter','sync_tx_persist_update_age_counter','query_pkt_tx_counter','query_pkt_rcv_counter','sync_tx_smp_radius_table_counter','sync_rx_smp_radius_table_counter','query_tx_max_packed','query_tx_min_packed','query_pkt_invalid_idx_counter','query_tx_get_buff_failed','query_rx_zero_info_counter','query_rx_full_info_counter','query_rx_unk_counter','sync_pkt_invalid_idx_counter','sync_tx_get_buff_failed','sync_tx_total_info_counter','sync_tx_create_ext_bit_counter','sync_tx_update_seqnos_counter','sync_tx_min_packed','sync_tx_max_packed','sync_rx_len_invalid','sync_persist_rx_len_invalid','sync_persist_rx_proto_not_supported','sync_persist_rx_type_invalid','sync_persist_rx_cannot_process_mandatory','sync_persist_rx_ext_bit_process_error','sync_persist_rx_no_such_vport','sync_persist_rx_vporttype_not_supported','sync_persist_rx_no_such_rport','sync_persist_rx_no_such_sg_group','sync_persist_rx_no_sg_group_info','sync_persist_rx_conn_get_failed','sync_rx_no_such_vport','sync_rx_no_such_rport','sync_rx_cannot_process_mandatory','sync_rx_ext_bit_process_error','sync_rx_create_ext_bit_counter','sync_rx_conn_exists','sync_rx_conn_get_failed','sync_rx_proto_not_supported','sync_rx_no_dst_for_vport_inline','sync_rx_no_such_nat_pool','sync_rx_no_such_sg_node','sync_rx_del_no_such_session','sync_rx_type_invalid','sync_rx_zero_info_counter','sync_rx_dcmsg_counter','sync_rx_total_info_counter','sync_rx_update_seqnos_counter','sync_rx_unk_counter','sync_rx_apptype_not_supported','sync_query_dcmsg_counter','sync_get_buff_failed_rt','sync_get_buff_failed_port','sync_rx_lsn_create_sby','sync_rx_nat_create_sby','sync_rx_nat_alloc_sby','sync_rx_insert_tuple','sync_rx_sfw','sync_rx_create_static_sby','sync_rx_ext_pptp','sync_rx_ext_rtsp','sync_rx_reserve_ha','sync_rx_seq_deltas','sync_rx_ftp_control','sync_rx_ext_lsn_acl','sync_rx_ext_lsn_ac_idle_timeout','sync_rx_ext_sip_alg','sync_rx_ext_h323_alg','sync_rx_ext_nat_mac','sync_tx_lsn_fullcone','sync_rx_lsn_fullcone','sync_err_lsn_fullcone','sync_tx_update_sctp_conn_addr','sync_rx_update_sctp_conn_addr','sync_rx_ext_nat_alg_tcp_info','sync_rx_ext_dcfw_rule_id','sync_rx_ext_dcfw_log','sync_rx_estab_counter','sync_tx_estab_counter','sync_rx_zone_failure_counter','sync_rx_ext_fw_http_logging','sync_rx_ext_dcfw_rule_idle_timeout','sync_rx_ext_fw_gtp_info','sync_rx_not_expect_sync_pkt','sync_rx_ext_fw_apps'])),
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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("state", module)
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

def update(module, result, existing_config):
    payload = build_json("state", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

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
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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