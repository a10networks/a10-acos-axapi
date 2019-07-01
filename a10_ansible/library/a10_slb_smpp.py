#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_smpp
description:
    - Show SMPP Statistics
short_description: Configures A10 slb.smpp
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
    partition:
        description:
        - Destination/target partition for object/command
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'msg_proxy_current'= Curr SMPP Proxy; 'msg_proxy_total'= Total SMPP Proxy; 'msg_proxy_mem_allocd'= msg_proxy_mem_allocd; 'msg_proxy_mem_cached'= msg_proxy_mem_cached; 'msg_proxy_mem_freed'= msg_proxy_mem_freed; 'msg_proxy_client_recv'= Client message rcvd; 'msg_proxy_client_send_success'= Sent to server; 'msg_proxy_client_incomplete'= Incomplete; 'msg_proxy_client_drop'= AX responds directly; 'msg_proxy_client_connection'= Connecting server; 'msg_proxy_client_fail'= Number of SMPP messages received from client but failed to forward to server; 'msg_proxy_client_fail_parse'= msg_proxy_client_fail_parse; 'msg_proxy_client_fail_process'= msg_proxy_client_fail_process; 'msg_proxy_client_fail_snat'= msg_proxy_client_fail_snat; 'msg_proxy_client_exceed_tmp_buff'= msg_proxy_client_exceed_tmp_buff; 'msg_proxy_client_fail_send_pkt'= msg_proxy_client_fail_send_pkt; 'msg_proxy_client_fail_start_server_Conn'= msg_proxy_client_fail_start_server_Conn; 'msg_proxy_server_recv'= Server message rcvd; 'msg_proxy_server_send_success'= Sent to client; 'msg_proxy_server_incomplete'= Incomplete; 'msg_proxy_server_drop'= Number of the packet AX drop; 'msg_proxy_server_fail'= Number of SMPP messages received from server but failed to forward to client; 'msg_proxy_server_fail_parse'= msg_proxy_server_fail_parse; 'msg_proxy_server_fail_process'= msg_proxy_server_fail_process; 'msg_proxy_server_fail_selec_connt'= msg_proxy_server_fail_selec_connt; 'msg_proxy_server_fail_snat'= msg_proxy_server_fail_snat; 'msg_proxy_server_exceed_tmp_buff'= msg_proxy_server_exceed_tmp_buff; 'msg_proxy_server_fail_send_pkt'= msg_proxy_server_fail_send_pkt; 'msg_proxy_create_server_conn'= Server conn created; 'msg_proxy_start_server_conn'= Number of server connection created successfully; 'msg_proxy_fail_start_server_conn'= Number of server connection created failed; 'msg_proxy_server_conn_fail_snat'= msg_proxy_server_conn_fail_snat; 'msg_proxy_fail_construct_server_conn'= msg_proxy_fail_construct_server_conn; 'msg_proxy_fail_reserve_pconn'= msg_proxy_fail_reserve_pconn; 'msg_proxy_start_server_conn_failed'= msg_proxy_start_server_conn_failed; 'msg_proxy_server_conn_already_exists'= msg_proxy_server_conn_already_exists; 'msg_proxy_fail_insert_server_conn'= msg_proxy_fail_insert_server_conn; 'msg_proxy_parse_msg_fail'= msg_proxy_parse_msg_fail; 'msg_proxy_process_msg_fail'= msg_proxy_process_msg_fail; 'msg_proxy_no_vport'= msg_proxy_no_vport; 'msg_proxy_fail_select_server'= msg_proxy_fail_select_server; 'msg_proxy_fail_alloc_mem'= msg_proxy_fail_alloc_mem; 'msg_proxy_unexpected_err'= msg_proxy_unexpected_err; 'msg_proxy_l7_cpu_failed'= msg_proxy_l7_cpu_failed; 'msg_proxy_l4_to_l7'= msg_proxy_l4_to_l7; 'msg_proxy_l4_from_l7'= msg_proxy_l4_from_l7; 'msg_proxy_to_l4_send_pkt'= msg_proxy_to_l4_send_pkt; 'msg_proxy_l4_from_l4_send'= msg_proxy_l4_from_l4_send; 'msg_proxy_l7_to_L4'= msg_proxy_l7_to_L4; 'msg_proxy_mag_back'= msg_proxy_mag_back; 'msg_proxy_fail_dcmsg'= msg_proxy_fail_dcmsg; 'msg_proxy_deprecated_conn'= msg_proxy_deprecated_conn; 'msg_proxy_hold_msg'= msg_proxy_hold_msg; 'msg_proxy_split_pkt'= msg_proxy_split_pkt; 'msg_proxy_pipline_msg'= msg_proxy_pipline_msg; 'msg_proxy_client_reset'= msg_proxy_client_reset; 'msg_proxy_server_reset'= msg_proxy_server_reset; 'payload_allocd'= payload_allocd; 'payload_freed'= payload_freed; 'pkt_too_small'= pkt_too_small; 'invalid_seq'= invalid_seq; 'AX_response_directly'= Number of packet which AX responds directly; 'select_client_conn'= Client conn selection; 'select_client_by_req'= Select by request; 'select_client_from_list'= Select by roundbin; 'select_client_by_conn'= Select by conn; 'select_client_fail'= Select failed; 'select_server_conn'= Server conn selection; 'select_server_by_req'= Select by request; 'select_server_from_list'= Select by roundbin; 'select_server_by_conn'= Select server conn by client conn; 'select_server_fail'= Fail to select server conn; 'bind_conn'= bind_conn; 'unbind_conn'= unbind_conn; 'enquire_link_recv'= enquire_link_recv; 'enquire_link_resp_recv'= enquire_link_resp_recv; 'enquire_link_send'= enquire_link_send; 'enquire_link_resp_send'= enquire_link_resp_send; 'client_conn_put_in_list'= client_conn_put_in_list; 'client_conn_get_from_list'= client_conn_get_from_list; 'server_conn_put_in_list'= server_conn_put_in_list; 'server_conn_get_from_list'= server_conn_get_from_list; 'server_conn_fail_bind'= server_conn_fail_bind; 'single_msg'= single_msg; 'fail_bind_msg'= fail_bind_msg; "
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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','msg_proxy_current','msg_proxy_total','msg_proxy_mem_allocd','msg_proxy_mem_cached','msg_proxy_mem_freed','msg_proxy_client_recv','msg_proxy_client_send_success','msg_proxy_client_incomplete','msg_proxy_client_drop','msg_proxy_client_connection','msg_proxy_client_fail','msg_proxy_client_fail_parse','msg_proxy_client_fail_process','msg_proxy_client_fail_snat','msg_proxy_client_exceed_tmp_buff','msg_proxy_client_fail_send_pkt','msg_proxy_client_fail_start_server_Conn','msg_proxy_server_recv','msg_proxy_server_send_success','msg_proxy_server_incomplete','msg_proxy_server_drop','msg_proxy_server_fail','msg_proxy_server_fail_parse','msg_proxy_server_fail_process','msg_proxy_server_fail_selec_connt','msg_proxy_server_fail_snat','msg_proxy_server_exceed_tmp_buff','msg_proxy_server_fail_send_pkt','msg_proxy_create_server_conn','msg_proxy_start_server_conn','msg_proxy_fail_start_server_conn','msg_proxy_server_conn_fail_snat','msg_proxy_fail_construct_server_conn','msg_proxy_fail_reserve_pconn','msg_proxy_start_server_conn_failed','msg_proxy_server_conn_already_exists','msg_proxy_fail_insert_server_conn','msg_proxy_parse_msg_fail','msg_proxy_process_msg_fail','msg_proxy_no_vport','msg_proxy_fail_select_server','msg_proxy_fail_alloc_mem','msg_proxy_unexpected_err','msg_proxy_l7_cpu_failed','msg_proxy_l4_to_l7','msg_proxy_l4_from_l7','msg_proxy_to_l4_send_pkt','msg_proxy_l4_from_l4_send','msg_proxy_l7_to_L4','msg_proxy_mag_back','msg_proxy_fail_dcmsg','msg_proxy_deprecated_conn','msg_proxy_hold_msg','msg_proxy_split_pkt','msg_proxy_pipline_msg','msg_proxy_client_reset','msg_proxy_server_reset','payload_allocd','payload_freed','pkt_too_small','invalid_seq','AX_response_directly','select_client_conn','select_client_by_req','select_client_from_list','select_client_by_conn','select_client_fail','select_server_conn','select_server_by_req','select_server_from_list','select_server_by_conn','select_server_fail','bind_conn','unbind_conn','enquire_link_recv','enquire_link_resp_recv','enquire_link_send','enquire_link_resp_send','client_conn_put_in_list','client_conn_get_from_list','server_conn_put_in_list','server_conn_get_from_list','server_conn_fail_bind','single_msg','fail_bind_msg'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/smpp"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/smpp"

    f_dict = {}

    return url_base.format(**f_dict)

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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("smpp", module)
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

def update(module, result, existing_config):
    payload = build_json("smpp", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("smpp", module)
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
    
    partition = module.params["partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

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