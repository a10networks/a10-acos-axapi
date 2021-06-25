#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_imap_proxy
description:
    - Configure IMAP Proxy global
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'num'= Num; 'curr'= Current proxy conns; 'total'= Total proxy
          conns; 'svrsel_fail'= Server selection failure; 'no_route'= no route failure;
          'snat_fail'= source nat failure; 'feat'= feat packet; 'cc'= clear ctrl port
          packet; 'data_ssl'= data ssl force; 'line_too_long'= line too long;
          'line_mem_freed'= request line freed; 'invalid_start_line'= invalid start line;
          'auth_tls'= auth tls cmd; 'prot'= prot cmd; 'pbsz'= pbsz cmd; 'pasv'= pasv cmd;
          'port'= port cmd; 'request_dont_care'= other cmd; 'client_auth_tls'= client
          auth tls; 'cant_find_pasv'= cant find pasv; 'pasv_addr_ne_server'= psv addr not
          equal to svr; 'smp_create_fail'= smp create fail; 'data_server_conn_fail'= data
          svr conn fail; 'data_send_fail'= data send fail; 'epsv'= epsv command;
          'cant_find_epsv'= cant find epsv; 'data_curr'= Current Data Proxy;
          'data_total'= Total Data Proxy; 'auth_unsupported'= Unsupported auth; 'adat'=
          adat cmd; 'unsupported_pbsz_value'= Unsupported PBSZ; 'unsupported_prot_value'=
          Unsupported PROT; 'unsupported_command'= Unsupported cmd; 'control_to_clear'=
          Control chn clear txt; 'control_to_ssl'= Control chn ssl; 'bad_sequence'= Bad
          Sequence; 'rsv_persist_conn_fail'= Serv Sel Persist fail; 'smp_v6_fail'= Serv
          Sel SMPv6 fail; 'smp_v4_fail'= Serv Sel SMPv4 fail; 'insert_tuple_fail'= Serv
          Sel insert tuple fail; 'cl_est_err'= Client EST state erro;
          'ser_connecting_err'= Serv CTNG state error; 'server_response_err'= Serv RESP
          state error; 'cl_request_err'= Client RQ state error; 'data_conn_start_err'=
          Data Start state error; 'data_serv_connecting_err'= Data Serv CTNG error;
          'data_serv_connected_err'= Data Serv CTED error; 'request'= Total FTP Request;
          'capability'= Capability cmd; 'start_tls'= Total Start TLS cmd; 'login'= Total
          Login cmd;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            num:
                description:
                - "Num"
                type: str
            curr:
                description:
                - "Current proxy conns"
                type: str
            total:
                description:
                - "Total proxy conns"
                type: str
            svrsel_fail:
                description:
                - "Server selection failure"
                type: str
            no_route:
                description:
                - "no route failure"
                type: str
            snat_fail:
                description:
                - "source nat failure"
                type: str
            feat:
                description:
                - "feat packet"
                type: str
            cc:
                description:
                - "clear ctrl port packet"
                type: str
            data_ssl:
                description:
                - "data ssl force"
                type: str
            line_too_long:
                description:
                - "line too long"
                type: str
            line_mem_freed:
                description:
                - "request line freed"
                type: str
            invalid_start_line:
                description:
                - "invalid start line"
                type: str
            auth_tls:
                description:
                - "auth tls cmd"
                type: str
            prot:
                description:
                - "prot cmd"
                type: str
            pbsz:
                description:
                - "pbsz cmd"
                type: str
            pasv:
                description:
                - "pasv cmd"
                type: str
            port:
                description:
                - "port cmd"
                type: str
            request_dont_care:
                description:
                - "other cmd"
                type: str
            client_auth_tls:
                description:
                - "client auth tls"
                type: str
            cant_find_pasv:
                description:
                - "cant find pasv"
                type: str
            pasv_addr_ne_server:
                description:
                - "psv addr not equal to svr"
                type: str
            smp_create_fail:
                description:
                - "smp create fail"
                type: str
            data_server_conn_fail:
                description:
                - "data svr conn fail"
                type: str
            data_send_fail:
                description:
                - "data send fail"
                type: str
            epsv:
                description:
                - "epsv command"
                type: str
            cant_find_epsv:
                description:
                - "cant find epsv"
                type: str
            data_curr:
                description:
                - "Current Data Proxy"
                type: str
            data_total:
                description:
                - "Total Data Proxy"
                type: str
            auth_unsupported:
                description:
                - "Unsupported auth"
                type: str
            adat:
                description:
                - "adat cmd"
                type: str
            unsupported_pbsz_value:
                description:
                - "Unsupported PBSZ"
                type: str
            unsupported_prot_value:
                description:
                - "Unsupported PROT"
                type: str
            unsupported_command:
                description:
                - "Unsupported cmd"
                type: str
            control_to_clear:
                description:
                - "Control chn clear txt"
                type: str
            control_to_ssl:
                description:
                - "Control chn ssl"
                type: str
            bad_sequence:
                description:
                - "Bad Sequence"
                type: str
            rsv_persist_conn_fail:
                description:
                - "Serv Sel Persist fail"
                type: str
            smp_v6_fail:
                description:
                - "Serv Sel SMPv6 fail"
                type: str
            smp_v4_fail:
                description:
                - "Serv Sel SMPv4 fail"
                type: str
            insert_tuple_fail:
                description:
                - "Serv Sel insert tuple fail"
                type: str
            cl_est_err:
                description:
                - "Client EST state erro"
                type: str
            ser_connecting_err:
                description:
                - "Serv CTNG state error"
                type: str
            server_response_err:
                description:
                - "Serv RESP state error"
                type: str
            cl_request_err:
                description:
                - "Client RQ state error"
                type: str
            data_conn_start_err:
                description:
                - "Data Start state error"
                type: str
            data_serv_connecting_err:
                description:
                - "Data Serv CTNG error"
                type: str
            data_serv_connected_err:
                description:
                - "Data Serv CTED error"
                type: str
            request:
                description:
                - "Total FTP Request"
                type: str
            capability:
                description:
                - "Capability cmd"
                type: str
            start_tls:
                description:
                - "Total Start TLS cmd"
                type: str
            login:
                description:
                - "Total Login cmd"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule
import copy

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'num', 'curr', 'total', 'svrsel_fail', 'no_route', 'snat_fail', 'feat', 'cc', 'data_ssl', 'line_too_long', 'line_mem_freed', 'invalid_start_line', 'auth_tls', 'prot', 'pbsz', 'pasv', 'port', 'request_dont_care', 'client_auth_tls', 'cant_find_pasv', 'pasv_addr_ne_server', 'smp_create_fail', 'data_server_conn_fail', 'data_send_fail', 'epsv', 'cant_find_epsv', 'data_curr', 'data_total', 'auth_unsupported', 'adat', 'unsupported_pbsz_value', 'unsupported_prot_value', 'unsupported_command', 'control_to_clear', 'control_to_ssl', 'bad_sequence', 'rsv_persist_conn_fail', 'smp_v6_fail', 'smp_v4_fail', 'insert_tuple_fail', 'cl_est_err', 'ser_connecting_err', 'server_response_err', 'cl_request_err', 'data_conn_start_err', 'data_serv_connecting_err', 'data_serv_connected_err', 'request', 'capability', 'start_tls', 'login']}},
        'oper': {'type': 'dict', 'l4_cpu_list': {'type': 'list', 'current_proxy_conns': {'type': 'int', }, 'total_proxy_conns': {'type': 'int', }, 'total_imap_request': {'type': 'int', }, 'server_selection_failure': {'type': 'int', }, 'no_route_failure': {'type': 'int', }, 'source_nat_failure': {'type': 'int', }, 'start_tls_cmd': {'type': 'int', }, 'login_packet': {'type': 'int', }, 'capability_packet': {'type': 'int', }, 'request_line_freed': {'type': 'int', }, 'inv_start_line': {'type': 'int', }, 'other_cmd': {'type': 'int', }, 'imap_line_too_long': {'type': 'int', }, 'control_chn_ssl': {'type': 'int', }, 'bad_seq': {'type': 'int', }, 'serv_sel_persist_fail': {'type': 'int', }, 'serv_sel_smpv6_fail': {'type': 'int', }, 'serv_sel_smpv4_fail': {'type': 'int', }, 'serv_sel_ins_tpl_fail': {'type': 'int', }, 'client_est_state_err': {'type': 'int', }, 'serv_ctng_state_err': {'type': 'int', }, 'serv_resp_state_err': {'type': 'int', }, 'client_rq_state_err': {'type': 'int', }}, 'cpu_count': {'type': 'int', }},
        'stats': {'type': 'dict', 'num': {'type': 'str', }, 'curr': {'type': 'str', }, 'total': {'type': 'str', }, 'svrsel_fail': {'type': 'str', }, 'no_route': {'type': 'str', }, 'snat_fail': {'type': 'str', }, 'feat': {'type': 'str', }, 'cc': {'type': 'str', }, 'data_ssl': {'type': 'str', }, 'line_too_long': {'type': 'str', }, 'line_mem_freed': {'type': 'str', }, 'invalid_start_line': {'type': 'str', }, 'auth_tls': {'type': 'str', }, 'prot': {'type': 'str', }, 'pbsz': {'type': 'str', }, 'pasv': {'type': 'str', }, 'port': {'type': 'str', }, 'request_dont_care': {'type': 'str', }, 'client_auth_tls': {'type': 'str', }, 'cant_find_pasv': {'type': 'str', }, 'pasv_addr_ne_server': {'type': 'str', }, 'smp_create_fail': {'type': 'str', }, 'data_server_conn_fail': {'type': 'str', }, 'data_send_fail': {'type': 'str', }, 'epsv': {'type': 'str', }, 'cant_find_epsv': {'type': 'str', }, 'data_curr': {'type': 'str', }, 'data_total': {'type': 'str', }, 'auth_unsupported': {'type': 'str', }, 'adat': {'type': 'str', }, 'unsupported_pbsz_value': {'type': 'str', }, 'unsupported_prot_value': {'type': 'str', }, 'unsupported_command': {'type': 'str', }, 'control_to_clear': {'type': 'str', }, 'control_to_ssl': {'type': 'str', }, 'bad_sequence': {'type': 'str', }, 'rsv_persist_conn_fail': {'type': 'str', }, 'smp_v6_fail': {'type': 'str', }, 'smp_v4_fail': {'type': 'str', }, 'insert_tuple_fail': {'type': 'str', }, 'cl_est_err': {'type': 'str', }, 'ser_connecting_err': {'type': 'str', }, 'server_response_err': {'type': 'str', }, 'cl_request_err': {'type': 'str', }, 'data_conn_start_err': {'type': 'str', }, 'data_serv_connecting_err': {'type': 'str', }, 'data_serv_connected_err': {'type': 'str', }, 'request': {'type': 'str', }, 'capability': {'type': 'str', }, 'start_tls': {'type': 'str', }, 'login': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/imap-proxy"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {"device-id": device_id},
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {"curr_part_name": a10_partition},
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)



def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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
    url_base = "/axapi/v3/slb/imap-proxy"

    f_dict = {}

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
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results


    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["imap-proxy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["imap-proxy"].get(k) != v:
            change_results["changed"] = True
            config_changes["imap-proxy"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(
                **call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(
                **call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("imap-proxy", module)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
    )

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(
            _active_partition(module, a10_partition))

    if a10_device_context_id:
         result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
