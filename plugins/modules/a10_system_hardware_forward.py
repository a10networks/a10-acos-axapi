#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_system_hardware_forward
description:
    - Field hardware_forward
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
                - "'all'= all; 'hit-counts'= Total packts hit counts; 'hit-index'= HW Fwd hit
          index; 'ipv4-forward-counts'= Total IPv4 hardware forwarded packets;
          'ipv6-forward-counts'= Total IPv6 hardware forwarded packets; 'hw-fwd-module-
          status'= hardware forwarder status flags; 'hw-fwd-prog-reqs'= hardware forward
          programming requests; 'hw-fwd-prog-errors'= hardware forward programming
          Errors; 'hw-fwd-flow-singlebit-errors'= hardware forward singlebit Errors; 'hw-
          fwd-flow-tag-mismatch'= hardware forward tag mismatch errors; 'hw-fwd-flow-seq-
          mismatch'= hardware forward sequence mismatch errors; 'hw-fwd-ageout-drop-
          count'= hardware forward ageout drop count; 'hw-fwd-invalidation-drop'=
          hardware forward invalid drop count; 'hw-fwd-flow-hit-index'= hardware forward
          flow hit index; 'hw-fwd-flow-reason-flags'= hardware forward flow reason flags;
          'hw-fwd-flow-drop-count'= hardware forward flow drop count; 'hw-fwd-flow-error-
          count'= hardware forward flow error count; 'hw-fwd-flow-unalign-count'=
          hardware forward flow unalign count; 'hw-fwd-flow-underflow-count'= hardware
          forward flow underflow count; 'hw-fwd-flow-tx-full-drop'= hardware forward flow
          tx full drop count; 'hw-fwd-flow-qdr-full-drop'= hardware forward flow qdr full
          drop count; 'hw-fwd-phyport-mismatch-drop'= hardware forward phyport mismatch
          count; 'hw-fwd-vlanid-mismatch-drop'= hardware forward vlanid mismatch count;
          'hw-fwd-vmid-drop'= hardware forward vmid mismatch count; 'hw-fwd-protocol-
          mismatch-drop'= hardware forward protocol mismatch count; 'hw-fwd-avail-
          ipv4-entry'= hardware forward available ipv4 entries count; 'hw-fwd-avail-
          ipv6-entry'= hardware forward available ipv6 entries count; 'hw-fwd-entry-
          create'= Hardware Entries Created; 'hw-fwd-entry-create-failure'= Hardware
          Entries Created; 'hw-fwd-entry-create-fail-server-down'= Hardware Entries
          Created; 'hw-fwd-entry-create-fail-max-entry'= Hardware Entries Created; 'hw-
          fwd-entry-free'= Hardware Entries Freed; 'hw-fwd-entry-free-opp-entry'=
          Hardware Entries Free due to opposite tuple entry ageout event; 'hw-fwd-entry-
          free-no-hw-prog'= Hardware Entry Free no hw prog; 'hw-fwd-entry-free-no-conn'=
          Hardware Entry Free no matched conn; 'hw-fwd-entry-free-no-sw-entry'= Hardware
          Entry Free no software entry; 'hw-fwd-entry-counter'= Hardware Entry Count;
          'hw-fwd-entry-age-out'= Hardware Entries Aged Out; 'hw-fwd-entry-age-out-idle'=
          Hardware Entries Aged Out Idle; 'hw-fwd-entry-age-out-tcp-fin'= Hardware
          Entries Aged Out TCP FIN; 'hw-fwd-entry-age-out-tcp-rst'= Hardware Entries Aged
          Out TCP RST; 'hw-fwd-entry-age-out-invalid-dst'= Hardware Entries Aged Out
          invalid dst; 'hw-fwd-entry-force-hw-invalidate'= Hardware Entries Force HW
          Invalidate; 'hw-fwd-entry-invalidate-server-down'= Hardware Entries Invalidate
          due to server down; 'hw-fwd-tcam-create'= TCAM Entries Created; 'hw-fwd-tcam-
          free'= TCAM Entries Freed; 'hw-fwd-tcam-counter'= TCAM Entry Count;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hit_counts:
                description:
                - "Total packts hit counts"
                type: str
            hit_index:
                description:
                - "HW Fwd hit index"
                type: str
            ipv4_forward_counts:
                description:
                - "Total IPv4 hardware forwarded packets"
                type: str
            ipv6_forward_counts:
                description:
                - "Total IPv6 hardware forwarded packets"
                type: str
            hw_fwd_module_status:
                description:
                - "hardware forwarder status flags"
                type: str
            hw_fwd_prog_reqs:
                description:
                - "hardware forward programming requests"
                type: str
            hw_fwd_prog_errors:
                description:
                - "hardware forward programming Errors"
                type: str
            hw_fwd_flow_singlebit_errors:
                description:
                - "hardware forward singlebit Errors"
                type: str
            hw_fwd_flow_tag_mismatch:
                description:
                - "hardware forward tag mismatch errors"
                type: str
            hw_fwd_flow_seq_mismatch:
                description:
                - "hardware forward sequence mismatch errors"
                type: str
            hw_fwd_ageout_drop_count:
                description:
                - "hardware forward ageout drop count"
                type: str
            hw_fwd_invalidation_drop:
                description:
                - "hardware forward invalid drop count"
                type: str
            hw_fwd_flow_hit_index:
                description:
                - "hardware forward flow hit index"
                type: str
            hw_fwd_flow_reason_flags:
                description:
                - "hardware forward flow reason flags"
                type: str
            hw_fwd_flow_drop_count:
                description:
                - "hardware forward flow drop count"
                type: str
            hw_fwd_flow_error_count:
                description:
                - "hardware forward flow error count"
                type: str
            hw_fwd_flow_unalign_count:
                description:
                - "hardware forward flow unalign count"
                type: str
            hw_fwd_flow_underflow_count:
                description:
                - "hardware forward flow underflow count"
                type: str
            hw_fwd_flow_tx_full_drop:
                description:
                - "hardware forward flow tx full drop count"
                type: str
            hw_fwd_flow_qdr_full_drop:
                description:
                - "hardware forward flow qdr full drop count"
                type: str
            hw_fwd_phyport_mismatch_drop:
                description:
                - "hardware forward phyport mismatch count"
                type: str
            hw_fwd_vlanid_mismatch_drop:
                description:
                - "hardware forward vlanid mismatch count"
                type: str
            hw_fwd_vmid_drop:
                description:
                - "hardware forward vmid mismatch count"
                type: str
            hw_fwd_protocol_mismatch_drop:
                description:
                - "hardware forward protocol mismatch count"
                type: str
            hw_fwd_avail_ipv4_entry:
                description:
                - "hardware forward available ipv4 entries count"
                type: str
            hw_fwd_avail_ipv6_entry:
                description:
                - "hardware forward available ipv6 entries count"
                type: str
            hw_fwd_entry_create:
                description:
                - "Hardware Entries Created"
                type: str
            hw_fwd_entry_create_failure:
                description:
                - "Hardware Entries Created"
                type: str
            hw_fwd_entry_create_fail_server_down:
                description:
                - "Hardware Entries Created"
                type: str
            hw_fwd_entry_create_fail_max_entry:
                description:
                - "Hardware Entries Created"
                type: str
            hw_fwd_entry_free:
                description:
                - "Hardware Entries Freed"
                type: str
            hw_fwd_entry_free_opp_entry:
                description:
                - "Hardware Entries Free due to opposite tuple entry ageout event"
                type: str
            hw_fwd_entry_free_no_hw_prog:
                description:
                - "Hardware Entry Free no hw prog"
                type: str
            hw_fwd_entry_free_no_conn:
                description:
                - "Hardware Entry Free no matched conn"
                type: str
            hw_fwd_entry_free_no_sw_entry:
                description:
                - "Hardware Entry Free no software entry"
                type: str
            hw_fwd_entry_counter:
                description:
                - "Hardware Entry Count"
                type: str
            hw_fwd_entry_age_out:
                description:
                - "Hardware Entries Aged Out"
                type: str
            hw_fwd_entry_age_out_idle:
                description:
                - "Hardware Entries Aged Out Idle"
                type: str
            hw_fwd_entry_age_out_tcp_fin:
                description:
                - "Hardware Entries Aged Out TCP FIN"
                type: str
            hw_fwd_entry_age_out_tcp_rst:
                description:
                - "Hardware Entries Aged Out TCP RST"
                type: str
            hw_fwd_entry_age_out_invalid_dst:
                description:
                - "Hardware Entries Aged Out invalid dst"
                type: str
            hw_fwd_entry_force_hw_invalidate:
                description:
                - "Hardware Entries Force HW Invalidate"
                type: str
            hw_fwd_entry_invalidate_server_down:
                description:
                - "Hardware Entries Invalidate due to server down"
                type: str
            hw_fwd_tcam_create:
                description:
                - "TCAM Entries Created"
                type: str
            hw_fwd_tcam_free:
                description:
                - "TCAM Entries Freed"
                type: str
            hw_fwd_tcam_counter:
                description:
                - "TCAM Entry Count"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hit-counts', 'hit-index', 'ipv4-forward-counts', 'ipv6-forward-counts', 'hw-fwd-module-status', 'hw-fwd-prog-reqs', 'hw-fwd-prog-errors', 'hw-fwd-flow-singlebit-errors', 'hw-fwd-flow-tag-mismatch', 'hw-fwd-flow-seq-mismatch', 'hw-fwd-ageout-drop-count', 'hw-fwd-invalidation-drop', 'hw-fwd-flow-hit-index', 'hw-fwd-flow-reason-flags', 'hw-fwd-flow-drop-count', 'hw-fwd-flow-error-count', 'hw-fwd-flow-unalign-count', 'hw-fwd-flow-underflow-count', 'hw-fwd-flow-tx-full-drop', 'hw-fwd-flow-qdr-full-drop', 'hw-fwd-phyport-mismatch-drop', 'hw-fwd-vlanid-mismatch-drop', 'hw-fwd-vmid-drop', 'hw-fwd-protocol-mismatch-drop', 'hw-fwd-avail-ipv4-entry', 'hw-fwd-avail-ipv6-entry', 'hw-fwd-entry-create', 'hw-fwd-entry-create-failure', 'hw-fwd-entry-create-fail-server-down', 'hw-fwd-entry-create-fail-max-entry', 'hw-fwd-entry-free', 'hw-fwd-entry-free-opp-entry', 'hw-fwd-entry-free-no-hw-prog', 'hw-fwd-entry-free-no-conn', 'hw-fwd-entry-free-no-sw-entry', 'hw-fwd-entry-counter', 'hw-fwd-entry-age-out', 'hw-fwd-entry-age-out-idle', 'hw-fwd-entry-age-out-tcp-fin', 'hw-fwd-entry-age-out-tcp-rst', 'hw-fwd-entry-age-out-invalid-dst', 'hw-fwd-entry-force-hw-invalidate', 'hw-fwd-entry-invalidate-server-down', 'hw-fwd-tcam-create', 'hw-fwd-tcam-free', 'hw-fwd-tcam-counter']}},
        'stats': {'type': 'dict', 'hit_counts': {'type': 'str', }, 'hit_index': {'type': 'str', }, 'ipv4_forward_counts': {'type': 'str', }, 'ipv6_forward_counts': {'type': 'str', }, 'hw_fwd_module_status': {'type': 'str', }, 'hw_fwd_prog_reqs': {'type': 'str', }, 'hw_fwd_prog_errors': {'type': 'str', }, 'hw_fwd_flow_singlebit_errors': {'type': 'str', }, 'hw_fwd_flow_tag_mismatch': {'type': 'str', }, 'hw_fwd_flow_seq_mismatch': {'type': 'str', }, 'hw_fwd_ageout_drop_count': {'type': 'str', }, 'hw_fwd_invalidation_drop': {'type': 'str', }, 'hw_fwd_flow_hit_index': {'type': 'str', }, 'hw_fwd_flow_reason_flags': {'type': 'str', }, 'hw_fwd_flow_drop_count': {'type': 'str', }, 'hw_fwd_flow_error_count': {'type': 'str', }, 'hw_fwd_flow_unalign_count': {'type': 'str', }, 'hw_fwd_flow_underflow_count': {'type': 'str', }, 'hw_fwd_flow_tx_full_drop': {'type': 'str', }, 'hw_fwd_flow_qdr_full_drop': {'type': 'str', }, 'hw_fwd_phyport_mismatch_drop': {'type': 'str', }, 'hw_fwd_vlanid_mismatch_drop': {'type': 'str', }, 'hw_fwd_vmid_drop': {'type': 'str', }, 'hw_fwd_protocol_mismatch_drop': {'type': 'str', }, 'hw_fwd_avail_ipv4_entry': {'type': 'str', }, 'hw_fwd_avail_ipv6_entry': {'type': 'str', }, 'hw_fwd_entry_create': {'type': 'str', }, 'hw_fwd_entry_create_failure': {'type': 'str', }, 'hw_fwd_entry_create_fail_server_down': {'type': 'str', }, 'hw_fwd_entry_create_fail_max_entry': {'type': 'str', }, 'hw_fwd_entry_free': {'type': 'str', }, 'hw_fwd_entry_free_opp_entry': {'type': 'str', }, 'hw_fwd_entry_free_no_hw_prog': {'type': 'str', }, 'hw_fwd_entry_free_no_conn': {'type': 'str', }, 'hw_fwd_entry_free_no_sw_entry': {'type': 'str', }, 'hw_fwd_entry_counter': {'type': 'str', }, 'hw_fwd_entry_age_out': {'type': 'str', }, 'hw_fwd_entry_age_out_idle': {'type': 'str', }, 'hw_fwd_entry_age_out_tcp_fin': {'type': 'str', }, 'hw_fwd_entry_age_out_tcp_rst': {'type': 'str', }, 'hw_fwd_entry_age_out_invalid_dst': {'type': 'str', }, 'hw_fwd_entry_force_hw_invalidate': {'type': 'str', }, 'hw_fwd_entry_invalidate_server_down': {'type': 'str', }, 'hw_fwd_tcam_create': {'type': 'str', }, 'hw_fwd_tcam_free': {'type': 'str', }, 'hw_fwd_tcam_counter': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/hardware-forward"

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
    url_base = "/axapi/v3/system/hardware-forward"

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
    for k, v in payload["hardware-forward"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["hardware-forward"].get(k) != v:
            change_results["changed"] = True
            config_changes["hardware-forward"][k] = v

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
    payload = build_json("hardware-forward", module)
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
