#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_visibility_mon_entity_telemetry_data
description:
    - dummy schema for sflow exports
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
                - "'all'= all; 'in_pkts'= Monitored Entity telemetry Metric IN pkts; 'out_pkts'=
          Monitored Entity telemetry Metric OUT pkts; 'in_bytes'= Monitored Entity
          telemetry Metric IN bytes; 'out_bytes'= Monitored Entity telemetry Metric OUT
          bytes; 'errors'= Monitored Entity telemetry Metric ERRORS; 'in_small_pkt'=
          Monitored Entity telemetry Metric IN SMALL pkt; 'in_frag'= Monitored Entity
          telemetry Metric IN frag; 'out_small_pkt'= Monitored Entity telemetry Metric
          OUT SMALL pkt; 'out_frag'= Monitored Entity telemetry Metric OUT frag; 'new-
          conn'= Monitored Entity telemetry Metric New Sessions; 'concurrent-conn'= some
          help string; 'in_bytes_per_out_bytes'= Monitored Entity telemetry Metric IN
          bytes per OUT bytes; 'drop_pkts_per_pkts'= Monitored Entity telemetry Metric
          Drop pkts per pkts; 'tcp_in_syn'= Monitored Entity telemetry Metric TCP IN syn;
          'tcp_out_syn'= Monitored Entity telemetry Metric TCP OUT syn; 'tcp_in_fin'=
          Monitored Entity telemetry Metric TCP IN fin; 'tcp_out_fin'= Monitored Entity
          telemetry Metric TCP OUT fin; 'tcp_in_payload'= Monitored Entity telemetry
          Metric TCP IN payload; 'tcp_out_payload'= Monitored Entity telemetry Metric TCP
          OUT payload; 'tcp_in_rexmit'= Monitored Entity telemetry Metric TCP IN rexmit;
          'tcp_out_rexmit'= Monitored Entity telemetry Metric TCP OUT rexmit;
          'tcp_in_rst'= Monitored Entity telemetry Metric TCP IN rst; 'tcp_out_rst'=
          Monitored Entity telemetry Metric TCP OUT rst; 'tcp_in_empty_ack'= Monitored
          Entity telemetry Metric TCP_IN EMPTY ack; 'tcp_out_empty_ack'= Monitored Entity
          telemetry Metric TCP OUT EMPTY ack; 'tcp_in_zero_wnd'= Monitored Entity
          telemetry Metric TCP IN ZERO wnd; 'tcp_out_zero_wnd'= Monitored Entity
          telemetry Metric TCP OUT ZERO wnd; 'tcp_fwd_syn_per_fin'= Monitored Entity
          telemetry Metric TCP FWD SYN per FIN;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            in_pkts:
                description:
                - "Monitored Entity telemetry Metric IN pkts"
                type: str
            out_pkts:
                description:
                - "Monitored Entity telemetry Metric OUT pkts"
                type: str
            in_bytes:
                description:
                - "Monitored Entity telemetry Metric IN bytes"
                type: str
            out_bytes:
                description:
                - "Monitored Entity telemetry Metric OUT bytes"
                type: str
            errors:
                description:
                - "Monitored Entity telemetry Metric ERRORS"
                type: str
            in_small_pkt:
                description:
                - "Monitored Entity telemetry Metric IN SMALL pkt"
                type: str
            in_frag:
                description:
                - "Monitored Entity telemetry Metric IN frag"
                type: str
            out_small_pkt:
                description:
                - "Monitored Entity telemetry Metric OUT SMALL pkt"
                type: str
            out_frag:
                description:
                - "Monitored Entity telemetry Metric OUT frag"
                type: str
            new_conn:
                description:
                - "Monitored Entity telemetry Metric New Sessions"
                type: str
            concurrent_conn:
                description:
                - "some help string"
                type: str
            in_bytes_per_out_bytes:
                description:
                - "Monitored Entity telemetry Metric IN bytes per OUT bytes"
                type: str
            drop_pkts_per_pkts:
                description:
                - "Monitored Entity telemetry Metric Drop pkts per pkts"
                type: str
            tcp_in_syn:
                description:
                - "Monitored Entity telemetry Metric TCP IN syn"
                type: str
            tcp_out_syn:
                description:
                - "Monitored Entity telemetry Metric TCP OUT syn"
                type: str
            tcp_in_fin:
                description:
                - "Monitored Entity telemetry Metric TCP IN fin"
                type: str
            tcp_out_fin:
                description:
                - "Monitored Entity telemetry Metric TCP OUT fin"
                type: str
            tcp_in_payload:
                description:
                - "Monitored Entity telemetry Metric TCP IN payload"
                type: str
            tcp_out_payload:
                description:
                - "Monitored Entity telemetry Metric TCP OUT payload"
                type: str
            tcp_in_rexmit:
                description:
                - "Monitored Entity telemetry Metric TCP IN rexmit"
                type: str
            tcp_out_rexmit:
                description:
                - "Monitored Entity telemetry Metric TCP OUT rexmit"
                type: str
            tcp_in_rst:
                description:
                - "Monitored Entity telemetry Metric TCP IN rst"
                type: str
            tcp_out_rst:
                description:
                - "Monitored Entity telemetry Metric TCP OUT rst"
                type: str
            tcp_in_empty_ack:
                description:
                - "Monitored Entity telemetry Metric TCP_IN EMPTY ack"
                type: str
            tcp_out_empty_ack:
                description:
                - "Monitored Entity telemetry Metric TCP OUT EMPTY ack"
                type: str
            tcp_in_zero_wnd:
                description:
                - "Monitored Entity telemetry Metric TCP IN ZERO wnd"
                type: str
            tcp_out_zero_wnd:
                description:
                - "Monitored Entity telemetry Metric TCP OUT ZERO wnd"
                type: str
            tcp_fwd_syn_per_fin:
                description:
                - "Monitored Entity telemetry Metric TCP FWD SYN per FIN"
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

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'in_pkts', 'out_pkts', 'in_bytes', 'out_bytes', 'errors', 'in_small_pkt', 'in_frag', 'out_small_pkt', 'out_frag', 'new-conn', 'concurrent-conn', 'in_bytes_per_out_bytes', 'drop_pkts_per_pkts', 'tcp_in_syn', 'tcp_out_syn', 'tcp_in_fin', 'tcp_out_fin', 'tcp_in_payload', 'tcp_out_payload', 'tcp_in_rexmit', 'tcp_out_rexmit', 'tcp_in_rst', 'tcp_out_rst', 'tcp_in_empty_ack', 'tcp_out_empty_ack', 'tcp_in_zero_wnd', 'tcp_out_zero_wnd', 'tcp_fwd_syn_per_fin']}},
        'stats': {'type': 'dict', 'in_pkts': {'type': 'str', }, 'out_pkts': {'type': 'str', }, 'in_bytes': {'type': 'str', }, 'out_bytes': {'type': 'str', }, 'errors': {'type': 'str', }, 'in_small_pkt': {'type': 'str', }, 'in_frag': {'type': 'str', }, 'out_small_pkt': {'type': 'str', }, 'out_frag': {'type': 'str', }, 'new_conn': {'type': 'str', }, 'concurrent_conn': {'type': 'str', }, 'in_bytes_per_out_bytes': {'type': 'str', }, 'drop_pkts_per_pkts': {'type': 'str', }, 'tcp_in_syn': {'type': 'str', }, 'tcp_out_syn': {'type': 'str', }, 'tcp_in_fin': {'type': 'str', }, 'tcp_out_fin': {'type': 'str', }, 'tcp_in_payload': {'type': 'str', }, 'tcp_out_payload': {'type': 'str', }, 'tcp_in_rexmit': {'type': 'str', }, 'tcp_out_rexmit': {'type': 'str', }, 'tcp_in_rst': {'type': 'str', }, 'tcp_out_rst': {'type': 'str', }, 'tcp_in_empty_ack': {'type': 'str', }, 'tcp_out_empty_ack': {'type': 'str', }, 'tcp_in_zero_wnd': {'type': 'str', }, 'tcp_out_zero_wnd': {'type': 'str', }, 'tcp_fwd_syn_per_fin': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/mon-entity-telemetry-data"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/mon-entity-telemetry-data"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["mon-entity-telemetry-data"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["mon-entity-telemetry-data"].get(k) != v:
            change_results["changed"] = True
            config_changes["mon-entity-telemetry-data"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("mon-entity-telemetry-data", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def run_command(module):
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)


    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["mon-entity-telemetry-data"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["mon-entity-telemetry-data-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["mon-entity-telemetry-data"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

if __name__ == '__main__':
    main()
