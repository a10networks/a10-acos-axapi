#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_system_fpga_drop_trigger_stats_rate
description:
    - Configure stats to trigger packet capture on increment rate
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    threshold_exceeded_by:
        description:
        - "Set the threshold to the number of times greater than the previous duration to
          start the capture, default is 5"
        type: int
        required: False
    duration:
        description:
        - "Time in seconds to look for the anomaly, default is 60"
        type: int
        required: False
    land_drop:
        description:
        - "Enable automatic packet-capture for Total LAND Attack Drop"
        type: bool
        required: False
    empty_frag_drop:
        description:
        - "Enable automatic packet-capture for Total Empty frag Drop"
        type: bool
        required: False
    mic_frag_drop:
        description:
        - "Enable automatic packet-capture for Total Micro frag Drop"
        type: bool
        required: False
    ipv4_opt_drop:
        description:
        - "Enable automatic packet-capture for Total IPv4 opt Drop"
        type: bool
        required: False
    ipv4_frag:
        description:
        - "Enable automatic packet-capture for Total IP frag Drop"
        type: bool
        required: False
    bad_ip_hdr_len:
        description:
        - "Enable automatic packet-capture for Total Bad IP hdr len Drop"
        type: bool
        required: False
    bad_ip_flags_drop:
        description:
        - "Enable automatic packet-capture for Total Bad IP Flags Drop"
        type: bool
        required: False
    bad_ip_ttl_drop:
        description:
        - "Enable automatic packet-capture for Total Bad IP TTL Drop"
        type: bool
        required: False
    no_ip_payload_drop:
        description:
        - "Enable automatic packet-capture for Total No IP Payload Drop"
        type: bool
        required: False
    oversize_ip_payload:
        description:
        - "Enable automatic packet-capture for Total Oversize IP PL Drop"
        type: bool
        required: False
    bad_ip_payload_len:
        description:
        - "Enable automatic packet-capture for Total Bad IP PL len Drop"
        type: bool
        required: False
    bad_ip_frag_offset:
        description:
        - "Enable automatic packet-capture for Total Bad IP frag off Drop"
        type: bool
        required: False
    bad_ip_chksum_drop:
        description:
        - "Enable automatic packet-capture for Total Bad IP csum Drop"
        type: bool
        required: False
    icmp_pod_drop:
        description:
        - "Enable automatic packet-capture for Total ICMP POD Drop"
        type: bool
        required: False
    tcp_bad_urg_offet:
        description:
        - "Enable automatic packet-capture for Total TCP bad urg off Drop"
        type: bool
        required: False
    tcp_short_hdr:
        description:
        - "Enable automatic packet-capture for Total TCP short hdr Drop"
        type: bool
        required: False
    tcp_bad_ip_len:
        description:
        - "Enable automatic packet-capture for Total TCP Bad IP Len Drop"
        type: bool
        required: False
    tcp_null_flags:
        description:
        - "Enable automatic packet-capture for Total TCP null flags Drop"
        type: bool
        required: False
    tcp_null_scan:
        description:
        - "Enable automatic packet-capture for Total TCP null scan Drop"
        type: bool
        required: False
    tcp_fin_sin:
        description:
        - "Enable automatic packet-capture for Total TCP SYN&FIN Drop"
        type: bool
        required: False
    tcp_xmas_flags:
        description:
        - "Enable automatic packet-capture for Total TCP XMAS FLAGS Drop"
        type: bool
        required: False
    tcp_xmas_scan:
        description:
        - "Enable automatic packet-capture for Total TCP XMAS scan Drop"
        type: bool
        required: False
    tcp_syn_frag:
        description:
        - "Enable automatic packet-capture for Total TCP SYN frag Drop"
        type: bool
        required: False
    tcp_frag_hdr:
        description:
        - "Enable automatic packet-capture for Total TCP frag header Drop"
        type: bool
        required: False
    tcp_bad_chksum:
        description:
        - "Enable automatic packet-capture for Total TCP bad csum Drop"
        type: bool
        required: False
    udp_short_hdr:
        description:
        - "Enable automatic packet-capture for Total UDP short hdr Drop"
        type: bool
        required: False
    udp_bad_ip_len:
        description:
        - "Enable automatic packet-capture for Total UDP bad leng Drop"
        type: bool
        required: False
    udp_kb_frags:
        description:
        - "Enable automatic packet-capture for Total UDP KB frag Drop"
        type: bool
        required: False
    udp_port_lb:
        description:
        - "Enable automatic packet-capture for Total UDP port LB Drop"
        type: bool
        required: False
    udp_bad_chksum:
        description:
        - "Enable automatic packet-capture for Total UDP bad csum Drop"
        type: bool
        required: False
    runt_ip_hdr:
        description:
        - "Enable automatic packet-capture for Total Runt IP hdr Drop"
        type: bool
        required: False
    runt_tcpudp_hdr:
        description:
        - "Enable automatic packet-capture for Total Runt TCPUDP hdr Drop"
        type: bool
        required: False
    tun_mismatch:
        description:
        - "Enable automatic packet-capture for Total Tun mismatch Drop"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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
AVAILABLE_PROPERTIES = ["bad_ip_chksum_drop", "bad_ip_flags_drop", "bad_ip_frag_offset", "bad_ip_hdr_len", "bad_ip_payload_len", "bad_ip_ttl_drop", "duration", "empty_frag_drop", "icmp_pod_drop", "ipv4_frag", "ipv4_opt_drop", "land_drop", "mic_frag_drop", "no_ip_payload_drop", "oversize_ip_payload", "runt_ip_hdr", "runt_tcpudp_hdr", "tcp_bad_chksum", "tcp_bad_ip_len", "tcp_bad_urg_offet", "tcp_fin_sin", "tcp_frag_hdr", "tcp_null_flags", "tcp_null_scan", "tcp_short_hdr", "tcp_syn_frag", "tcp_xmas_flags", "tcp_xmas_scan", "threshold_exceeded_by", "tun_mismatch", "udp_bad_chksum", "udp_bad_ip_len", "udp_kb_frags", "udp_port_lb", "udp_short_hdr", "uuid", ]


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
    rv.update({'threshold_exceeded_by': {'type': 'int', },
        'duration': {'type': 'int', },
        'land_drop': {'type': 'bool', },
        'empty_frag_drop': {'type': 'bool', },
        'mic_frag_drop': {'type': 'bool', },
        'ipv4_opt_drop': {'type': 'bool', },
        'ipv4_frag': {'type': 'bool', },
        'bad_ip_hdr_len': {'type': 'bool', },
        'bad_ip_flags_drop': {'type': 'bool', },
        'bad_ip_ttl_drop': {'type': 'bool', },
        'no_ip_payload_drop': {'type': 'bool', },
        'oversize_ip_payload': {'type': 'bool', },
        'bad_ip_payload_len': {'type': 'bool', },
        'bad_ip_frag_offset': {'type': 'bool', },
        'bad_ip_chksum_drop': {'type': 'bool', },
        'icmp_pod_drop': {'type': 'bool', },
        'tcp_bad_urg_offet': {'type': 'bool', },
        'tcp_short_hdr': {'type': 'bool', },
        'tcp_bad_ip_len': {'type': 'bool', },
        'tcp_null_flags': {'type': 'bool', },
        'tcp_null_scan': {'type': 'bool', },
        'tcp_fin_sin': {'type': 'bool', },
        'tcp_xmas_flags': {'type': 'bool', },
        'tcp_xmas_scan': {'type': 'bool', },
        'tcp_syn_frag': {'type': 'bool', },
        'tcp_frag_hdr': {'type': 'bool', },
        'tcp_bad_chksum': {'type': 'bool', },
        'udp_short_hdr': {'type': 'bool', },
        'udp_bad_ip_len': {'type': 'bool', },
        'udp_kb_frags': {'type': 'bool', },
        'udp_port_lb': {'type': 'bool', },
        'udp_bad_chksum': {'type': 'bool', },
        'runt_ip_hdr': {'type': 'bool', },
        'runt_tcpudp_hdr': {'type': 'bool', },
        'tun_mismatch': {'type': 'bool', },
        'uuid': {'type': 'str', }
    })
    # Parent keys
    rv.update(dict(
        template_name=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/system-fpga-drop/trigger-stats-rate"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/system-fpga-drop/trigger-stats-rate"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-rate"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-rate"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-rate"][k] = v

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
    payload = utils.build_json("trigger-stats-rate", module.params, AVAILABLE_PROPERTIES)
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
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
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

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["trigger-stats-rate"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["trigger-stats-rate-list"] if info != "NotFound" else info
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
