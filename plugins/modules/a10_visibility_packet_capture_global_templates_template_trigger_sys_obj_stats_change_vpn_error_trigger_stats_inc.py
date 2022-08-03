#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_vpn_error_trigger_stats_inc
description:
    - Configure stats to trigger packet capture on increment
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
    bad_opcode:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_sg_write_len:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_len:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_protocol:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_auth:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_padding:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ip_version:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_auth_type:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_encrypt_type:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_spi:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_checksum:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_context:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_context_direction:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_context_flag_mismatch:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ipcomp_payload:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_selector_match:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_fragment_size:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_inline_data:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_frag_size_configuration:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    dummy_payload:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ip_payload_type:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_min_frag_size_auth_sha384_512:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_esp_next_header:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_gre_header:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_gre_protocol:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ipv6_extension_headers_too_big:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ipv6_hop_by_hop_error:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    error_ipv6_decrypt_rh_segs_left_error:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ipv6_rh_length_error:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ipv6_outbound_rh_copy_addr_error:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    error_IPv6_extension_header_bad:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_encrypt_type_ctr_gcm:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    ah_not_supported_with_gcm_gmac_sha2:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    tfc_padding_with_prefrag_not_supported:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_srtp_auth_tag:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipcomp_configuration:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    dsiv_incorrect_param:
        description:
        - "Enable automatic packet-capture for some help string"
        type: bool
        required: False
    bad_ipsec_unknown:
        description:
        - "Enable automatic packet-capture for some help string"
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
AVAILABLE_PROPERTIES = [
    "ah_not_supported_with_gcm_gmac_sha2",
    "bad_auth_type",
    "bad_checksum",
    "bad_encrypt_type",
    "bad_encrypt_type_ctr_gcm",
    "bad_esp_next_header",
    "bad_frag_size_configuration",
    "bad_fragment_size",
    "bad_gre_header",
    "bad_gre_protocol",
    "bad_inline_data",
    "bad_ip_payload_type",
    "bad_ip_version",
    "bad_ipcomp_configuration",
    "bad_ipsec_auth",
    "bad_ipsec_context",
    "bad_ipsec_context_direction",
    "bad_ipsec_context_flag_mismatch",
    "bad_ipsec_padding",
    "bad_ipsec_protocol",
    "bad_ipsec_spi",
    "bad_ipsec_unknown",
    "bad_len",
    "bad_min_frag_size_auth_sha384_512",
    "bad_opcode",
    "bad_selector_match",
    "bad_sg_write_len",
    "bad_srtp_auth_tag",
    "dsiv_incorrect_param",
    "dummy_payload",
    "error_ipv6_decrypt_rh_segs_left_error",
    "error_IPv6_extension_header_bad",
    "ipcomp_payload",
    "ipv6_extension_headers_too_big",
    "ipv6_hop_by_hop_error",
    "ipv6_outbound_rh_copy_addr_error",
    "ipv6_rh_length_error",
    "tfc_padding_with_prefrag_not_supported",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'bad_opcode': {
            'type': 'bool',
        },
        'bad_sg_write_len': {
            'type': 'bool',
        },
        'bad_len': {
            'type': 'bool',
        },
        'bad_ipsec_protocol': {
            'type': 'bool',
        },
        'bad_ipsec_auth': {
            'type': 'bool',
        },
        'bad_ipsec_padding': {
            'type': 'bool',
        },
        'bad_ip_version': {
            'type': 'bool',
        },
        'bad_auth_type': {
            'type': 'bool',
        },
        'bad_encrypt_type': {
            'type': 'bool',
        },
        'bad_ipsec_spi': {
            'type': 'bool',
        },
        'bad_checksum': {
            'type': 'bool',
        },
        'bad_ipsec_context': {
            'type': 'bool',
        },
        'bad_ipsec_context_direction': {
            'type': 'bool',
        },
        'bad_ipsec_context_flag_mismatch': {
            'type': 'bool',
        },
        'ipcomp_payload': {
            'type': 'bool',
        },
        'bad_selector_match': {
            'type': 'bool',
        },
        'bad_fragment_size': {
            'type': 'bool',
        },
        'bad_inline_data': {
            'type': 'bool',
        },
        'bad_frag_size_configuration': {
            'type': 'bool',
        },
        'dummy_payload': {
            'type': 'bool',
        },
        'bad_ip_payload_type': {
            'type': 'bool',
        },
        'bad_min_frag_size_auth_sha384_512': {
            'type': 'bool',
        },
        'bad_esp_next_header': {
            'type': 'bool',
        },
        'bad_gre_header': {
            'type': 'bool',
        },
        'bad_gre_protocol': {
            'type': 'bool',
        },
        'ipv6_extension_headers_too_big': {
            'type': 'bool',
        },
        'ipv6_hop_by_hop_error': {
            'type': 'bool',
        },
        'error_ipv6_decrypt_rh_segs_left_error': {
            'type': 'bool',
        },
        'ipv6_rh_length_error': {
            'type': 'bool',
        },
        'ipv6_outbound_rh_copy_addr_error': {
            'type': 'bool',
        },
        'error_IPv6_extension_header_bad': {
            'type': 'bool',
        },
        'bad_encrypt_type_ctr_gcm': {
            'type': 'bool',
        },
        'ah_not_supported_with_gcm_gmac_sha2': {
            'type': 'bool',
        },
        'tfc_padding_with_prefrag_not_supported': {
            'type': 'bool',
        },
        'bad_srtp_auth_tag': {
            'type': 'bool',
        },
        'bad_ipcomp_configuration': {
            'type': 'bool',
        },
        'dsiv_incorrect_param': {
            'type': 'bool',
        },
        'bad_ipsec_unknown': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/vpn-error/trigger-stats-inc"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/vpn-error/trigger-stats-inc"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-inc"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-inc"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-inc"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("trigger-stats-inc", module.params,
                               AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
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
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "trigger-stats-inc"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "trigger-stats-inc-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
