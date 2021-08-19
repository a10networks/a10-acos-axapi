#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_vpn_error
description:
    - Error counters
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            bad_opcode:
                description:
                - "Field bad_opcode"
                type: str
            bad_sg_write_len:
                description:
                - "Field bad_sg_write_len"
                type: str
            bad_len:
                description:
                - "Field bad_len"
                type: str
            bad_ipsec_protocol:
                description:
                - "Field bad_ipsec_protocol"
                type: str
            bad_ipsec_auth:
                description:
                - "Field bad_ipsec_auth"
                type: str
            bad_ipsec_padding:
                description:
                - "Field bad_ipsec_padding"
                type: str
            bad_ip_version:
                description:
                - "Field bad_ip_version"
                type: str
            bad_auth_type:
                description:
                - "Field bad_auth_type"
                type: str
            bad_encrypt_type:
                description:
                - "Field bad_encrypt_type"
                type: str
            bad_ipsec_spi:
                description:
                - "Field bad_ipsec_spi"
                type: str
            bad_checksum:
                description:
                - "Field bad_checksum"
                type: str
            bad_ipsec_context:
                description:
                - "Field bad_ipsec_context"
                type: str
            bad_ipsec_context_direction:
                description:
                - "Field bad_ipsec_context_direction"
                type: str
            bad_ipsec_context_flag_mismatch:
                description:
                - "Field bad_ipsec_context_flag_mismatch"
                type: str
            ipcomp_payload:
                description:
                - "Field ipcomp_payload"
                type: str
            bad_selector_match:
                description:
                - "Field bad_selector_match"
                type: str
            bad_fragment_size:
                description:
                - "Field bad_fragment_size"
                type: str
            bad_inline_data:
                description:
                - "Field bad_inline_data"
                type: str
            bad_frag_size_configuration:
                description:
                - "Field bad_frag_size_configuration"
                type: str
            dummy_payload:
                description:
                - "Field dummy_payload"
                type: str
            bad_ip_payload_type:
                description:
                - "Field bad_ip_payload_type"
                type: str
            bad_min_frag_size_auth_sha384_512:
                description:
                - "Field bad_min_frag_size_auth_sha384_512"
                type: str
            bad_esp_next_header:
                description:
                - "Field bad_esp_next_header"
                type: str
            bad_gre_header:
                description:
                - "Field bad_gre_header"
                type: str
            bad_gre_protocol:
                description:
                - "Field bad_gre_protocol"
                type: str
            ipv6_extension_headers_too_big:
                description:
                - "Field ipv6_extension_headers_too_big"
                type: str
            ipv6_hop_by_hop_error:
                description:
                - "Field ipv6_hop_by_hop_error"
                type: str
            error_ipv6_decrypt_rh_segs_left_error:
                description:
                - "Field error_ipv6_decrypt_rh_segs_left_error"
                type: str
            ipv6_rh_length_error:
                description:
                - "Field ipv6_rh_length_error"
                type: str
            ipv6_outbound_rh_copy_addr_error:
                description:
                - "Field ipv6_outbound_rh_copy_addr_error"
                type: str
            error_IPv6_extension_header_bad:
                description:
                - "Field error_IPv6_extension_header_bad"
                type: str
            bad_encrypt_type_ctr_gcm:
                description:
                - "Field bad_encrypt_type_ctr_gcm"
                type: str
            ah_not_supported_with_gcm_gmac_sha2:
                description:
                - "Field ah_not_supported_with_gcm_gmac_sha2"
                type: str
            tfc_padding_with_prefrag_not_supported:
                description:
                - "Field tfc_padding_with_prefrag_not_supported"
                type: str
            bad_srtp_auth_tag:
                description:
                - "Field bad_srtp_auth_tag"
                type: str
            bad_ipcomp_configuration:
                description:
                - "Field bad_ipcomp_configuration"
                type: str
            dsiv_incorrect_param:
                description:
                - "Field dsiv_incorrect_param"
                type: str
            bad_ipsec_unknown:
                description:
                - "Field bad_ipsec_unknown"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {'type': 'dict', 'bad_opcode': {'type': 'str', }, 'bad_sg_write_len': {'type': 'str', }, 'bad_len': {'type': 'str', }, 'bad_ipsec_protocol': {'type': 'str', }, 'bad_ipsec_auth': {'type': 'str', }, 'bad_ipsec_padding': {'type': 'str', }, 'bad_ip_version': {'type': 'str', }, 'bad_auth_type': {'type': 'str', }, 'bad_encrypt_type': {'type': 'str', }, 'bad_ipsec_spi': {'type': 'str', }, 'bad_checksum': {'type': 'str', }, 'bad_ipsec_context': {'type': 'str', }, 'bad_ipsec_context_direction': {'type': 'str', }, 'bad_ipsec_context_flag_mismatch': {'type': 'str', }, 'ipcomp_payload': {'type': 'str', }, 'bad_selector_match': {'type': 'str', }, 'bad_fragment_size': {'type': 'str', }, 'bad_inline_data': {'type': 'str', }, 'bad_frag_size_configuration': {'type': 'str', }, 'dummy_payload': {'type': 'str', }, 'bad_ip_payload_type': {'type': 'str', }, 'bad_min_frag_size_auth_sha384_512': {'type': 'str', }, 'bad_esp_next_header': {'type': 'str', }, 'bad_gre_header': {'type': 'str', }, 'bad_gre_protocol': {'type': 'str', }, 'ipv6_extension_headers_too_big': {'type': 'str', }, 'ipv6_hop_by_hop_error': {'type': 'str', }, 'error_ipv6_decrypt_rh_segs_left_error': {'type': 'str', }, 'ipv6_rh_length_error': {'type': 'str', }, 'ipv6_outbound_rh_copy_addr_error': {'type': 'str', }, 'error_IPv6_extension_header_bad': {'type': 'str', }, 'bad_encrypt_type_ctr_gcm': {'type': 'str', }, 'ah_not_supported_with_gcm_gmac_sha2': {'type': 'str', }, 'tfc_padding_with_prefrag_not_supported': {'type': 'str', }, 'bad_srtp_auth_tag': {'type': 'str', }, 'bad_ipcomp_configuration': {'type': 'str', }, 'dsiv_incorrect_param': {'type': 'str', }, 'bad_ipsec_unknown': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/error"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/error"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("error", module.params, AVAILABLE_PROPERTIES)
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
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
