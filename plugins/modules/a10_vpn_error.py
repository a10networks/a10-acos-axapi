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

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'uuid': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'bad_opcode': {
                'type': 'str',
            },
            'bad_sg_write_len': {
                'type': 'str',
            },
            'bad_len': {
                'type': 'str',
            },
            'bad_ipsec_protocol': {
                'type': 'str',
            },
            'bad_ipsec_auth': {
                'type': 'str',
            },
            'bad_ipsec_padding': {
                'type': 'str',
            },
            'bad_ip_version': {
                'type': 'str',
            },
            'bad_auth_type': {
                'type': 'str',
            },
            'bad_encrypt_type': {
                'type': 'str',
            },
            'bad_ipsec_spi': {
                'type': 'str',
            },
            'bad_checksum': {
                'type': 'str',
            },
            'bad_ipsec_context': {
                'type': 'str',
            },
            'bad_ipsec_context_direction': {
                'type': 'str',
            },
            'bad_ipsec_context_flag_mismatch': {
                'type': 'str',
            },
            'ipcomp_payload': {
                'type': 'str',
            },
            'bad_selector_match': {
                'type': 'str',
            },
            'bad_fragment_size': {
                'type': 'str',
            },
            'bad_inline_data': {
                'type': 'str',
            },
            'bad_frag_size_configuration': {
                'type': 'str',
            },
            'dummy_payload': {
                'type': 'str',
            },
            'bad_ip_payload_type': {
                'type': 'str',
            },
            'bad_min_frag_size_auth_sha384_512': {
                'type': 'str',
            },
            'bad_esp_next_header': {
                'type': 'str',
            },
            'bad_gre_header': {
                'type': 'str',
            },
            'bad_gre_protocol': {
                'type': 'str',
            },
            'ipv6_extension_headers_too_big': {
                'type': 'str',
            },
            'ipv6_hop_by_hop_error': {
                'type': 'str',
            },
            'error_ipv6_decrypt_rh_segs_left_error': {
                'type': 'str',
            },
            'ipv6_rh_length_error': {
                'type': 'str',
            },
            'ipv6_outbound_rh_copy_addr_error': {
                'type': 'str',
            },
            'error_IPv6_extension_header_bad': {
                'type': 'str',
            },
            'bad_encrypt_type_ctr_gcm': {
                'type': 'str',
            },
            'ah_not_supported_with_gcm_gmac_sha2': {
                'type': 'str',
            },
            'tfc_padding_with_prefrag_not_supported': {
                'type': 'str',
            },
            'bad_srtp_auth_tag': {
                'type': 'str',
            },
            'bad_ipcomp_configuration': {
                'type': 'str',
            },
            'dsiv_incorrect_param': {
                'type': 'str',
            },
            'bad_ipsec_unknown': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/error"

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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/error"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

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


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config):
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)


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


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
