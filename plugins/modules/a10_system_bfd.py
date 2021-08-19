#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_bfd
description:
    - BFD Statistics
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
                - "'all'= all; 'ip_checksum_error'= IP packet checksum errors;
          'udp_checksum_error'= UDP packet checksum errors; 'session_not_found'= Session
          not found; 'multihop_mismatch'= Multihop session or packet mismatch;
          'version_mismatch'= BFD version mismatch; 'length_too_small'= Packets too
          small; 'data_is_short'= Packet data length too short; 'invalid_detect_mult'=
          Invalid detect multiplier; 'invalid_multipoint'= Invalid multipoint setting;
          'invalid_my_disc'= Invalid my descriptor; 'invalid_ttl'= Invalid TTL;
          'auth_length_invalid'= Invalid authentication length; 'auth_mismatch'=
          Authentication mismatch; 'auth_type_mismatch'= Authentication type mismatch;
          'auth_key_id_mismatch'= Authentication key-id mismatch; 'auth_key_mismatch'=
          Authentication key mismatch; 'auth_seqnum_invalid'= Invalid authentication
          sequence number; 'auth_failed'= Authentication failures;
          'local_state_admin_down'= Local admin down session state; 'dest_unreachable'=
          Destination unreachable; 'no_ipv6_enable'= No IPv6 enable; 'other_error'= Other
          errors;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ip_checksum_error:
                description:
                - "IP packet checksum errors"
                type: str
            udp_checksum_error:
                description:
                - "UDP packet checksum errors"
                type: str
            session_not_found:
                description:
                - "Session not found"
                type: str
            multihop_mismatch:
                description:
                - "Multihop session or packet mismatch"
                type: str
            version_mismatch:
                description:
                - "BFD version mismatch"
                type: str
            length_too_small:
                description:
                - "Packets too small"
                type: str
            data_is_short:
                description:
                - "Packet data length too short"
                type: str
            invalid_detect_mult:
                description:
                - "Invalid detect multiplier"
                type: str
            invalid_multipoint:
                description:
                - "Invalid multipoint setting"
                type: str
            invalid_my_disc:
                description:
                - "Invalid my descriptor"
                type: str
            invalid_ttl:
                description:
                - "Invalid TTL"
                type: str
            auth_length_invalid:
                description:
                - "Invalid authentication length"
                type: str
            auth_mismatch:
                description:
                - "Authentication mismatch"
                type: str
            auth_type_mismatch:
                description:
                - "Authentication type mismatch"
                type: str
            auth_key_id_mismatch:
                description:
                - "Authentication key-id mismatch"
                type: str
            auth_key_mismatch:
                description:
                - "Authentication key mismatch"
                type: str
            auth_seqnum_invalid:
                description:
                - "Invalid authentication sequence number"
                type: str
            auth_failed:
                description:
                - "Authentication failures"
                type: str
            local_state_admin_down:
                description:
                - "Local admin down session state"
                type: str
            dest_unreachable:
                description:
                - "Destination unreachable"
                type: str
            no_ipv6_enable:
                description:
                - "No IPv6 enable"
                type: str
            other_error:
                description:
                - "Other errors"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'ip_checksum_error', 'udp_checksum_error',
                    'session_not_found', 'multihop_mismatch',
                    'version_mismatch', 'length_too_small', 'data_is_short',
                    'invalid_detect_mult', 'invalid_multipoint',
                    'invalid_my_disc', 'invalid_ttl', 'auth_length_invalid',
                    'auth_mismatch', 'auth_type_mismatch',
                    'auth_key_id_mismatch', 'auth_key_mismatch',
                    'auth_seqnum_invalid', 'auth_failed',
                    'local_state_admin_down', 'dest_unreachable',
                    'no_ipv6_enable', 'other_error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'ip_checksum_error': {
                'type': 'str',
            },
            'udp_checksum_error': {
                'type': 'str',
            },
            'session_not_found': {
                'type': 'str',
            },
            'multihop_mismatch': {
                'type': 'str',
            },
            'version_mismatch': {
                'type': 'str',
            },
            'length_too_small': {
                'type': 'str',
            },
            'data_is_short': {
                'type': 'str',
            },
            'invalid_detect_mult': {
                'type': 'str',
            },
            'invalid_multipoint': {
                'type': 'str',
            },
            'invalid_my_disc': {
                'type': 'str',
            },
            'invalid_ttl': {
                'type': 'str',
            },
            'auth_length_invalid': {
                'type': 'str',
            },
            'auth_mismatch': {
                'type': 'str',
            },
            'auth_type_mismatch': {
                'type': 'str',
            },
            'auth_key_id_mismatch': {
                'type': 'str',
            },
            'auth_key_mismatch': {
                'type': 'str',
            },
            'auth_seqnum_invalid': {
                'type': 'str',
            },
            'auth_failed': {
                'type': 'str',
            },
            'local_state_admin_down': {
                'type': 'str',
            },
            'dest_unreachable': {
                'type': 'str',
            },
            'no_ipv6_enable': {
                'type': 'str',
            },
            'other_error': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/bfd"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/bfd"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["bfd"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["bfd"].get(k) != v:
            change_results["changed"] = True
            config_changes["bfd"][k] = v

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
    payload = utils.build_json("bfd", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
