#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l7_quic
description:
    - DDOS QUIC Statistics
author: A10 Networks
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
                - "'all'= all; 'quic_packet_received'= QUIC Packet Received;
          'quic_initial_received'= QUIC Initial Packet Received;
          'quic_version_negotiation_received'= QUIC Version Negotiation Received;
          'quic_retry_received'= QUIC Retry Received; 'quic_0rtt_recevied'= QUIC 0RTT
          Received; 'quic_handshake_received'= QUIC Handshake Received;
          'quic_version_match_action_taken'= QUIC Version Match Action Taken;
          'quic_version_match_action_drop'= QUIC Version Match Action Drop;
          'quic_version_match_action_blacklist'= QUIC Version Match Action Blacklist;
          'quic_malformed_action_taken'= QUIC Malformed Action Taken;
          'quic_malformed_action_drop'= QUIC Malformed Action Drop;
          'quic_malformed_action_blacklist'= QUIC Malformed Action Blacklist;
          'quic_malformed_dcid_len_max_exceed'= QUIC Malformed DCID Len Max Exceed;
          'quic_malformed_scid_len_max_exceed'= QUIC Malformed SCID Len Max Exceed;
          'quic_fixed_bit_not_set'= QUIC Fixed Bit Not Set; 'quic_retry_auth_sent'= QUIC
          Retry Auth Sent; 'quic_retry_auth_pass'= QUIC Retry Auth Pass;
          'quic_retry_auth_fail'= QUIC Retry Auth Fail; 'quic_connection_close_sent'=
          QUIC Connection Close Sent; 'quic_invalid_retry_token'= QUIC Invalid Retry
          Token; 'quic_short_header_received'= QUIC Short Header Received;
          'quic_short_headr_action_drop'= QUIC Short Header Drop; 'quic_encrypt_fail'=
          QUIC Encrypt Fail; 'quic_decrypt_fail'= QUIC Decrypt Fail;
          'quic_encrypt_success'= QUIC Encrypt Success; 'quic_decrypt_success'= QUIC
          Decrypt Success; 'quic_0rtt_drop'= QUIC 0RTT Drop; 'quic_aead_pkt_rate_exceed'=
          QUIC AEAD Packet Rate Exceed; 'quic_dcid_pkt_rate_exceed'= QUIC DCID Packet
          Rate Exceed; 'quic_create_conn_init_only'= QUIC Create Connection on Initial
          Only;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            quic_packet_received:
                description:
                - "QUIC Packet Received"
                type: str
            quic_initial_received:
                description:
                - "QUIC Initial Packet Received"
                type: str
            quic_version_negotiation_received:
                description:
                - "QUIC Version Negotiation Received"
                type: str
            quic_retry_received:
                description:
                - "QUIC Retry Received"
                type: str
            quic_0rtt_recevied:
                description:
                - "QUIC 0RTT Received"
                type: str
            quic_handshake_received:
                description:
                - "QUIC Handshake Received"
                type: str
            quic_version_match_action_taken:
                description:
                - "QUIC Version Match Action Taken"
                type: str
            quic_version_match_action_drop:
                description:
                - "QUIC Version Match Action Drop"
                type: str
            quic_version_match_action_blacklist:
                description:
                - "QUIC Version Match Action Blacklist"
                type: str
            quic_malformed_action_taken:
                description:
                - "QUIC Malformed Action Taken"
                type: str
            quic_malformed_action_drop:
                description:
                - "QUIC Malformed Action Drop"
                type: str
            quic_malformed_action_blacklist:
                description:
                - "QUIC Malformed Action Blacklist"
                type: str
            quic_malformed_dcid_len_max_exceed:
                description:
                - "QUIC Malformed DCID Len Max Exceed"
                type: str
            quic_malformed_scid_len_max_exceed:
                description:
                - "QUIC Malformed SCID Len Max Exceed"
                type: str
            quic_fixed_bit_not_set:
                description:
                - "QUIC Fixed Bit Not Set"
                type: str
            quic_retry_auth_sent:
                description:
                - "QUIC Retry Auth Sent"
                type: str
            quic_retry_auth_pass:
                description:
                - "QUIC Retry Auth Pass"
                type: str
            quic_retry_auth_fail:
                description:
                - "QUIC Retry Auth Fail"
                type: str
            quic_connection_close_sent:
                description:
                - "QUIC Connection Close Sent"
                type: str
            quic_invalid_retry_token:
                description:
                - "QUIC Invalid Retry Token"
                type: str
            quic_short_header_received:
                description:
                - "QUIC Short Header Received"
                type: str
            quic_short_headr_action_drop:
                description:
                - "QUIC Short Header Drop"
                type: str
            quic_encrypt_fail:
                description:
                - "QUIC Encrypt Fail"
                type: str
            quic_decrypt_fail:
                description:
                - "QUIC Decrypt Fail"
                type: str
            quic_encrypt_success:
                description:
                - "QUIC Encrypt Success"
                type: str
            quic_decrypt_success:
                description:
                - "QUIC Decrypt Success"
                type: str
            quic_0rtt_drop:
                description:
                - "QUIC 0RTT Drop"
                type: str
            quic_aead_pkt_rate_exceed:
                description:
                - "QUIC AEAD Packet Rate Exceed"
                type: str
            quic_dcid_pkt_rate_exceed:
                description:
                - "QUIC DCID Packet Rate Exceed"
                type: str
            quic_create_conn_init_only:
                description:
                - "QUIC Create Connection on Initial Only"
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
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
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
                    'all', 'quic_packet_received', 'quic_initial_received', 'quic_version_negotiation_received', 'quic_retry_received', 'quic_0rtt_recevied', 'quic_handshake_received', 'quic_version_match_action_taken', 'quic_version_match_action_drop', 'quic_version_match_action_blacklist', 'quic_malformed_action_taken',
                    'quic_malformed_action_drop', 'quic_malformed_action_blacklist', 'quic_malformed_dcid_len_max_exceed', 'quic_malformed_scid_len_max_exceed', 'quic_fixed_bit_not_set', 'quic_retry_auth_sent', 'quic_retry_auth_pass', 'quic_retry_auth_fail', 'quic_connection_close_sent', 'quic_invalid_retry_token', 'quic_short_header_received',
                    'quic_short_headr_action_drop', 'quic_encrypt_fail', 'quic_decrypt_fail', 'quic_encrypt_success', 'quic_decrypt_success', 'quic_0rtt_drop', 'quic_aead_pkt_rate_exceed', 'quic_dcid_pkt_rate_exceed', 'quic_create_conn_init_only'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'quic_packet_received': {
                'type': 'str',
                },
            'quic_initial_received': {
                'type': 'str',
                },
            'quic_version_negotiation_received': {
                'type': 'str',
                },
            'quic_retry_received': {
                'type': 'str',
                },
            'quic_0rtt_recevied': {
                'type': 'str',
                },
            'quic_handshake_received': {
                'type': 'str',
                },
            'quic_version_match_action_taken': {
                'type': 'str',
                },
            'quic_version_match_action_drop': {
                'type': 'str',
                },
            'quic_version_match_action_blacklist': {
                'type': 'str',
                },
            'quic_malformed_action_taken': {
                'type': 'str',
                },
            'quic_malformed_action_drop': {
                'type': 'str',
                },
            'quic_malformed_action_blacklist': {
                'type': 'str',
                },
            'quic_malformed_dcid_len_max_exceed': {
                'type': 'str',
                },
            'quic_malformed_scid_len_max_exceed': {
                'type': 'str',
                },
            'quic_fixed_bit_not_set': {
                'type': 'str',
                },
            'quic_retry_auth_sent': {
                'type': 'str',
                },
            'quic_retry_auth_pass': {
                'type': 'str',
                },
            'quic_retry_auth_fail': {
                'type': 'str',
                },
            'quic_connection_close_sent': {
                'type': 'str',
                },
            'quic_invalid_retry_token': {
                'type': 'str',
                },
            'quic_short_header_received': {
                'type': 'str',
                },
            'quic_short_headr_action_drop': {
                'type': 'str',
                },
            'quic_encrypt_fail': {
                'type': 'str',
                },
            'quic_decrypt_fail': {
                'type': 'str',
                },
            'quic_encrypt_success': {
                'type': 'str',
                },
            'quic_decrypt_success': {
                'type': 'str',
                },
            'quic_0rtt_drop': {
                'type': 'str',
                },
            'quic_aead_pkt_rate_exceed': {
                'type': 'str',
                },
            'quic_dcid_pkt_rate_exceed': {
                'type': 'str',
                },
            'quic_create_conn_init_only': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l7-quic"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l7-quic"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["l7-quic"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["l7-quic"].get(k) != v:
            change_results["changed"] = True
            config_changes["l7-quic"][k] = v

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
    payload = utils.build_json("l7-quic", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

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
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["l7-quic"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l7-quic-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l7-quic"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
