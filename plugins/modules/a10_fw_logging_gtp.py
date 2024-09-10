#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_logging_gtp
description:
    - Counters for GTP Logging
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
                - "'all'= all; 'log_type_gtp_invalid_teid'= Log Event Type GTP Invalid TEID;
          'log_gtp_type_reserved_ie_present'= Log Event Type GTP Reserved IE Present;
          'log_type_gtp_mandatory_ie_missing'= Log Event Type GTP Mandatory IE Missing;
          'log_type_gtp_mandatory_ie_inside_grouped_ie_missing'= Log Event Type GTP
          Mandatory IE Missing Inside Grouped IE; 'log_type_gtp_msisdn_filtering'= Log
          Event Type GTP MSISDN Filtering; 'log_type_gtp_out_of_order_ie'= Log Event Type
          GTP Out of Order IE V1; 'log_type_gtp_out_of_state_ie'= Log Event Type GTP Out
          of State IE; 'log_type_enduser_ip_spoofed'= Log Event Type GTP Enduser IP
          Spoofed; 'log_type_crosslayer_correlation'= Log Event GTP Crosslayer
          Correlation; 'log_type_message_not_supported'= Log Event GTP Reserved Message
          Found; 'log_type_out_of_state'= Log Event GTP Out of State Message;
          'log_type_max_msg_length'= Log Event GTP Message Length Exceeded Max;
          'log_type_gtp_message_filtering'= Log Event Type GTP Message Filtering;
          'log_type_gtp_apn_filtering'= Log Event Type GTP Apn Filtering;
          'log_type_gtp_rat_type_filtering'= Log Event GTP RAT Type Filtering;
          'log_type_country_code_mismatch'= Log Event GTP Country Code Mismatch;
          'log_type_gtp_in_gtp_filtering'= Log Event GTP in GTP Filtering;
          'log_type_gtp_node_restart'= Log Event GTP SGW/PGW restarted;
          'log_type_gtp_seq_num_mismatch'= Log Event GTP Response Sequence number
          Mismatch; 'log_type_gtp_rate_limit_periodic'= Log Event GTP Rate Limit
          Periodic; 'log_type_gtp_invalid_message_length'= Log Event GTP Invalid message
          length across layers; 'log_type_gtp_hdr_invalid_protocol_flag'= Log Event GTP
          Protocol flag in header; 'log_type_gtp_hdr_invalid_spare_bits'= Log Event GTP
          invalid spare bits in header; 'log_type_gtp_hdr_invalid_piggy_flag'= Log Event
          GTP invalid piggyback flag in header; 'log_type_gtp_invalid_version'= Log Event
          invalid GTP version; 'log_type_gtp_invalid_ports'= Log Event mismatch of GTP
          message and ports;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            log_type_gtp_invalid_teid:
                description:
                - "Log Event Type GTP Invalid TEID"
                type: str
            log_gtp_type_reserved_ie_present:
                description:
                - "Log Event Type GTP Reserved IE Present"
                type: str
            log_type_gtp_mandatory_ie_missing:
                description:
                - "Log Event Type GTP Mandatory IE Missing"
                type: str
            log_type_gtp_mandatory_ie_inside_grouped_ie_missing:
                description:
                - "Log Event Type GTP Mandatory IE Missing Inside Grouped IE"
                type: str
            log_type_gtp_msisdn_filtering:
                description:
                - "Log Event Type GTP MSISDN Filtering"
                type: str
            log_type_gtp_out_of_order_ie:
                description:
                - "Log Event Type GTP Out of Order IE V1"
                type: str
            log_type_gtp_out_of_state_ie:
                description:
                - "Log Event Type GTP Out of State IE"
                type: str
            log_type_enduser_ip_spoofed:
                description:
                - "Log Event Type GTP Enduser IP Spoofed"
                type: str
            log_type_crosslayer_correlation:
                description:
                - "Log Event GTP Crosslayer Correlation"
                type: str
            log_type_message_not_supported:
                description:
                - "Log Event GTP Reserved Message Found"
                type: str
            log_type_out_of_state:
                description:
                - "Log Event GTP Out of State Message"
                type: str
            log_type_max_msg_length:
                description:
                - "Log Event GTP Message Length Exceeded Max"
                type: str
            log_type_gtp_message_filtering:
                description:
                - "Log Event Type GTP Message Filtering"
                type: str
            log_type_gtp_apn_filtering:
                description:
                - "Log Event Type GTP Apn Filtering"
                type: str
            log_type_gtp_rat_type_filtering:
                description:
                - "Log Event GTP RAT Type Filtering"
                type: str
            log_type_country_code_mismatch:
                description:
                - "Log Event GTP Country Code Mismatch"
                type: str
            log_type_gtp_in_gtp_filtering:
                description:
                - "Log Event GTP in GTP Filtering"
                type: str
            log_type_gtp_node_restart:
                description:
                - "Log Event GTP SGW/PGW restarted"
                type: str
            log_type_gtp_seq_num_mismatch:
                description:
                - "Log Event GTP Response Sequence number Mismatch"
                type: str
            log_type_gtp_rate_limit_periodic:
                description:
                - "Log Event GTP Rate Limit Periodic"
                type: str
            log_type_gtp_invalid_message_length:
                description:
                - "Log Event GTP Invalid message length across layers"
                type: str
            log_type_gtp_hdr_invalid_protocol_flag:
                description:
                - "Log Event GTP Protocol flag in header"
                type: str
            log_type_gtp_hdr_invalid_spare_bits:
                description:
                - "Log Event GTP invalid spare bits in header"
                type: str
            log_type_gtp_hdr_invalid_piggy_flag:
                description:
                - "Log Event GTP invalid piggyback flag in header"
                type: str
            log_type_gtp_invalid_version:
                description:
                - "Log Event invalid GTP version"
                type: str
            log_type_gtp_invalid_ports:
                description:
                - "Log Event mismatch of GTP message and ports"
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
                    'all', 'log_type_gtp_invalid_teid', 'log_gtp_type_reserved_ie_present', 'log_type_gtp_mandatory_ie_missing', 'log_type_gtp_mandatory_ie_inside_grouped_ie_missing', 'log_type_gtp_msisdn_filtering', 'log_type_gtp_out_of_order_ie', 'log_type_gtp_out_of_state_ie', 'log_type_enduser_ip_spoofed', 'log_type_crosslayer_correlation',
                    'log_type_message_not_supported', 'log_type_out_of_state', 'log_type_max_msg_length', 'log_type_gtp_message_filtering', 'log_type_gtp_apn_filtering', 'log_type_gtp_rat_type_filtering', 'log_type_country_code_mismatch', 'log_type_gtp_in_gtp_filtering', 'log_type_gtp_node_restart', 'log_type_gtp_seq_num_mismatch',
                    'log_type_gtp_rate_limit_periodic', 'log_type_gtp_invalid_message_length', 'log_type_gtp_hdr_invalid_protocol_flag', 'log_type_gtp_hdr_invalid_spare_bits', 'log_type_gtp_hdr_invalid_piggy_flag', 'log_type_gtp_invalid_version', 'log_type_gtp_invalid_ports'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'log_type_gtp_invalid_teid': {
                'type': 'str',
                },
            'log_gtp_type_reserved_ie_present': {
                'type': 'str',
                },
            'log_type_gtp_mandatory_ie_missing': {
                'type': 'str',
                },
            'log_type_gtp_mandatory_ie_inside_grouped_ie_missing': {
                'type': 'str',
                },
            'log_type_gtp_msisdn_filtering': {
                'type': 'str',
                },
            'log_type_gtp_out_of_order_ie': {
                'type': 'str',
                },
            'log_type_gtp_out_of_state_ie': {
                'type': 'str',
                },
            'log_type_enduser_ip_spoofed': {
                'type': 'str',
                },
            'log_type_crosslayer_correlation': {
                'type': 'str',
                },
            'log_type_message_not_supported': {
                'type': 'str',
                },
            'log_type_out_of_state': {
                'type': 'str',
                },
            'log_type_max_msg_length': {
                'type': 'str',
                },
            'log_type_gtp_message_filtering': {
                'type': 'str',
                },
            'log_type_gtp_apn_filtering': {
                'type': 'str',
                },
            'log_type_gtp_rat_type_filtering': {
                'type': 'str',
                },
            'log_type_country_code_mismatch': {
                'type': 'str',
                },
            'log_type_gtp_in_gtp_filtering': {
                'type': 'str',
                },
            'log_type_gtp_node_restart': {
                'type': 'str',
                },
            'log_type_gtp_seq_num_mismatch': {
                'type': 'str',
                },
            'log_type_gtp_rate_limit_periodic': {
                'type': 'str',
                },
            'log_type_gtp_invalid_message_length': {
                'type': 'str',
                },
            'log_type_gtp_hdr_invalid_protocol_flag': {
                'type': 'str',
                },
            'log_type_gtp_hdr_invalid_spare_bits': {
                'type': 'str',
                },
            'log_type_gtp_hdr_invalid_piggy_flag': {
                'type': 'str',
                },
            'log_type_gtp_invalid_version': {
                'type': 'str',
                },
            'log_type_gtp_invalid_ports': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/logging/gtp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/logging/gtp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["gtp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["gtp"].get(k) != v:
            change_results["changed"] = True
            config_changes["gtp"][k] = v

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
    payload = utils.build_json("gtp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["gtp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["gtp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["gtp"]["stats"] if info != "NotFound" else info
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
