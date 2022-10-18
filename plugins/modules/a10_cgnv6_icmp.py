#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_icmp
description:
    - CGNV6 ICMP Statistics
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
                - "'all'= all; 'icmp-unknown-type'= ICMP Unknown Type; 'icmp-no-port-info'= ICMP
          Port Info Not Included; 'icmp-no-session-drop'= ICMP No Matching Session Drop;
          'icmpv6-unknown-type'= ICMPv6 Unknown Type; 'icmpv6-no-port-info'= ICMPv6 Port
          Info Not Included; 'icmpv6-no-session-drop'= ICMPv6 No Matching Session Drop;
          'icmp-to-icmp'= ICMP to ICMP Conversion; 'icmp-to-icmpv6'= ICMP to ICMPv6
          Conversion; 'icmpv6-to-icmp'= ICMPv6 to ICMP Conversion; 'icmpv6-to-icmpv6'=
          ICMPv6 to ICMPv6 Conversion; 'icmp-bad-type'= Bad Embedded ICMP Type;
          'icmpv6-bad-type'= Bad Embedded ICMPv6 Type; '64-known-drop'= NAT64 Forward
          Known ICMPv6 Drop; '64-unknown-drop'= NAT64 Forward Unknown ICMPv6 Drop;
          '64-midpoint-hop'= NAT64 Forward Unknown Source Drop; '46-known-drop'= NAT64
          Reverse Known ICMP Drop; '46-unknown-drop'= NAT64 Reverse Known ICMPv6 Drop;
          '46-no-prefix-for-ipv4'= NAT64 Reverse No Prefix Match for IPv4; '46-bad-encap-
          ip-header-len'= 4to6 Bad Encapsulated IP Header Length; 'icmp-to-icmp-err'=
          ICMP to ICMP Conversion Error; 'icmp-to-icmpv6-err'= ICMP to ICMPv6 Conversion
          Error; 'icmpv6-to-icmp-err'= ICMPv6 to ICMP Conversion Error; 'icmpv6-to-
          icmpv6-err'= ICMPv6 to ICMPv6 Conversion Error; 'encap-cross-cpu-no-match'=
          ICMP Embedded Cross CPU No Matching Session; 'encap-cross-cpu-preprocess-err'=
          ICMP Embedded Cross CPU Preprocess Error; 'icmp-to-icmp-unknown-l4'= ICMP
          Embedded Unknown L4 Protocol; 'icmp-to-icmpv6-unknown-l4'= ICMP to ICMPv6
          Embedded Unknown L4 Protocol; 'icmpv6-to-icmp-unknown-l4'= ICMPv6 to ICMP
          Embedded Unknown L4 Protocol; 'icmpv6-to-icmpv6-unknown-l4'= ICMPv6 to ICMPv6
          Embedded Unknown L4 Protocol; 'static-nat'= ICMP Static NAT; 'echo-to-pool-
          reply'= Ping to Pool Reply; 'echo-to-pool-drop'= Ping to Pool Drop; 'error-to-
          pool-drop'= Error to Pool Drop; 'echo-to-pool-reply-v6'= Ping6 to Pool Reply;
          'echo-to-pool-drop-v6'= Ping6 to Pool Drop; 'error-to-pool-drop-v6'= Error to
          IPv6 Pool Drop; 'error-ip-mismatch'= ICMP IP address mismatch;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            icmp_unknown_type:
                description:
                - "ICMP Unknown Type"
                type: str
            icmp_no_port_info:
                description:
                - "ICMP Port Info Not Included"
                type: str
            icmp_no_session_drop:
                description:
                - "ICMP No Matching Session Drop"
                type: str
            icmpv6_unknown_type:
                description:
                - "ICMPv6 Unknown Type"
                type: str
            icmpv6_no_port_info:
                description:
                - "ICMPv6 Port Info Not Included"
                type: str
            icmpv6_no_session_drop:
                description:
                - "ICMPv6 No Matching Session Drop"
                type: str
            icmp_to_icmp:
                description:
                - "ICMP to ICMP Conversion"
                type: str
            icmp_to_icmpv6:
                description:
                - "ICMP to ICMPv6 Conversion"
                type: str
            icmpv6_to_icmp:
                description:
                - "ICMPv6 to ICMP Conversion"
                type: str
            icmpv6_to_icmpv6:
                description:
                - "ICMPv6 to ICMPv6 Conversion"
                type: str
            icmp_bad_type:
                description:
                - "Bad Embedded ICMP Type"
                type: str
            icmpv6_bad_type:
                description:
                - "Bad Embedded ICMPv6 Type"
                type: str
            64_known_drop:
                description:
                - "NAT64 Forward Known ICMPv6 Drop"
                type: str
            64_unknown_drop:
                description:
                - "NAT64 Forward Unknown ICMPv6 Drop"
                type: str
            64_midpoint_hop:
                description:
                - "NAT64 Forward Unknown Source Drop"
                type: str
            46_known_drop:
                description:
                - "NAT64 Reverse Known ICMP Drop"
                type: str
            46_unknown_drop:
                description:
                - "NAT64 Reverse Known ICMPv6 Drop"
                type: str
            46_no_prefix_for_ipv4:
                description:
                - "NAT64 Reverse No Prefix Match for IPv4"
                type: str
            icmp_to_icmp_err:
                description:
                - "ICMP to ICMP Conversion Error"
                type: str
            icmp_to_icmpv6_err:
                description:
                - "ICMP to ICMPv6 Conversion Error"
                type: str
            icmpv6_to_icmp_err:
                description:
                - "ICMPv6 to ICMP Conversion Error"
                type: str
            icmpv6_to_icmpv6_err:
                description:
                - "ICMPv6 to ICMPv6 Conversion Error"
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
                    'all', 'icmp-unknown-type', 'icmp-no-port-info', 'icmp-no-session-drop', 'icmpv6-unknown-type', 'icmpv6-no-port-info', 'icmpv6-no-session-drop', 'icmp-to-icmp', 'icmp-to-icmpv6', 'icmpv6-to-icmp', 'icmpv6-to-icmpv6', 'icmp-bad-type', 'icmpv6-bad-type', '64-known-drop', '64-unknown-drop', '64-midpoint-hop', '46-known-drop',
                    '46-unknown-drop', '46-no-prefix-for-ipv4', '46-bad-encap-ip-header-len', 'icmp-to-icmp-err', 'icmp-to-icmpv6-err', 'icmpv6-to-icmp-err', 'icmpv6-to-icmpv6-err', 'encap-cross-cpu-no-match', 'encap-cross-cpu-preprocess-err', 'icmp-to-icmp-unknown-l4', 'icmp-to-icmpv6-unknown-l4', 'icmpv6-to-icmp-unknown-l4',
                    'icmpv6-to-icmpv6-unknown-l4', 'static-nat', 'echo-to-pool-reply', 'echo-to-pool-drop', 'error-to-pool-drop', 'echo-to-pool-reply-v6', 'echo-to-pool-drop-v6', 'error-to-pool-drop-v6', 'error-ip-mismatch'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'icmp_unknown_type': {
                'type': 'str',
                },
            'icmp_no_port_info': {
                'type': 'str',
                },
            'icmp_no_session_drop': {
                'type': 'str',
                },
            'icmpv6_unknown_type': {
                'type': 'str',
                },
            'icmpv6_no_port_info': {
                'type': 'str',
                },
            'icmpv6_no_session_drop': {
                'type': 'str',
                },
            'icmp_to_icmp': {
                'type': 'str',
                },
            'icmp_to_icmpv6': {
                'type': 'str',
                },
            'icmpv6_to_icmp': {
                'type': 'str',
                },
            'icmpv6_to_icmpv6': {
                'type': 'str',
                },
            'icmp_bad_type': {
                'type': 'str',
                },
            'icmpv6_bad_type': {
                'type': 'str',
                },
            '64_known_drop': {
                'type': 'str',
                },
            '64_unknown_drop': {
                'type': 'str',
                },
            '64_midpoint_hop': {
                'type': 'str',
                },
            '46_known_drop': {
                'type': 'str',
                },
            '46_unknown_drop': {
                'type': 'str',
                },
            '46_no_prefix_for_ipv4': {
                'type': 'str',
                },
            'icmp_to_icmp_err': {
                'type': 'str',
                },
            'icmp_to_icmpv6_err': {
                'type': 'str',
                },
            'icmpv6_to_icmp_err': {
                'type': 'str',
                },
            'icmpv6_to_icmpv6_err': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/icmp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/icmp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["icmp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["icmp"].get(k) != v:
            change_results["changed"] = True
            config_changes["icmp"][k] = v

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
    payload = utils.build_json("icmp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["icmp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["icmp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["icmp"]["stats"] if info != "NotFound" else info
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
