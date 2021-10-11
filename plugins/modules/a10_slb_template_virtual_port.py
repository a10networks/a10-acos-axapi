#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_virtual_port
description:
    - Virtual port template
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
    name:
        description:
        - "Virtual port template name"
        type: str
        required: True
    aflow:
        description:
        - "Use aFlow to eliminate the traffic surge"
        type: bool
        required: False
    allow_syn_otherflags:
        description:
        - "Allow initial SYN packet with other flags"
        type: bool
        required: False
    conn_limit:
        description:
        - "Connection limit"
        type: int
        required: False
    conn_limit_reset:
        description:
        - "Send client reset when connection over limit"
        type: bool
        required: False
    conn_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        type: bool
        required: False
    conn_rate_limit:
        description:
        - "Connection rate limit"
        type: int
        required: False
    rate_interval:
        description:
        - "'100ms'= Use 100 ms as sampling interval; 'second'= Use 1 second as sampling
          interval;"
        type: str
        required: False
    conn_rate_limit_reset:
        description:
        - "Send client reset when connection rate over limit"
        type: bool
        required: False
    conn_rate_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        type: bool
        required: False
    pkt_rate_type:
        description:
        - "'src-ip-port'= Source IP and port rate limit; 'src-port'= Source port rate
          limit;"
        type: str
        required: False
    rate:
        description:
        - "Source IP and port rate limit (Packet rate limit)"
        type: int
        required: False
    pkt_rate_interval:
        description:
        - "'100ms'= Source IP and port rate limit per 100ms; 'second'= Source IP and port
          rate limit per second (default);"
        type: str
        required: False
    pkt_rate_limit_reset:
        description:
        - "send client-side reset (reset after packet limit)"
        type: int
        required: False
    log_options:
        description:
        - "'no-logging'= Do not log over limit event; 'no-repeat-logging'= log once for
          over limit event. Default is log once per minute;"
        type: str
        required: False
    when_rr_enable:
        description:
        - "Only do rate limit if CPU RR triggered"
        type: bool
        required: False
    allow_vip_to_rport_mapping:
        description:
        - "Allow mapping of VIP to real port"
        type: bool
        required: False
    dscp:
        description:
        - "Differentiated Services Code Point (DSCP to Real Server IP Mapping Value)"
        type: int
        required: False
    drop_unknown_conn:
        description:
        - "Drop conection if receives TCP packet without SYN or RST flag and it does not
          belong to any existing connections"
        type: bool
        required: False
    reset_unknown_conn:
        description:
        - "Send reset back if receives TCP packet without SYN or RST flag and it does not
          belong to any existing connections"
        type: bool
        required: False
    reset_l7_on_failover:
        description:
        - "Send reset to L7 client and server connection upon a failover"
        type: bool
        required: False
    ignore_tcp_msl:
        description:
        - "reclaim TCP resource immediately without MSL"
        type: bool
        required: False
    snat_msl:
        description:
        - "Source NAT MSL (Source NAT MSL value (seconds))"
        type: int
        required: False
    snat_port_preserve:
        description:
        - "Source NAT Port Preservation"
        type: bool
        required: False
    non_syn_initiation:
        description:
        - "Allow initial TCP packet to be non-SYN"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
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
    "aflow",
    "allow_syn_otherflags",
    "allow_vip_to_rport_mapping",
    "conn_limit",
    "conn_limit_no_logging",
    "conn_limit_reset",
    "conn_rate_limit",
    "conn_rate_limit_no_logging",
    "conn_rate_limit_reset",
    "drop_unknown_conn",
    "dscp",
    "ignore_tcp_msl",
    "log_options",
    "name",
    "non_syn_initiation",
    "pkt_rate_interval",
    "pkt_rate_limit_reset",
    "pkt_rate_type",
    "rate",
    "rate_interval",
    "reset_l7_on_failover",
    "reset_unknown_conn",
    "snat_msl",
    "snat_port_preserve",
    "user_tag",
    "uuid",
    "when_rr_enable",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'aflow': {
            'type': 'bool',
        },
        'allow_syn_otherflags': {
            'type': 'bool',
        },
        'conn_limit': {
            'type': 'int',
        },
        'conn_limit_reset': {
            'type': 'bool',
        },
        'conn_limit_no_logging': {
            'type': 'bool',
        },
        'conn_rate_limit': {
            'type': 'int',
        },
        'rate_interval': {
            'type': 'str',
            'choices': ['100ms', 'second']
        },
        'conn_rate_limit_reset': {
            'type': 'bool',
        },
        'conn_rate_limit_no_logging': {
            'type': 'bool',
        },
        'pkt_rate_type': {
            'type': 'str',
            'choices': ['src-ip-port', 'src-port']
        },
        'rate': {
            'type': 'int',
        },
        'pkt_rate_interval': {
            'type': 'str',
            'choices': ['100ms', 'second']
        },
        'pkt_rate_limit_reset': {
            'type': 'int',
        },
        'log_options': {
            'type': 'str',
            'choices': ['no-logging', 'no-repeat-logging']
        },
        'when_rr_enable': {
            'type': 'bool',
        },
        'allow_vip_to_rport_mapping': {
            'type': 'bool',
        },
        'dscp': {
            'type': 'int',
        },
        'drop_unknown_conn': {
            'type': 'bool',
        },
        'reset_unknown_conn': {
            'type': 'bool',
        },
        'reset_l7_on_failover': {
            'type': 'bool',
        },
        'ignore_tcp_msl': {
            'type': 'bool',
        },
        'snat_msl': {
            'type': 'int',
        },
        'snat_port_preserve': {
            'type': 'bool',
        },
        'non_syn_initiation': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["virtual-port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["virtual-port"].get(k) != v:
            change_results["changed"] = True
            config_changes["virtual-port"][k] = v

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
    payload = utils.build_json("virtual-port", module.params,
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
                    "virtual-port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "virtual-port-list"] if info != "NotFound" else info
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
