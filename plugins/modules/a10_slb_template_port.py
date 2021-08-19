#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_template_port
description:
    - Port template
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
        - "Port template name"
        type: str
        required: True
    conn_limit:
        description:
        - "Connection limit"
        type: int
        required: False
    resume:
        description:
        - "Resume accepting new connection after connection number drops below threshold
          (Connection resume threshold)"
        type: int
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
    conn_rate_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        type: bool
        required: False
    request_rate_limit:
        description:
        - "Request rate limit"
        type: int
        required: False
    request_rate_interval:
        description:
        - "'100ms'= Use 100 ms as sampling interval; 'second'= Use 1 second as sampling
          interval;"
        type: str
        required: False
    reset:
        description:
        - "Send client reset when connection rate over limit"
        type: bool
        required: False
    request_rate_no_logging:
        description:
        - "Do not log connection over limit event"
        type: bool
        required: False
    dest_nat:
        description:
        - "Destination NAT"
        type: bool
        required: False
    down_grace_period:
        description:
        - "Port down grace period (Down grace period in seconds)"
        type: int
        required: False
    del_session_on_server_down:
        description:
        - "Delete session if the server/port goes down (either disabled/hm down)"
        type: bool
        required: False
    dscp:
        description:
        - "Differentiated Services Code Point (DSCP to Real Server IP Mapping Value)"
        type: int
        required: False
    dynamic_member_priority:
        description:
        - "Set dynamic member's priority (Initial priority (default is 16))"
        type: int
        required: False
    decrement:
        description:
        - "Decrease after every round of DNS query (default is 0)"
        type: int
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on real server port"
        type: bool
        required: False
    no_ssl:
        description:
        - "No SSL"
        type: bool
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for real server port;
          'stats-data-disable'= Disable statistical data collection for real server port;"
        type: str
        required: False
    health_check:
        description:
        - "Health Check Monitor (Health monitor name)"
        type: str
        required: False
    health_check_disable:
        description:
        - "Disable configured health check configuration"
        type: bool
        required: False
    inband_health_check:
        description:
        - "Use inband traffic to detect port's health status"
        type: bool
        required: False
    retry:
        description:
        - "Maximum retry times before reassign this connection to another server/port
          (default is 2) (The maximum retry number)"
        type: int
        required: False
    reassign:
        description:
        - "Maximum reassign times before declear the server/port down (default is 25) (The
          maximum reassign number)"
        type: int
        required: False
    down_timer:
        description:
        - "The timer to bring the marked down server/port to up (default is 0, never bring
          up) (The timer to bring up server (in second, default is 0))"
        type: int
        required: False
    resel_on_reset:
        description:
        - "When receiving reset from server, do the server/port reselection (default is 0,
          don't do reselection)"
        type: bool
        required: False
    source_nat:
        description:
        - "Source NAT (IP NAT Pool or pool group name)"
        type: str
        required: False
    shared_partition_pool:
        description:
        - "Reference a NAT pool or pool-group from shared partition"
        type: bool
        required: False
    template_port_pool_shared:
        description:
        - "Source NAT (IP NAT Pool or pool group name)"
        type: str
        required: False
    weight:
        description:
        - "Weight (port weight)"
        type: int
        required: False
    dampening_flaps:
        description:
        - "service dampening flaps count (max-flaps allowed in flap period)"
        type: int
        required: False
    flap_period:
        description:
        - "take service out of rotation if max-flaps exceeded within time in seconds"
        type: int
        required: False
    restore_svc_time:
        description:
        - "put the service back to the rotation after time in seconds"
        type: int
        required: False
    sub_group:
        description:
        - "Divide service group members into different sub groups (Sub group ID (default
          is 0))"
        type: int
        required: False
    slow_start:
        description:
        - "Slowly ramp up the connection number after port is up"
        type: bool
        required: False
    initial_slow_start:
        description:
        - "Initial slow start connection limit (default 128)"
        type: int
        required: False
    add:
        description:
        - "Slow start connection limit add by a number every interval (Add by this number
          every interval)"
        type: int
        required: False
    times:
        description:
        - "Slow start connection limit multiply by a number every interval (default 2)
          (Multiply by this number every interval)"
        type: int
        required: False
    every:
        description:
        - "Slow start connection limit increment interval (default 10)"
        type: int
        required: False
    till:
        description:
        - "Slow start ends when slow start connection limit reaches a number (default
          4096) (Slow start ends when connection limit reaches this number)"
        type: int
        required: False
    bw_rate_limit:
        description:
        - "Configure bandwidth rate limit on real server port (Bandwidth rate limit in
          Kbps)"
        type: int
        required: False
    bw_rate_limit_resume:
        description:
        - "Resume server selection after bandwidth drops below this threshold (in Kbps)
          (Bandwidth rate limit resume threshold (in Kbps))"
        type: int
        required: False
    bw_rate_limit_duration:
        description:
        - "Duration in seconds the observed rate needs to honor"
        type: int
        required: False
    bw_rate_limit_no_logging:
        description:
        - "Do not log bandwidth rate limit related state transitions"
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
AVAILABLE_PROPERTIES = ["add", "bw_rate_limit", "bw_rate_limit_duration", "bw_rate_limit_no_logging", "bw_rate_limit_resume", "conn_limit", "conn_limit_no_logging", "conn_rate_limit", "conn_rate_limit_no_logging", "dampening_flaps", "decrement", "del_session_on_server_down", "dest_nat", "down_grace_period", "down_timer", "dscp", "dynamic_member_priority", "every", "extended_stats", "flap_period", "health_check", "health_check_disable", "inband_health_check", "initial_slow_start", "name", "no_ssl", "rate_interval", "reassign", "request_rate_interval", "request_rate_limit", "request_rate_no_logging", "resel_on_reset", "reset", "restore_svc_time", "resume", "retry", "shared_partition_pool", "slow_start", "source_nat", "stats_data_action", "sub_group", "template_port_pool_shared", "till", "times", "user_tag", "uuid", "weight", ]


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
    rv.update({'name': {'type': 'str', 'required': True, },
        'conn_limit': {'type': 'int', },
        'resume': {'type': 'int', },
        'conn_limit_no_logging': {'type': 'bool', },
        'conn_rate_limit': {'type': 'int', },
        'rate_interval': {'type': 'str', 'choices': ['100ms', 'second']},
        'conn_rate_limit_no_logging': {'type': 'bool', },
        'request_rate_limit': {'type': 'int', },
        'request_rate_interval': {'type': 'str', 'choices': ['100ms', 'second']},
        'reset': {'type': 'bool', },
        'request_rate_no_logging': {'type': 'bool', },
        'dest_nat': {'type': 'bool', },
        'down_grace_period': {'type': 'int', },
        'del_session_on_server_down': {'type': 'bool', },
        'dscp': {'type': 'int', },
        'dynamic_member_priority': {'type': 'int', },
        'decrement': {'type': 'int', },
        'extended_stats': {'type': 'bool', },
        'no_ssl': {'type': 'bool', },
        'stats_data_action': {'type': 'str', 'choices': ['stats-data-enable', 'stats-data-disable']},
        'health_check': {'type': 'str', },
        'health_check_disable': {'type': 'bool', },
        'inband_health_check': {'type': 'bool', },
        'retry': {'type': 'int', },
        'reassign': {'type': 'int', },
        'down_timer': {'type': 'int', },
        'resel_on_reset': {'type': 'bool', },
        'source_nat': {'type': 'str', },
        'shared_partition_pool': {'type': 'bool', },
        'template_port_pool_shared': {'type': 'str', },
        'weight': {'type': 'int', },
        'dampening_flaps': {'type': 'int', },
        'flap_period': {'type': 'int', },
        'restore_svc_time': {'type': 'int', },
        'sub_group': {'type': 'int', },
        'slow_start': {'type': 'bool', },
        'initial_slow_start': {'type': 'int', },
        'add': {'type': 'int', },
        'times': {'type': 'int', },
        'every': {'type': 'int', },
        'till': {'type': 'int', },
        'bw_rate_limit': {'type': 'int', },
        'bw_rate_limit_resume': {'type': 'int', },
        'bw_rate_limit_duration': {'type': 'int', },
        'bw_rate_limit_no_logging': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/port/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/port/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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
