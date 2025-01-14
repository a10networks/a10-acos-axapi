#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vcs_vcs_para
description:
    - Virtual Chassis System Paramter
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
    floating_ip_cfg:
        description:
        - "Field floating_ip_cfg"
        type: list
        required: False
        suboptions:
            floating_ip:
                description:
                - "Floating IP address (IPv4 address)"
                type: str
            floating_ip_mask:
                description:
                - "Netmask"
                type: str
    floating_ipv6_cfg:
        description:
        - "Field floating_ipv6_cfg"
        type: list
        required: False
        suboptions:
            floating_ipv6:
                description:
                - "Floating IPv6 address"
                type: str
    ssl_enable:
        description:
        - "Enable SSL"
        type: bool
        required: False
    multicast_ip:
        description:
        - "Multicast (group) IP address (Multicast IP address (224.0.0.211 by default))"
        type: str
        required: False
    multicast_ipv6:
        description:
        - "Multicast (group) IPv6 address (Multicast IPv6 address)"
        type: str
        required: False
    multicast_port:
        description:
        - "Port used in multicast communication (Port number)"
        type: int
        required: False
    failure_retry_count_value:
        description:
        - "0-255, default is 2"
        type: int
        required: False
    forever:
        description:
        - "VCS retry forever if fails to join the chassis"
        type: bool
        required: False
    dead_interval_mseconds:
        description:
        - "The node will be considered dead as lack of hearbeats after this time
          (milisecond) (in unit of msecond, default is 0)"
        type: int
        required: False
    time_interval_mseconds:
        description:
        - "how long between heartbeats (mseconds) (in unit of milisecond, default is 0)"
        type: int
        required: False
    dead_interval:
        description:
        - "The node will be considered dead as lack of hearbeats after this time (in unit
          of second, 10 by default)"
        type: int
        required: False
    time_interval:
        description:
        - "how long between heartbeats (in unit of second, default is 3)"
        type: int
        required: False
    link_poll_timeout:
        description:
        - "Field link_poll_timeout"
        type: int
        required: False
    chassis_id:
        description:
        - "Chassis ID"
        type: int
        required: False
    config_info:
        description:
        - "Configuration information (Configuration tag)"
        type: str
        required: False
    config_seq:
        description:
        - "Configuration sequence number"
        type: str
        required: False
    tcp_channel_monitor:
        description:
        - "Enable vBlade TCP channel monitor"
        type: bool
        required: False
    size:
        description:
        - "file size (MBytes) to transmit to monitor the TCP channel"
        type: int
        required: False
    speed_limit:
        description:
        - "speed (KByte/s) limitation for the transmit monitor"
        type: int
        required: False
    force_wait_interval:
        description:
        - "The node will wait the specified time interval before it start aVCS (in unit of
          second (default is 5))"
        type: int
        required: False
    hold_preemption_interval:
        description:
        - "The VCS Node will hold specified time interval before it start to challenge
          peer(s) for Mastership (in unit of second (default is 60))"
        type: int
        required: False
    slog_level:
        description:
        - "Set the level of slog for aVCS"
        type: int
        required: False
    slog_method:
        description:
        - "Set the print method of slog for aVCS"
        type: int
        required: False
    transmit_fragment_size:
        description:
        - "Set the fragment size (KByte) of the aVCS transmit"
        type: int
        required: False
    memory_stat_interval:
        description:
        - "Interval of aVCS memory statistics record (minutes)"
        type: int
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
    "chassis_id", "config_info", "config_seq", "dead_interval", "dead_interval_mseconds", "failure_retry_count_value", "floating_ip_cfg", "floating_ipv6_cfg", "force_wait_interval", "forever", "hold_preemption_interval", "link_poll_timeout", "memory_stat_interval", "multicast_ip", "multicast_ipv6", "multicast_port", "size", "slog_level",
    "slog_method", "speed_limit", "ssl_enable", "tcp_channel_monitor", "time_interval", "time_interval_mseconds", "transmit_fragment_size", "uuid",
    ]


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
        'floating_ip_cfg': {
            'type': 'list',
            'floating_ip': {
                'type': 'str',
                },
            'floating_ip_mask': {
                'type': 'str',
                }
            },
        'floating_ipv6_cfg': {
            'type': 'list',
            'floating_ipv6': {
                'type': 'str',
                }
            },
        'ssl_enable': {
            'type': 'bool',
            },
        'multicast_ip': {
            'type': 'str',
            },
        'multicast_ipv6': {
            'type': 'str',
            },
        'multicast_port': {
            'type': 'int',
            },
        'failure_retry_count_value': {
            'type': 'int',
            },
        'forever': {
            'type': 'bool',
            },
        'dead_interval_mseconds': {
            'type': 'int',
            },
        'time_interval_mseconds': {
            'type': 'int',
            },
        'dead_interval': {
            'type': 'int',
            },
        'time_interval': {
            'type': 'int',
            },
        'link_poll_timeout': {
            'type': 'int',
            },
        'chassis_id': {
            'type': 'int',
            },
        'config_info': {
            'type': 'str',
            },
        'config_seq': {
            'type': 'str',
            },
        'tcp_channel_monitor': {
            'type': 'bool',
            },
        'size': {
            'type': 'int',
            },
        'speed_limit': {
            'type': 'int',
            },
        'force_wait_interval': {
            'type': 'int',
            },
        'hold_preemption_interval': {
            'type': 'int',
            },
        'slog_level': {
            'type': 'int',
            },
        'slog_method': {
            'type': 'int',
            },
        'transmit_fragment_size': {
            'type': 'int',
            },
        'memory_stat_interval': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vcs/vcs-para"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vcs/vcs-para"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["vcs-para"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["vcs-para"].get(k) != v:
            change_results["changed"] = True
            config_changes["vcs-para"][k] = v

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
    payload = utils.build_json("vcs-para", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["vcs-para"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["vcs-para-list"] if info != "NotFound" else info
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
