#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_health_stat
description:
    - Configure health monitor
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
                - "'all'= all; 'num_burst'= Number of burst; 'max_jiffie'= Maximum number of
          jiffies; 'min_jiffie'= Minimum number of jiffies; 'avg_jiffie'= Average number
          of jiffies; 'open_socket'= Number of open sockets; 'open_socket_failed'= Number
          of failed open sockets; 'close_socket'= Number of closed sockets;
          'connect_failed'= Number of failed connections; 'send_packet'= Number of
          packets sent; 'send_packet_failed'= Number of packet send failures;
          'recv_packet'= Number of received packets; 'recv_packet_failed'= Number of
          failed packet receives; 'retry_times'= Retry times; 'timeout'= Timouet value;
          'unexpected_error'= Number of unexpected errors; 'conn_imdt_succ'= Number of
          connection immediete success; 'sock_close_before_17'= Number of sockets closed
          before l7; 'sock_close_without_notify'= Number of sockets closed without
          notify; 'curr_health_rate'= Current health rate; 'ext_health_rate'= External
          health rate; 'ext_health_rate_val'= External health rate value; 'total_number'=
          Total number; 'status_up'= Number of status ups; 'status_down'= Number of
          status downs; 'status_unkn'= Number of status unknowns; 'status_other'= Number
          of other status; 'running_time'= Running time; 'config_health_rate'= Config
          health rate; 'ssl_post_handshake_packet'= Number of ssl post handshake packets
          before client sends request; 'timeout_with_packet'= Number of pin timeouts
          while socket has packets;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            health_check_list:
                description:
                - "Field health_check_list"
                type: list
            num_pins:
                description:
                - "Field num_pins"
                type: int
            num_pins_stat_up:
                description:
                - "Field num_pins_stat_up"
                type: int
            num_pins_stat_down:
                description:
                - "Field num_pins_stat_down"
                type: int
            num_pins_stat_unkn:
                description:
                - "Field num_pins_stat_unkn"
                type: int
            num_pins_stat_else:
                description:
                - "Field num_pins_stat_else"
                type: int
            num_ssl_tickets:
                description:
                - "Field num_ssl_tickets"
                type: int
            total_stat:
                description:
                - "Field total_stat"
                type: int
            method:
                description:
                - "Field method"
                type: str
            clear_ssl_ticket:
                description:
                - "Field clear_ssl_ticket"
                type: int
            monitor:
                description:
                - "Field monitor"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            num_burst:
                description:
                - "Number of burst"
                type: str
            max_jiffie:
                description:
                - "Maximum number of jiffies"
                type: str
            min_jiffie:
                description:
                - "Minimum number of jiffies"
                type: str
            avg_jiffie:
                description:
                - "Average number of jiffies"
                type: str
            open_socket:
                description:
                - "Number of open sockets"
                type: str
            open_socket_failed:
                description:
                - "Number of failed open sockets"
                type: str
            close_socket:
                description:
                - "Number of closed sockets"
                type: str
            connect_failed:
                description:
                - "Number of failed connections"
                type: str
            send_packet:
                description:
                - "Number of packets sent"
                type: str
            send_packet_failed:
                description:
                - "Number of packet send failures"
                type: str
            recv_packet:
                description:
                - "Number of received packets"
                type: str
            recv_packet_failed:
                description:
                - "Number of failed packet receives"
                type: str
            retry_times:
                description:
                - "Retry times"
                type: str
            timeout:
                description:
                - "Timouet value"
                type: str
            unexpected_error:
                description:
                - "Number of unexpected errors"
                type: str
            conn_imdt_succ:
                description:
                - "Number of connection immediete success"
                type: str
            sock_close_before_17:
                description:
                - "Number of sockets closed before l7"
                type: str
            sock_close_without_notify:
                description:
                - "Number of sockets closed without notify"
                type: str
            curr_health_rate:
                description:
                - "Current health rate"
                type: str
            ext_health_rate:
                description:
                - "External health rate"
                type: str
            ext_health_rate_val:
                description:
                - "External health rate value"
                type: str
            total_number:
                description:
                - "Total number"
                type: str
            status_up:
                description:
                - "Number of status ups"
                type: str
            status_down:
                description:
                - "Number of status downs"
                type: str
            status_unkn:
                description:
                - "Number of status unknowns"
                type: str
            status_other:
                description:
                - "Number of other status"
                type: str
            running_time:
                description:
                - "Running time"
                type: str
            config_health_rate:
                description:
                - "Config health rate"
                type: str
            ssl_post_handshake_packet:
                description:
                - "Number of ssl post handshake packets before client sends request"
                type: str
            timeout_with_packet:
                description:
                - "Number of pin timeouts while socket has packets"
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
AVAILABLE_PROPERTIES = [
    "oper",
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
                    'all', 'num_burst', 'max_jiffie', 'min_jiffie',
                    'avg_jiffie', 'open_socket', 'open_socket_failed',
                    'close_socket', 'connect_failed', 'send_packet',
                    'send_packet_failed', 'recv_packet', 'recv_packet_failed',
                    'retry_times', 'timeout', 'unexpected_error',
                    'conn_imdt_succ', 'sock_close_before_17',
                    'sock_close_without_notify', 'curr_health_rate',
                    'ext_health_rate', 'ext_health_rate_val', 'total_number',
                    'status_up', 'status_down', 'status_unkn', 'status_other',
                    'running_time', 'config_health_rate',
                    'ssl_post_handshake_packet', 'timeout_with_packet'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'health_check_list': {
                'type': 'list',
                'ip_address': {
                    'type': 'str',
                },
                'port': {
                    'type': 'str',
                },
                'health_monitor': {
                    'type': 'str',
                },
                'status': {
                    'type': 'str',
                },
                'up_cause': {
                    'type': 'int',
                },
                'down_cause': {
                    'type': 'int',
                },
                'down_state': {
                    'type': 'int',
                },
                'reason': {
                    'type': 'str',
                },
                'total_retry': {
                    'type': 'int',
                },
                'retries': {
                    'type': 'int',
                },
                'up_retries': {
                    'type': 'int',
                },
                'partition_id': {
                    'type': 'int',
                },
                'server': {
                    'type': 'str',
                },
                'ssl_version': {
                    'type': 'str',
                },
                'ssl_cipher': {
                    'type': 'str',
                },
                'ssl_ticket': {
                    'type': 'int',
                }
            },
            'num_pins': {
                'type': 'int',
            },
            'num_pins_stat_up': {
                'type': 'int',
            },
            'num_pins_stat_down': {
                'type': 'int',
            },
            'num_pins_stat_unkn': {
                'type': 'int',
            },
            'num_pins_stat_else': {
                'type': 'int',
            },
            'num_ssl_tickets': {
                'type': 'int',
            },
            'total_stat': {
                'type': 'int',
            },
            'method': {
                'type':
                'str',
                'choices': [
                    'icmp', 'tcp', 'udp', 'http', 'ftp', 'snmp', 'smtp', 'dns',
                    'pop3', 'imap', 'sip', 'radius', 'ldap', 'rtsp',
                    'database', 'external', 'ntp', 'compound', 'https',
                    'kerberos-kdc', 'tacplus'
                ]
            },
            'clear_ssl_ticket': {
                'type': 'int',
            },
            'monitor': {
                'type': 'str',
            }
        },
        'stats': {
            'type': 'dict',
            'num_burst': {
                'type': 'str',
            },
            'max_jiffie': {
                'type': 'str',
            },
            'min_jiffie': {
                'type': 'str',
            },
            'avg_jiffie': {
                'type': 'str',
            },
            'open_socket': {
                'type': 'str',
            },
            'open_socket_failed': {
                'type': 'str',
            },
            'close_socket': {
                'type': 'str',
            },
            'connect_failed': {
                'type': 'str',
            },
            'send_packet': {
                'type': 'str',
            },
            'send_packet_failed': {
                'type': 'str',
            },
            'recv_packet': {
                'type': 'str',
            },
            'recv_packet_failed': {
                'type': 'str',
            },
            'retry_times': {
                'type': 'str',
            },
            'timeout': {
                'type': 'str',
            },
            'unexpected_error': {
                'type': 'str',
            },
            'conn_imdt_succ': {
                'type': 'str',
            },
            'sock_close_before_17': {
                'type': 'str',
            },
            'sock_close_without_notify': {
                'type': 'str',
            },
            'curr_health_rate': {
                'type': 'str',
            },
            'ext_health_rate': {
                'type': 'str',
            },
            'ext_health_rate_val': {
                'type': 'str',
            },
            'total_number': {
                'type': 'str',
            },
            'status_up': {
                'type': 'str',
            },
            'status_down': {
                'type': 'str',
            },
            'status_unkn': {
                'type': 'str',
            },
            'status_other': {
                'type': 'str',
            },
            'running_time': {
                'type': 'str',
            },
            'config_health_rate': {
                'type': 'str',
            },
            'ssl_post_handshake_packet': {
                'type': 'str',
            },
            'timeout_with_packet': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/health-stat"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/health-stat"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["health-stat"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["health-stat"].get(k) != v:
            change_results["changed"] = True
            config_changes["health-stat"][k] = v

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
    payload = utils.build_json("health-stat", module.params,
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
                    "health-stat"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "health-stat-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["health-stat"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["health-stat"][
                    "stats"] if info != "NotFound" else info
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
