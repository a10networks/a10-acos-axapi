#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_mqtt
description:
    - Show MQTT Statistics
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
                - "'all'= all; 'recv_mqtt_connect'= MQTT Connect; 'recv_mqtt_connack'= MQTT
          Connack; 'recv_mqtt_publish'= MQTT Publish; 'recv_mqtt_puback'= MQTT Puback;
          'recv_mqtt_pubrec'= MQTT Pubrec; 'recv_mqtt_pubrel'= MQTT Pubrel;
          'recv_mqtt_pubcomp'= MQTT Pubcomp; 'recv_mqtt_subscribe'= MQTT Subscribe;
          'recv_mqtt_suback'= MQTT Suback; 'recv_mqtt_unsubscribe'= MQTT Unsubscribe;
          'recv_mqtt_unsuback'= MQTT Unsuback; 'recv_mqtt_pingreq'= MQTT Pingreq;
          'recv_mqtt_pingresp'= MQTT Pingresp; 'recv_mqtt_disconnect'= MQTT Disconnect;
          'recv_mqtt_auth'= MQTT Auth; 'recv_mqtt_other'= MQTT Unknown; 'curr_proxy'=
          Current proxy conns; 'total_proxy'= Total proxy conns; 'request'= Total MQTT
          Commands; 'parse_connect_fail'= Parse connect failure; 'parse_publish_fail'=
          Parse publish failure; 'parse_subscribe_fail'= Parse subscribe failure;
          'parse_unsubscribe_fail'= Parse unsubscribe failure; 'tuple_not_linked'= tuple-
          not-linked failure; 'tuple_already_linked'= tuple-already-linked failure;
          'conn_null'= Null conn; 'client_id_null'= Null client id; 'session_exist'=
          Session already exist; 'insertion_failed'= Insertion failure;
          'insertion_successful'= Insertion successful;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            mqtt_cpu_list:
                description:
                - "Field mqtt_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            recv_mqtt_connect:
                description:
                - "MQTT Connect"
                type: str
            recv_mqtt_connack:
                description:
                - "MQTT Connack"
                type: str
            recv_mqtt_publish:
                description:
                - "MQTT Publish"
                type: str
            recv_mqtt_puback:
                description:
                - "MQTT Puback"
                type: str
            recv_mqtt_pubrec:
                description:
                - "MQTT Pubrec"
                type: str
            recv_mqtt_pubrel:
                description:
                - "MQTT Pubrel"
                type: str
            recv_mqtt_pubcomp:
                description:
                - "MQTT Pubcomp"
                type: str
            recv_mqtt_subscribe:
                description:
                - "MQTT Subscribe"
                type: str
            recv_mqtt_suback:
                description:
                - "MQTT Suback"
                type: str
            recv_mqtt_unsubscribe:
                description:
                - "MQTT Unsubscribe"
                type: str
            recv_mqtt_unsuback:
                description:
                - "MQTT Unsuback"
                type: str
            recv_mqtt_pingreq:
                description:
                - "MQTT Pingreq"
                type: str
            recv_mqtt_pingresp:
                description:
                - "MQTT Pingresp"
                type: str
            recv_mqtt_disconnect:
                description:
                - "MQTT Disconnect"
                type: str
            recv_mqtt_auth:
                description:
                - "MQTT Auth"
                type: str
            recv_mqtt_other:
                description:
                - "MQTT Unknown"
                type: str
            curr_proxy:
                description:
                - "Current proxy conns"
                type: str
            total_proxy:
                description:
                - "Total proxy conns"
                type: str
            request:
                description:
                - "Total MQTT Commands"
                type: str
            parse_connect_fail:
                description:
                - "Parse connect failure"
                type: str
            parse_publish_fail:
                description:
                - "Parse publish failure"
                type: str
            parse_subscribe_fail:
                description:
                - "Parse subscribe failure"
                type: str
            parse_unsubscribe_fail:
                description:
                - "Parse unsubscribe failure"
                type: str
            tuple_not_linked:
                description:
                - "tuple-not-linked failure"
                type: str
            tuple_already_linked:
                description:
                - "tuple-already-linked failure"
                type: str
            conn_null:
                description:
                - "Null conn"
                type: str
            client_id_null:
                description:
                - "Null client id"
                type: str
            session_exist:
                description:
                - "Session already exist"
                type: str
            insertion_failed:
                description:
                - "Insertion failure"
                type: str
            insertion_successful:
                description:
                - "Insertion successful"
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
                    'all', 'recv_mqtt_connect', 'recv_mqtt_connack',
                    'recv_mqtt_publish', 'recv_mqtt_puback',
                    'recv_mqtt_pubrec', 'recv_mqtt_pubrel',
                    'recv_mqtt_pubcomp', 'recv_mqtt_subscribe',
                    'recv_mqtt_suback', 'recv_mqtt_unsubscribe',
                    'recv_mqtt_unsuback', 'recv_mqtt_pingreq',
                    'recv_mqtt_pingresp', 'recv_mqtt_disconnect',
                    'recv_mqtt_auth', 'recv_mqtt_other', 'curr_proxy',
                    'total_proxy', 'request', 'parse_connect_fail',
                    'parse_publish_fail', 'parse_subscribe_fail',
                    'parse_unsubscribe_fail', 'tuple_not_linked',
                    'tuple_already_linked', 'conn_null', 'client_id_null',
                    'session_exist', 'insertion_failed', 'insertion_successful'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'mqtt_cpu_list': {
                'type': 'list',
                'recv_mqtt_connect': {
                    'type': 'int',
                },
                'recv_mqtt_connack': {
                    'type': 'int',
                },
                'recv_mqtt_publish': {
                    'type': 'int',
                },
                'recv_mqtt_puback': {
                    'type': 'int',
                },
                'recv_mqtt_pubrec': {
                    'type': 'int',
                },
                'recv_mqtt_pubrel': {
                    'type': 'int',
                },
                'recv_mqtt_pubcomp': {
                    'type': 'int',
                },
                'recv_mqtt_subscribe': {
                    'type': 'int',
                },
                'recv_mqtt_suback': {
                    'type': 'int',
                },
                'recv_mqtt_unsubscribe': {
                    'type': 'int',
                },
                'recv_mqtt_unsuback': {
                    'type': 'int',
                },
                'recv_mqtt_pingreq': {
                    'type': 'int',
                },
                'recv_mqtt_pingresp': {
                    'type': 'int',
                },
                'recv_mqtt_disconnect': {
                    'type': 'int',
                },
                'recv_mqtt_auth': {
                    'type': 'int',
                },
                'recv_mqtt_other': {
                    'type': 'int',
                },
                'curr_proxy': {
                    'type': 'int',
                },
                'total_proxy': {
                    'type': 'int',
                },
                'request': {
                    'type': 'int',
                },
                'parse_connect_fail': {
                    'type': 'int',
                },
                'parse_publish_fail': {
                    'type': 'int',
                },
                'parse_subscribe_fail': {
                    'type': 'int',
                },
                'parse_unsubscribe_fail': {
                    'type': 'int',
                },
                'tuple_not_linked': {
                    'type': 'int',
                },
                'tuple_already_linked': {
                    'type': 'int',
                },
                'conn_null': {
                    'type': 'int',
                },
                'client_id_null': {
                    'type': 'int',
                },
                'session_exist': {
                    'type': 'int',
                },
                'insertion_failed': {
                    'type': 'int',
                },
                'insertion_successful': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'recv_mqtt_connect': {
                'type': 'str',
            },
            'recv_mqtt_connack': {
                'type': 'str',
            },
            'recv_mqtt_publish': {
                'type': 'str',
            },
            'recv_mqtt_puback': {
                'type': 'str',
            },
            'recv_mqtt_pubrec': {
                'type': 'str',
            },
            'recv_mqtt_pubrel': {
                'type': 'str',
            },
            'recv_mqtt_pubcomp': {
                'type': 'str',
            },
            'recv_mqtt_subscribe': {
                'type': 'str',
            },
            'recv_mqtt_suback': {
                'type': 'str',
            },
            'recv_mqtt_unsubscribe': {
                'type': 'str',
            },
            'recv_mqtt_unsuback': {
                'type': 'str',
            },
            'recv_mqtt_pingreq': {
                'type': 'str',
            },
            'recv_mqtt_pingresp': {
                'type': 'str',
            },
            'recv_mqtt_disconnect': {
                'type': 'str',
            },
            'recv_mqtt_auth': {
                'type': 'str',
            },
            'recv_mqtt_other': {
                'type': 'str',
            },
            'curr_proxy': {
                'type': 'str',
            },
            'total_proxy': {
                'type': 'str',
            },
            'request': {
                'type': 'str',
            },
            'parse_connect_fail': {
                'type': 'str',
            },
            'parse_publish_fail': {
                'type': 'str',
            },
            'parse_subscribe_fail': {
                'type': 'str',
            },
            'parse_unsubscribe_fail': {
                'type': 'str',
            },
            'tuple_not_linked': {
                'type': 'str',
            },
            'tuple_already_linked': {
                'type': 'str',
            },
            'conn_null': {
                'type': 'str',
            },
            'client_id_null': {
                'type': 'str',
            },
            'session_exist': {
                'type': 'str',
            },
            'insertion_failed': {
                'type': 'str',
            },
            'insertion_successful': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/mqtt"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/mqtt"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["mqtt"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["mqtt"].get(k) != v:
            change_results["changed"] = True
            config_changes["mqtt"][k] = v

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
    payload = utils.build_json("mqtt", module.params, AVAILABLE_PROPERTIES)
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
                result[
                    "acos_info"] = info["mqtt"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "mqtt-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["mqtt"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["mqtt"][
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
