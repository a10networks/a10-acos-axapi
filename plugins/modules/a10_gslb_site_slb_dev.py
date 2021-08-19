#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_gslb_site_slb_dev
description:
    - Specify a SLB device for the GSLB site
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
    site_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    device_name:
        description:
        - "Specify SLB device name"
        type: str
        required: True
    ip_address:
        description:
        - "IP address"
        type: str
        required: False
    admin_preference:
        description:
        - "Specify administrative preference (Specify admin-preference value,default is
          100)"
        type: int
        required: False
    client_ip:
        description:
        - "Specify client IP address"
        type: str
        required: False
    rdt_value:
        description:
        - "Specify Round-delay-time"
        type: int
        required: False
    auto_detect:
        description:
        - "'ip'= Service IP only; 'port'= Service Port only; 'ip-and-port'= Both service
          IP and service port; 'disabled'= disable auto-detect;"
        type: str
        required: False
    auto_map:
        description:
        - "Enable DNS Auto Mapping"
        type: bool
        required: False
    max_client:
        description:
        - "Specify maximum number of clients, default is 32768"
        type: int
        required: False
    proto_aging_time:
        description:
        - "Specify GSLB Protocol aging time, default is 60"
        type: int
        required: False
    proto_aging_fast:
        description:
        - "Fast GSLB Protocol aging"
        type: bool
        required: False
    health_check_action:
        description:
        - "'health-check'= Enable health Check; 'health-check-disable'= Disable health
          check;"
        type: str
        required: False
    gateway_ip_addr:
        description:
        - "IP address"
        type: str
        required: False
    proto_compatible:
        description:
        - "Run GSLB Protocol in compatible mode"
        type: bool
        required: False
    msg_format_acos_2x:
        description:
        - "Run GSLB Protocol in compatible mode with a ACOS 2.x GSLB peer"
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
    vip_server:
        description:
        - "Field vip_server"
        type: dict
        required: False
        suboptions:
            vip_server_v4_list:
                description:
                - "Field vip_server_v4_list"
                type: list
            vip_server_v6_list:
                description:
                - "Field vip_server_v6_list"
                type: list
            vip_server_name_list:
                description:
                - "Field vip_server_name_list"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            dev_name:
                description:
                - "Field dev_name"
                type: str
            dev_ip:
                description:
                - "Field dev_ip"
                type: str
            dev_attr:
                description:
                - "Field dev_attr"
                type: str
            dev_admin_preference:
                description:
                - "Field dev_admin_preference"
                type: int
            dev_session_num:
                description:
                - "Field dev_session_num"
                type: int
            dev_session_util:
                description:
                - "Field dev_session_util"
                type: int
            dev_gw_state:
                description:
                - "Field dev_gw_state"
                type: str
            dev_ip_cnt:
                description:
                - "Field dev_ip_cnt"
                type: int
            dev_state:
                description:
                - "Field dev_state"
                type: str
            client_ldns_list:
                description:
                - "Field client_ldns_list"
                type: list
            device_name:
                description:
                - "Specify SLB device name"
                type: str
            vip_server:
                description:
                - "Field vip_server"
                type: dict

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
AVAILABLE_PROPERTIES = ["admin_preference", "auto_detect", "auto_map", "client_ip", "device_name", "gateway_ip_addr", "health_check_action", "ip_address", "max_client", "msg_format_acos_2x", "oper", "proto_aging_fast", "proto_aging_time", "proto_compatible", "rdt_value", "user_tag", "uuid", "vip_server", ]


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
    rv.update({'device_name': {'type': 'str', 'required': True, },
        'ip_address': {'type': 'str', },
        'admin_preference': {'type': 'int', },
        'client_ip': {'type': 'str', },
        'rdt_value': {'type': 'int', },
        'auto_detect': {'type': 'str', 'choices': ['ip', 'port', 'ip-and-port', 'disabled']},
        'auto_map': {'type': 'bool', },
        'max_client': {'type': 'int', },
        'proto_aging_time': {'type': 'int', },
        'proto_aging_fast': {'type': 'bool', },
        'health_check_action': {'type': 'str', 'choices': ['health-check', 'health-check-disable']},
        'gateway_ip_addr': {'type': 'str', },
        'proto_compatible': {'type': 'bool', },
        'msg_format_acos_2x': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'vip_server': {'type': 'dict', 'vip_server_v4_list': {'type': 'list', 'ipv4': {'type': 'str', 'required': True, }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'dev_vip_hits']}}}, 'vip_server_v6_list': {'type': 'list', 'ipv6': {'type': 'str', 'required': True, }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'dev_vip_hits']}}}, 'vip_server_name_list': {'type': 'list', 'vip_name': {'type': 'str', 'required': True, }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'dev_vip_hits']}}}},
        'oper': {'type': 'dict', 'dev_name': {'type': 'str', }, 'dev_ip': {'type': 'str', }, 'dev_attr': {'type': 'str', }, 'dev_admin_preference': {'type': 'int', }, 'dev_session_num': {'type': 'int', }, 'dev_session_util': {'type': 'int', }, 'dev_gw_state': {'type': 'str', }, 'dev_ip_cnt': {'type': 'int', }, 'dev_state': {'type': 'str', }, 'client_ldns_list': {'type': 'list', 'client_ip': {'type': 'str', }, 'age': {'type': 'int', }, 'ntype': {'type': 'str', }, 'rdt_sample1': {'type': 'int', }, 'rdt_sample2': {'type': 'int', }, 'rdt_sample3': {'type': 'int', }, 'rdt_sample4': {'type': 'int', }, 'rdt_sample5': {'type': 'int', }, 'rdt_sample6': {'type': 'int', }, 'rdt_sample7': {'type': 'int', }, 'rdt_sample8': {'type': 'int', }}, 'device_name': {'type': 'str', 'required': True, }, 'vip_server': {'type': 'dict', 'oper': {'type': 'dict', }, 'vip_server_v4_list': {'type': 'list', 'ipv4': {'type': 'str', 'required': True, }, 'oper': {'type': 'dict', 'dev_vip_addr': {'type': 'str', }, 'dev_vip_state': {'type': 'str', }, 'dev_vip_port_list': {'type': 'list', 'dev_vip_port_num': {'type': 'int', }, 'dev_vip_port_state': {'type': 'str', }}}}, 'vip_server_v6_list': {'type': 'list', 'ipv6': {'type': 'str', 'required': True, }, 'oper': {'type': 'dict', 'dev_vip_addr': {'type': 'str', }, 'dev_vip_state': {'type': 'str', }, 'dev_vip_port_list': {'type': 'list', 'dev_vip_port_num': {'type': 'int', }, 'dev_vip_port_state': {'type': 'str', }}}}, 'vip_server_name_list': {'type': 'list', 'vip_name': {'type': 'str', 'required': True, }, 'oper': {'type': 'dict', 'dev_vip_addr': {'type': 'str', }, 'dev_vip_state': {'type': 'str', }, 'dev_vip_port_list': {'type': 'list', 'dev_vip_port_num': {'type': 'int', }, 'dev_vip_port_state': {'type': 'str', }}}}}}
    })
    # Parent keys
    rv.update(dict(
        site_name=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/site/{site_name}/slb-dev/{device-name}"

    f_dict = {}
    f_dict["device-name"] = module.params["device_name"]
    f_dict["site_name"] = module.params["site_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/site/{site_name}/slb-dev/{device-name}"

    f_dict = {}
    f_dict["device-name"] = ""
    f_dict["site_name"] = module.params["site_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["slb-dev"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["slb-dev"].get(k) != v:
            change_results["changed"] = True
            config_changes["slb-dev"][k] = v

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
    payload = utils.build_json("slb-dev", module.params, AVAILABLE_PROPERTIES)
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
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
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
