#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_service_group_member
description:
    - Service Group Member
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
    service_group_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    name:
        description:
        - "Member name"
        type: str
        required: True
    port:
        description:
        - "Port number"
        type: int
        required: True
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_conn'= Current connections; 'total_fwd_bytes'= Total forward
          bytes; 'total_fwd_pkts'= Total forward packets; 'total_rev_bytes'= Total
          reverse bytes; 'total_rev_pkts'= Total reverse packets; 'total_conn'= Total
          connections; 'total_rev_pkts_inspected'= Total reverse packets inspected;
          'total_rev_pkts_inspected_status_code_2xx'= Total reverse packets inspected
          status code 2xx; 'total_rev_pkts_inspected_status_code_non_5xx'= Total reverse
          packets inspected status code non 5xx; 'curr_req'= Current requests;
          'total_req'= Total requests; 'total_req_succ'= Total requests success;
          'peak_conn'= Peak connections; 'response_time'= Response time;
          'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response
          time; 'curr_ssl_conn'= Current SSL connections; 'total_ssl_conn'= Total SSL
          connections; 'curr_conn_overflow'= Current connection counter overflow count;
          'state_flaps'= State flaps count;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "Field state"
                type: str
            hm_key:
                description:
                - "Field hm_key"
                type: int
            hm_index:
                description:
                - "Field hm_index"
                type: int
            drs_list:
                description:
                - "Field drs_list"
                type: list
            alt_list:
                description:
                - "Field alt_list"
                type: list
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current connections"
                type: str
            total_fwd_bytes:
                description:
                - "Total forward bytes"
                type: str
            total_fwd_pkts:
                description:
                - "Total forward packets"
                type: str
            total_rev_bytes:
                description:
                - "Total reverse bytes"
                type: str
            total_rev_pkts:
                description:
                - "Total reverse packets"
                type: str
            total_conn:
                description:
                - "Total connections"
                type: str
            total_rev_pkts_inspected:
                description:
                - "Total reverse packets inspected"
                type: str
            total_rev_pkts_inspected_status_code_2xx:
                description:
                - "Total reverse packets inspected status code 2xx"
                type: str
            total_rev_pkts_inspected_status_code_non_5xx:
                description:
                - "Total reverse packets inspected status code non 5xx"
                type: str
            curr_req:
                description:
                - "Current requests"
                type: str
            total_req:
                description:
                - "Total requests"
                type: str
            total_req_succ:
                description:
                - "Total requests success"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            response_time:
                description:
                - "Response time"
                type: str
            fastest_rsp_time:
                description:
                - "Fastest response time"
                type: str
            slowest_rsp_time:
                description:
                - "Slowest response time"
                type: str
            curr_ssl_conn:
                description:
                - "Current SSL connections"
                type: str
            total_ssl_conn:
                description:
                - "Total SSL connections"
                type: str
            curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
                type: str
            state_flaps:
                description:
                - "State flaps count"
                type: str
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int

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
    "name",
    "oper",
    "packet_capture_template",
    "port",
    "sampling_enable",
    "stats",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'port': {
            'type': 'int',
            'required': True,
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'curr_conn', 'total_fwd_bytes', 'total_fwd_pkts',
                    'total_rev_bytes', 'total_rev_pkts', 'total_conn',
                    'total_rev_pkts_inspected',
                    'total_rev_pkts_inspected_status_code_2xx',
                    'total_rev_pkts_inspected_status_code_non_5xx', 'curr_req',
                    'total_req', 'total_req_succ', 'peak_conn',
                    'response_time', 'fastest_rsp_time', 'slowest_rsp_time',
                    'curr_ssl_conn', 'total_ssl_conn', 'curr_conn_overflow',
                    'state_flaps'
                ]
            }
        },
        'packet_capture_template': {
            'type': 'str',
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['UP', 'DOWN', 'MAINTENANCE']
            },
            'hm_key': {
                'type': 'int',
            },
            'hm_index': {
                'type': 'int',
            },
            'drs_list': {
                'type': 'list',
                'drs_name': {
                    'type': 'str',
                },
                'drs_state': {
                    'type': 'str',
                },
                'drs_hm_key': {
                    'type': 'int',
                },
                'drs_hm_index': {
                    'type': 'int',
                },
                'drs_port': {
                    'type': 'int',
                },
                'drs_priority': {
                    'type': 'int',
                },
                'drs_curr_conn': {
                    'type': 'int',
                },
                'drs_pers_conn': {
                    'type': 'int',
                },
                'drs_total_conn': {
                    'type': 'int',
                },
                'drs_curr_req': {
                    'type': 'int',
                },
                'drs_total_req': {
                    'type': 'int',
                },
                'drs_total_req_succ': {
                    'type': 'int',
                },
                'drs_rev_pkts': {
                    'type': 'int',
                },
                'drs_fwd_pkts': {
                    'type': 'int',
                },
                'drs_rev_bts': {
                    'type': 'int',
                },
                'drs_fwd_bts': {
                    'type': 'int',
                },
                'drs_peak_conn': {
                    'type': 'int',
                },
                'drs_rsp_time': {
                    'type': 'int',
                },
                'drs_frsp_time': {
                    'type': 'int',
                },
                'drs_srsp_time': {
                    'type': 'int',
                }
            },
            'alt_list': {
                'type': 'list',
                'alt_name': {
                    'type': 'str',
                },
                'alt_port': {
                    'type': 'int',
                },
                'alt_state': {
                    'type': 'str',
                },
                'alt_curr_conn': {
                    'type': 'int',
                },
                'alt_total_conn': {
                    'type': 'int',
                },
                'alt_rev_pkts': {
                    'type': 'int',
                },
                'alt_fwd_pkts': {
                    'type': 'int',
                },
                'alt_peak_conn': {
                    'type': 'int',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'curr_conn': {
                'type': 'str',
            },
            'total_fwd_bytes': {
                'type': 'str',
            },
            'total_fwd_pkts': {
                'type': 'str',
            },
            'total_rev_bytes': {
                'type': 'str',
            },
            'total_rev_pkts': {
                'type': 'str',
            },
            'total_conn': {
                'type': 'str',
            },
            'total_rev_pkts_inspected': {
                'type': 'str',
            },
            'total_rev_pkts_inspected_status_code_2xx': {
                'type': 'str',
            },
            'total_rev_pkts_inspected_status_code_non_5xx': {
                'type': 'str',
            },
            'curr_req': {
                'type': 'str',
            },
            'total_req': {
                'type': 'str',
            },
            'total_req_succ': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'str',
            },
            'response_time': {
                'type': 'str',
            },
            'fastest_rsp_time': {
                'type': 'str',
            },
            'slowest_rsp_time': {
                'type': 'str',
            },
            'curr_ssl_conn': {
                'type': 'str',
            },
            'total_ssl_conn': {
                'type': 'str',
            },
            'curr_conn_overflow': {
                'type': 'str',
            },
            'state_flaps': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            }
        }
    })
    # Parent keys
    rv.update(dict(service_group_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]
    if '/' in str(module.params["port"]):
        f_dict["port"] = module.params["port"].replace("/", "%2F")
    else:
        f_dict["port"] = module.params["port"]
    if '/' in module.params["service_group_name"]:
        f_dict["service_group_name"] = module.params[
            "service_group_name"].replace("/", "%2F")
    else:
        f_dict["service_group_name"] = module.params["service_group_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    f_dict["name"] = ""
    f_dict["port"] = ""
    f_dict["service_group_name"] = module.params["service_group_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["member"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["member"].get(k) != v:
            change_results["changed"] = True
            config_changes["member"][k] = v

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
    payload = utils.build_json("member", module.params, AVAILABLE_PROPERTIES)
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
                    "member"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "member-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["member"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["member"][
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
