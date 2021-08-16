#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_proxy
description:
    - Configure Proxy Global
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
                - "'all'= all; 'num'= Num; 'tcp_event'= TCP stack event; 'est_event'= Connection
          established; 'data_event'= Data received; 'client_fin'= Client FIN;
          'server_fin'= Server FIN; 'wbuf_event'= Ready to send data; 'err_event'= Error
          occured; 'no_mem'= No memory; 'client_rst'= Client RST; 'server_rst'= Server
          RST; 'queue_depth_over_limit'= Queue depth over limit; 'event_failed'= Event
          failed; 'conn_not_exist'= Conn not exist; 'service_alloc_cb'= Service alloc
          callback; 'service_alloc_cb_failed'= Service alloc callback failed;
          'service_free_cb'= Service free callback; 'service_free_cb_failed'= Service
          free callback failed; 'est_cb_failed'= App EST callback failed;
          'data_cb_failed'= App DATA callback failed; 'wbuf_cb_failed'= App WBUF callback
          failed; 'err_cb_failed'= App ERR callback failed; 'start_server_conn'= Start
          server conn; 'start_server_conn_succ'= Success; 'start_server_conn_no_route'=
          No route to server; 'start_server_conn_fail_mem'= No memory;
          'start_server_conn_fail_snat'= Failed Source NAT;
          'start_server_conn_fail_persist'= Fail Persistence;
          'start_server_conn_fail_server'= Fail Server issue;
          'start_server_conn_fail_tuple'= Fail Tuple Issue; 'line_too_long'= Line too
          long;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            tcp_event:
                description:
                - "TCP stack event"
                type: str
            est_event:
                description:
                - "Connection established"
                type: str
            data_event:
                description:
                - "Data received"
                type: str
            client_fin:
                description:
                - "Client FIN"
                type: str
            server_fin:
                description:
                - "Server FIN"
                type: str
            wbuf_event:
                description:
                - "Ready to send data"
                type: str
            err_event:
                description:
                - "Error occured"
                type: str
            no_mem:
                description:
                - "No memory"
                type: str
            client_rst:
                description:
                - "Client RST"
                type: str
            server_rst:
                description:
                - "Server RST"
                type: str
            queue_depth_over_limit:
                description:
                - "Queue depth over limit"
                type: str
            event_failed:
                description:
                - "Event failed"
                type: str
            conn_not_exist:
                description:
                - "Conn not exist"
                type: str
            service_alloc_cb:
                description:
                - "Service alloc callback"
                type: str
            service_alloc_cb_failed:
                description:
                - "Service alloc callback failed"
                type: str
            service_free_cb:
                description:
                - "Service free callback"
                type: str
            service_free_cb_failed:
                description:
                - "Service free callback failed"
                type: str
            est_cb_failed:
                description:
                - "App EST callback failed"
                type: str
            data_cb_failed:
                description:
                - "App DATA callback failed"
                type: str
            wbuf_cb_failed:
                description:
                - "App WBUF callback failed"
                type: str
            err_cb_failed:
                description:
                - "App ERR callback failed"
                type: str
            start_server_conn:
                description:
                - "Start server conn"
                type: str
            start_server_conn_succ:
                description:
                - "Success"
                type: str
            start_server_conn_no_route:
                description:
                - "No route to server"
                type: str
            start_server_conn_fail_mem:
                description:
                - "No memory"
                type: str
            start_server_conn_fail_snat:
                description:
                - "Failed Source NAT"
                type: str
            start_server_conn_fail_persist:
                description:
                - "Fail Persistence"
                type: str
            start_server_conn_fail_server:
                description:
                - "Fail Server issue"
                type: str
            start_server_conn_fail_tuple:
                description:
                - "Fail Tuple Issue"
                type: str
            line_too_long:
                description:
                - "Line too long"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
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
                    'all', 'num', 'tcp_event', 'est_event', 'data_event',
                    'client_fin', 'server_fin', 'wbuf_event', 'err_event',
                    'no_mem', 'client_rst', 'server_rst',
                    'queue_depth_over_limit', 'event_failed', 'conn_not_exist',
                    'service_alloc_cb', 'service_alloc_cb_failed',
                    'service_free_cb', 'service_free_cb_failed',
                    'est_cb_failed', 'data_cb_failed', 'wbuf_cb_failed',
                    'err_cb_failed', 'start_server_conn',
                    'start_server_conn_succ', 'start_server_conn_no_route',
                    'start_server_conn_fail_mem',
                    'start_server_conn_fail_snat',
                    'start_server_conn_fail_persist',
                    'start_server_conn_fail_server',
                    'start_server_conn_fail_tuple', 'line_too_long'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'tcp_event': {
                'type': 'str',
            },
            'est_event': {
                'type': 'str',
            },
            'data_event': {
                'type': 'str',
            },
            'client_fin': {
                'type': 'str',
            },
            'server_fin': {
                'type': 'str',
            },
            'wbuf_event': {
                'type': 'str',
            },
            'err_event': {
                'type': 'str',
            },
            'no_mem': {
                'type': 'str',
            },
            'client_rst': {
                'type': 'str',
            },
            'server_rst': {
                'type': 'str',
            },
            'queue_depth_over_limit': {
                'type': 'str',
            },
            'event_failed': {
                'type': 'str',
            },
            'conn_not_exist': {
                'type': 'str',
            },
            'service_alloc_cb': {
                'type': 'str',
            },
            'service_alloc_cb_failed': {
                'type': 'str',
            },
            'service_free_cb': {
                'type': 'str',
            },
            'service_free_cb_failed': {
                'type': 'str',
            },
            'est_cb_failed': {
                'type': 'str',
            },
            'data_cb_failed': {
                'type': 'str',
            },
            'wbuf_cb_failed': {
                'type': 'str',
            },
            'err_cb_failed': {
                'type': 'str',
            },
            'start_server_conn': {
                'type': 'str',
            },
            'start_server_conn_succ': {
                'type': 'str',
            },
            'start_server_conn_no_route': {
                'type': 'str',
            },
            'start_server_conn_fail_mem': {
                'type': 'str',
            },
            'start_server_conn_fail_snat': {
                'type': 'str',
            },
            'start_server_conn_fail_persist': {
                'type': 'str',
            },
            'start_server_conn_fail_server': {
                'type': 'str',
            },
            'start_server_conn_fail_tuple': {
                'type': 'str',
            },
            'line_too_long': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["proxy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["proxy"].get(k) != v:
            change_results["changed"] = True
            config_changes["proxy"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("proxy", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
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
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
