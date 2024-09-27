#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_l7session
description:
    - Configure l7session
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
                - "'all'= all; 'start_server_conn_succ'= Start Server Conn Success;
          'conn_not_exist'= Conn does not exist; 'data_event'= Data event from TCP;
          'client_fin'= FIN from client; 'server_fin'= FIN from server; 'wbuf_event'=
          Wbuf event from TCP; 'wbuf_cb_failed'= Wbuf event callback failed; 'err_event'=
          Err event from TCP; 'err_cb_failed'= Err event callback failed;
          'server_conn_failed'= Server connection failed; 'client_rst'= RST from client;
          'server_rst'= RST from server; 'client_rst_req'= RST from client - request;
          'client_rst_connecting'= RST from client - connecting; 'client_rst_connected'=
          RST from client - connected; 'client_rst_rsp'= RST from client - response;
          'server_rst_req'= RST from server - request; 'server_rst_connecting'= RST from
          server - connecting; 'server_rst_connected'= RST from server - connected;
          'server_rst_rsp'= RST from server - response; 'proxy_v1_connection'= counter
          for Proxy v1 connection; 'proxy_v2_connection'= counter for Proxy v2
          connection; 'curr_proxy'= Curr proxy conn; 'curr_proxy_client'= Curr proxy conn
          - client; 'curr_proxy_server'= Curr proxy conn - server; 'curr_proxy_es'= Curr
          proxy conn - ES; 'total_proxy'= Total proxy conn; 'total_proxy_client'= Total
          proxy conn - client; 'total_proxy_server'= Total proxy conn - server;
          'total_proxy_es'= Total proxy conn - ES; 'server_select_fail'= Server selection
          fail; 'est_event'= Est event from TCP; 'est_cb_failed'= Est event callback
          fail; 'data_cb_failed'= Data event callback fail; 'hps_fwdreq_fail'= Fwd req
          fail; 'hps_fwdreq_fail_buff'= Fwd req fail - buff; 'hps_fwdreq_fail_rport'= Fwd
          req fail - rport; 'hps_fwdreq_fail_route'= Fwd req fail - route;
          'hps_fwdreq_fail_persist'= Fwd req fail - persist; 'hps_fwdreq_fail_server'=
          Fwd req fail - server; 'hps_fwdreq_fail_tuple'= Fwd req fail - tuple;
          'udp_data_event'= Data event from UDP; 'transaction_cleaned'= Transaction
          cleaned - tuple; 'old_server_cleaned'= Old server cleaned - tuple;
          'server_not_cleaned'= Server not cleaned - tuple; 'client_not_cleaned'= Client
          not cleaned - tuple; 'invalid_server'= Invalid server - tuple;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            start_server_conn_succ:
                description:
                - "Start Server Conn Success"
                type: str
            conn_not_exist:
                description:
                - "Conn does not exist"
                type: str
            data_event:
                description:
                - "Data event from TCP"
                type: str
            client_fin:
                description:
                - "FIN from client"
                type: str
            server_fin:
                description:
                - "FIN from server"
                type: str
            wbuf_event:
                description:
                - "Wbuf event from TCP"
                type: str
            wbuf_cb_failed:
                description:
                - "Wbuf event callback failed"
                type: str
            err_event:
                description:
                - "Err event from TCP"
                type: str
            err_cb_failed:
                description:
                - "Err event callback failed"
                type: str
            server_conn_failed:
                description:
                - "Server connection failed"
                type: str
            client_rst:
                description:
                - "RST from client"
                type: str
            server_rst:
                description:
                - "RST from server"
                type: str
            curr_proxy:
                description:
                - "Curr proxy conn"
                type: str
            total_proxy:
                description:
                - "Total proxy conn"
                type: str
            server_select_fail:
                description:
                - "Server selection fail"
                type: str
            data_cb_failed:
                description:
                - "Data event callback fail"
                type: str
            hps_fwdreq_fail:
                description:
                - "Fwd req fail"
                type: str
            udp_data_event:
                description:
                - "Data event from UDP"
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
                    'all', 'start_server_conn_succ', 'conn_not_exist', 'data_event', 'client_fin', 'server_fin', 'wbuf_event', 'wbuf_cb_failed', 'err_event', 'err_cb_failed', 'server_conn_failed', 'client_rst', 'server_rst', 'client_rst_req', 'client_rst_connecting', 'client_rst_connected', 'client_rst_rsp', 'server_rst_req',
                    'server_rst_connecting', 'server_rst_connected', 'server_rst_rsp', 'proxy_v1_connection', 'proxy_v2_connection', 'curr_proxy', 'curr_proxy_client', 'curr_proxy_server', 'curr_proxy_es', 'total_proxy', 'total_proxy_client', 'total_proxy_server', 'total_proxy_es', 'server_select_fail', 'est_event', 'est_cb_failed',
                    'data_cb_failed', 'hps_fwdreq_fail', 'hps_fwdreq_fail_buff', 'hps_fwdreq_fail_rport', 'hps_fwdreq_fail_route', 'hps_fwdreq_fail_persist', 'hps_fwdreq_fail_server', 'hps_fwdreq_fail_tuple', 'udp_data_event', 'transaction_cleaned', 'old_server_cleaned', 'server_not_cleaned', 'client_not_cleaned', 'invalid_server'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'start_server_conn_succ': {
                'type': 'str',
                },
            'conn_not_exist': {
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
            'wbuf_cb_failed': {
                'type': 'str',
                },
            'err_event': {
                'type': 'str',
                },
            'err_cb_failed': {
                'type': 'str',
                },
            'server_conn_failed': {
                'type': 'str',
                },
            'client_rst': {
                'type': 'str',
                },
            'server_rst': {
                'type': 'str',
                },
            'curr_proxy': {
                'type': 'str',
                },
            'total_proxy': {
                'type': 'str',
                },
            'server_select_fail': {
                'type': 'str',
                },
            'data_cb_failed': {
                'type': 'str',
                },
            'hps_fwdreq_fail': {
                'type': 'str',
                },
            'udp_data_event': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/l7session"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/l7session"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["l7session"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["l7session"].get(k) != v:
            change_results["changed"] = True
            config_changes["l7session"][k] = v

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
    payload = utils.build_json("l7session", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l7session"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l7session-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l7session"]["stats"] if info != "NotFound" else info
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
