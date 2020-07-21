#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_l7session
description:
    - Configure l7session
short_description: Configures A10 slb.l7session
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            l7_cpu_list:
                description:
                - "Field l7_cpu_list"
            cpu_count:
                description:
                - "Field cpu_count"
    sampling_enable:
        description:
        - "Field sampling_enable"
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
          Fwd req fail - server; 'hps_fwdreq_fail_tuple'= Fwd req fail - tuple;"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            server_fin:
                description:
                - "FIN from server"
            data_cb_failed:
                description:
                - "Data event callback fail"
            server_rst:
                description:
                - "RST from server"
            err_event:
                description:
                - "Err event from TCP"
            total_proxy:
                description:
                - "Total proxy conn"
            start_server_conn_succ:
                description:
                - "Start Server Conn Success"
            curr_proxy:
                description:
                - "Curr proxy conn"
            wbuf_event:
                description:
                - "Wbuf event from TCP"
            data_event:
                description:
                - "Data event from TCP"
            wbuf_cb_failed:
                description:
                - "Wbuf event callback failed"
            client_rst:
                description:
                - "RST from client"
            err_cb_failed:
                description:
                - "Err event callback failed"
            client_fin:
                description:
                - "FIN from client"
            server_select_fail:
                description:
                - "Server selection fail"
            server_conn_failed:
                description:
                - "Server connection failed"
            hps_fwdreq_fail:
                description:
                - "Fwd req fail"
            conn_not_exist:
                description:
                - "Conn does not exist"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "sampling_enable",
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'oper': {
            'type': 'dict',
            'l7_cpu_list': {
                'type': 'list',
                'curr_proxy_client': {
                    'type': 'int',
                },
                'proxy_v2_connection': {
                    'type': 'int',
                },
                'total_proxy': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_rport': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_persist': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_server': {
                    'type': 'int',
                },
                'client_rst_rsp': {
                    'type': 'int',
                },
                'client_rst': {
                    'type': 'int',
                },
                'hps_fwdreq_fail': {
                    'type': 'int',
                },
                'total_proxy_server': {
                    'type': 'int',
                },
                'est_event': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_buff': {
                    'type': 'int',
                },
                'start_server_conn_succ': {
                    'type': 'int',
                },
                'wbuf_event': {
                    'type': 'int',
                },
                'data_event': {
                    'type': 'int',
                },
                'client_rst_req': {
                    'type': 'int',
                },
                'err_cb_failed': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_tuple': {
                    'type': 'int',
                },
                'client_fin': {
                    'type': 'int',
                },
                'est_cb_failed': {
                    'type': 'int',
                },
                'server_rst': {
                    'type': 'int',
                },
                'total_proxy_es': {
                    'type': 'int',
                },
                'curr_proxy': {
                    'type': 'int',
                },
                'hps_fwdreq_fail_route': {
                    'type': 'int',
                },
                'client_rst_connected': {
                    'type': 'int',
                },
                'total_proxy_client': {
                    'type': 'int',
                },
                'server_fin': {
                    'type': 'int',
                },
                'err_event': {
                    'type': 'int',
                },
                'server_rst_rsp': {
                    'type': 'int',
                },
                'server_rst_req': {
                    'type': 'int',
                },
                'server_rst_connecting': {
                    'type': 'int',
                },
                'curr_proxy_es': {
                    'type': 'int',
                },
                'wbuf_cb_failed': {
                    'type': 'int',
                },
                'server_rst_connected': {
                    'type': 'int',
                },
                'server_conn_failed': {
                    'type': 'int',
                },
                'client_rst_connecting': {
                    'type': 'int',
                },
                'server_select_fail': {
                    'type': 'int',
                },
                'proxy_v1_connection': {
                    'type': 'int',
                },
                'curr_proxy_server': {
                    'type': 'int',
                },
                'data_cb_failed': {
                    'type': 'int',
                },
                'conn_not_exist': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'start_server_conn_succ', 'conn_not_exist',
                    'data_event', 'client_fin', 'server_fin', 'wbuf_event',
                    'wbuf_cb_failed', 'err_event', 'err_cb_failed',
                    'server_conn_failed', 'client_rst', 'server_rst',
                    'client_rst_req', 'client_rst_connecting',
                    'client_rst_connected', 'client_rst_rsp', 'server_rst_req',
                    'server_rst_connecting', 'server_rst_connected',
                    'server_rst_rsp', 'proxy_v1_connection',
                    'proxy_v2_connection', 'curr_proxy', 'curr_proxy_client',
                    'curr_proxy_server', 'curr_proxy_es', 'total_proxy',
                    'total_proxy_client', 'total_proxy_server',
                    'total_proxy_es', 'server_select_fail', 'est_event',
                    'est_cb_failed', 'data_cb_failed', 'hps_fwdreq_fail',
                    'hps_fwdreq_fail_buff', 'hps_fwdreq_fail_rport',
                    'hps_fwdreq_fail_route', 'hps_fwdreq_fail_persist',
                    'hps_fwdreq_fail_server', 'hps_fwdreq_fail_tuple'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'server_fin': {
                'type': 'str',
            },
            'data_cb_failed': {
                'type': 'str',
            },
            'server_rst': {
                'type': 'str',
            },
            'err_event': {
                'type': 'str',
            },
            'total_proxy': {
                'type': 'str',
            },
            'start_server_conn_succ': {
                'type': 'str',
            },
            'curr_proxy': {
                'type': 'str',
            },
            'wbuf_event': {
                'type': 'str',
            },
            'data_event': {
                'type': 'str',
            },
            'wbuf_cb_failed': {
                'type': 'str',
            },
            'client_rst': {
                'type': 'str',
            },
            'err_cb_failed': {
                'type': 'str',
            },
            'client_fin': {
                'type': 'str',
            },
            'server_select_fail': {
                'type': 'str',
            },
            'server_conn_failed': {
                'type': 'str',
            },
            'hps_fwdreq_fail': {
                'type': 'str',
            },
            'conn_not_exist': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/l7session"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


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
    url_base = "/axapi/v3/slb/l7session"

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
    if existing_config:
        for k, v in payload["l7session"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["l7session"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["l7session"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
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


def present(module, result, existing_config):
    payload = build_json("l7session", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
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
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
