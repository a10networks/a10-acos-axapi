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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
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
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
    for k, v in payload["virtual-port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["virtual-port"].get(k) != v:
            change_results["changed"] = True
            config_changes["virtual-port"][k] = v

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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("virtual-port", module)
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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
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

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
