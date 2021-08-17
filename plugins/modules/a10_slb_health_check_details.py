#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_health_check_details
description:
    - Display Health Monitor Information for a given PIN and PID
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
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            pin_id:
                description:
                - "Field pin_id"
                type: int
            process_index:
                description:
                - "Field process_index"
                type: int
            health_state:
                description:
                - "Field health_state"
                type: str
            state_reason:
                description:
                - "Field state_reason"
                type: str
            monitor_name:
                description:
                - "Field monitor_name"
                type: str
            received_success:
                description:
                - "Field received_success"
                type: int
            received_fail:
                description:
                - "Field received_fail"
                type: int
            response_timeout:
                description:
                - "Field response_timeout"
                type: int
            curr_interval:
                description:
                - "Field curr_interval"
                type: int
            method:
                description:
                - "Field method"
                type: str
            attr_alias_addr:
                description:
                - "Field attr_alias_addr"
                type: str
            attr_port:
                description:
                - "Field attr_port"
                type: int
            half_open:
                description:
                - "Field half_open"
                type: int
            send:
                description:
                - "Field send"
                type: str
            resp_cont:
                description:
                - "Field resp_cont"
                type: str
            force_up:
                description:
                - "Field force_up"
                type: int
            url:
                description:
                - "Field url"
                type: str
            expect_text:
                description:
                - "Field expect_text"
                type: str
            expect_resp_code:
                description:
                - "Field expect_resp_code"
                type: str
            expect_text_regex:
                description:
                - "Field expect_text_regex"
                type: str
            expect_resp_regex_code:
                description:
                - "Field expect_resp_regex_code"
                type: str
            maintenance_code:
                description:
                - "Field maintenance_code"
                type: str
            user:
                description:
                - "Field user"
                type: str
            pass:
                description:
                - "Field pass"
                type: str
            postdata:
                description:
                - "Field postdata"
                type: str
            host:
                description:
                - "Field host"
                type: str
            kerberos_realm:
                description:
                - "Field kerberos_realm"
                type: str
            kerberos_kdc:
                description:
                - "Field kerberos_kdc"
                type: str
            kerberos_port:
                description:
                - "Field kerberos_port"
                type: int
            snmp_operation:
                description:
                - "Field snmp_operation"
                type: int
            community:
                description:
                - "Field community"
                type: str
            oid:
                description:
                - "Field oid"
                type: str
            domain:
                description:
                - "Field domain"
                type: str
            starttls:
                description:
                - "Field starttls"
                type: int
            mail_from:
                description:
                - "Field mail_from"
                type: str
            rcpt_to:
                description:
                - "Field rcpt_to"
                type: str
            ipaddr:
                description:
                - "Field ipaddr"
                type: str
            dns_qtype:
                description:
                - "Field dns_qtype"
                type: int
            dns_recurse:
                description:
                - "Field dns_recurse"
                type: int
            dns_expect_type:
                description:
                - "Field dns_expect_type"
                type: int
            dns_expect:
                description:
                - "Field dns_expect"
                type: str
            transport_proto:
                description:
                - "Field transport_proto"
                type: int
            sip_register:
                description:
                - "Field sip_register"
                type: int
            secret:
                description:
                - "Field secret"
                type: str
            query:
                description:
                - "Field query"
                type: str
            base_dn:
                description:
                - "Field base_dn"
                type: str
            ldap_ssl:
                description:
                - "Field ldap_ssl"
                type: int
            ldap_tls:
                description:
                - "Field ldap_tls"
                type: int
            attr_type:
                description:
                - "Field attr_type"
                type: str
            db_name:
                description:
                - "Field db_name"
                type: str
            receive:
                description:
                - "Field receive"
                type: str
            rcv_integer:
                description:
                - "Field rcv_integer"
                type: int
            db_row:
                description:
                - "Field db_row"
                type: int
            db_column:
                description:
                - "Field db_column"
                type: int
            pname:
                description:
                - "Field pname"
                type: str
            tcp_only:
                description:
                - "Field tcp_only"
                type: int
            attr_program:
                description:
                - "Field attr_program"
                type: str
            arguments:
                description:
                - "Field arguments"
                type: str
            attr_rpn:
                description:
                - "Field attr_rpn"
                type: str
            http_wait_resp:
                description:
                - "Field http_wait_resp"
                type: int
            l4_conn_num:
                description:
                - "Field l4_conn_num"
                type: int
            l4_errors:
                description:
                - "Field l4_errors"
                type: int
            avg_rtt:
                description:
                - "Field avg_rtt"
                type: int
            curr_rtt:
                description:
                - "Field curr_rtt"
                type: int
            avg_tcp_rtt:
                description:
                - "Field avg_tcp_rtt"
                type: int
            curr_tcp_rtt:
                description:
                - "Field curr_tcp_rtt"
                type: int
            status_code_rcv:
                description:
                - "Field status_code_rcv"
                type: int
            http_req_sent:
                description:
                - "Field http_req_sent"
                type: int
            http_errors:
                description:
                - "Field http_errors"
                type: int
            mac_addr:
                description:
                - "Field mac_addr"
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

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
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
        'oper': {
            'type': 'dict',
            'pin_id': {
                'type': 'int',
            },
            'process_index': {
                'type': 'int',
            },
            'health_state': {
                'type': 'str',
            },
            'state_reason': {
                'type': 'str',
            },
            'monitor_name': {
                'type': 'str',
            },
            'received_success': {
                'type': 'int',
            },
            'received_fail': {
                'type': 'int',
            },
            'response_timeout': {
                'type': 'int',
            },
            'curr_interval': {
                'type': 'int',
            },
            'method': {
                'type': 'str',
            },
            'attr_alias_addr': {
                'type': 'str',
            },
            'attr_port': {
                'type': 'int',
            },
            'half_open': {
                'type': 'int',
            },
            'send': {
                'type': 'str',
            },
            'resp_cont': {
                'type': 'str',
            },
            'force_up': {
                'type': 'int',
            },
            'url': {
                'type': 'str',
            },
            'expect_text': {
                'type': 'str',
            },
            'expect_resp_code': {
                'type': 'str',
            },
            'expect_text_regex': {
                'type': 'str',
            },
            'expect_resp_regex_code': {
                'type': 'str',
            },
            'maintenance_code': {
                'type': 'str',
            },
            'user': {
                'type': 'str',
            },
            'pass': {
                'type': 'str',
            },
            'postdata': {
                'type': 'str',
            },
            'host': {
                'type': 'str',
            },
            'kerberos_realm': {
                'type': 'str',
            },
            'kerberos_kdc': {
                'type': 'str',
            },
            'kerberos_port': {
                'type': 'int',
            },
            'snmp_operation': {
                'type': 'int',
            },
            'community': {
                'type': 'str',
            },
            'oid': {
                'type': 'str',
            },
            'domain': {
                'type': 'str',
            },
            'starttls': {
                'type': 'int',
            },
            'mail_from': {
                'type': 'str',
            },
            'rcpt_to': {
                'type': 'str',
            },
            'ipaddr': {
                'type': 'str',
            },
            'dns_qtype': {
                'type': 'int',
            },
            'dns_recurse': {
                'type': 'int',
            },
            'dns_expect_type': {
                'type': 'int',
            },
            'dns_expect': {
                'type': 'str',
            },
            'transport_proto': {
                'type': 'int',
            },
            'sip_register': {
                'type': 'int',
            },
            'secret': {
                'type': 'str',
            },
            'query': {
                'type': 'str',
            },
            'base_dn': {
                'type': 'str',
            },
            'ldap_ssl': {
                'type': 'int',
            },
            'ldap_tls': {
                'type': 'int',
            },
            'attr_type': {
                'type': 'str',
            },
            'db_name': {
                'type': 'str',
            },
            'receive': {
                'type': 'str',
            },
            'rcv_integer': {
                'type': 'int',
            },
            'db_row': {
                'type': 'int',
            },
            'db_column': {
                'type': 'int',
            },
            'pname': {
                'type': 'str',
            },
            'tcp_only': {
                'type': 'int',
            },
            'attr_program': {
                'type': 'str',
            },
            'arguments': {
                'type': 'str',
            },
            'attr_rpn': {
                'type': 'str',
            },
            'http_wait_resp': {
                'type': 'int',
            },
            'l4_conn_num': {
                'type': 'int',
            },
            'l4_errors': {
                'type': 'int',
            },
            'avg_rtt': {
                'type': 'int',
            },
            'curr_rtt': {
                'type': 'int',
            },
            'avg_tcp_rtt': {
                'type': 'int',
            },
            'curr_tcp_rtt': {
                'type': 'int',
            },
            'status_code_rcv': {
                'type': 'int',
            },
            'http_req_sent': {
                'type': 'int',
            },
            'http_errors': {
                'type': 'int',
            },
            'mac_addr': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/health-check-details"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


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


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


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
    url_base = "/axapi/v3/slb/health-check-details"

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


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result):
    try:
        call_result = _post(module, new_url(module))
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


def update(module, result, existing_config):
    try:
        call_result = _post(module, existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)


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
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
