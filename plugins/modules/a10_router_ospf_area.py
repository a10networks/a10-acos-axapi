#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_ospf_area
description:
    - OSPF area parameters
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
    ospf_process_id:
        description:
        - Key to identify parent object
        type: str
        required: True
    area_ipv4:
        description:
        - "OSPF area ID in IP address format"
        type: str
        required: True
    area_num:
        description:
        - "OSPF area ID as a decimal value"
        type: int
        required: True
    auth_cfg:
        description:
        - "Field auth_cfg"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Enable authentication"
                type: bool
            message_digest:
                description:
                - "Use message-digest authentication"
                type: bool
    filter_lists:
        description:
        - "Field filter_lists"
        type: list
        required: False
        suboptions:
            filter_list:
                description:
                - "Filter networks between OSPF areas"
                type: bool
            acl_name:
                description:
                - "Filter networks by access-list (Name of an access-list)"
                type: str
            acl_direction:
                description:
                - "'in'= Filter networks sent to this area; 'out'= Filter networks sent from this
          area;"
                type: str
            plist_name:
                description:
                - "Filter networks by prefix-list (Name of an IP prefix-list)"
                type: str
            plist_direction:
                description:
                - "'in'= Filter networks sent to this area; 'out'= Filter networks sent from this
          area;"
                type: str
    nssa_cfg:
        description:
        - "Field nssa_cfg"
        type: dict
        required: False
        suboptions:
            nssa:
                description:
                - "Specify a NSSA area"
                type: bool
            no_redistribution:
                description:
                - "No redistribution into this NSSA area"
                type: bool
            no_summary:
                description:
                - "Do not send summary LSA into NSSA"
                type: bool
            translator_role:
                description:
                - "'always'= Translate always; 'candidate'= Candidate for translator (default);
          'never'= Do not translate;"
                type: str
            default_information_originate:
                description:
                - "Originate Type 7 default into NSSA area"
                type: bool
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
                type: int
            metric_type:
                description:
                - "OSPF metric type (OSPF metric type for default routes)"
                type: int
    default_cost:
        description:
        - "Set the summary-default cost of a NSSA or stub area (Stub's advertised default
          summary cost)"
        type: int
        required: False
    range_list:
        description:
        - "Field range_list"
        type: list
        required: False
        suboptions:
            area_range_prefix:
                description:
                - "Area range for IPv4 prefix"
                type: str
            option:
                description:
                - "'advertise'= Advertise this range (default); 'not-advertise'= DoNotAdvertise
          this range;"
                type: str
    shortcut:
        description:
        - "'default'= Set default shortcutting behavior; 'disable'= Disable shortcutting
          through the area; 'enable'= Enable shortcutting through the area;"
        type: str
        required: False
    stub_cfg:
        description:
        - "Field stub_cfg"
        type: dict
        required: False
        suboptions:
            stub:
                description:
                - "Configure OSPF area as stub"
                type: bool
            no_summary:
                description:
                - "Do not inject inter-area routes into area"
                type: bool
    virtual_link_list:
        description:
        - "Field virtual_link_list"
        type: list
        required: False
        suboptions:
            virtual_link_ip_addr:
                description:
                - "ID (IP addr) associated with virtual link neighbor"
                type: str
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
                type: bool
            hello_interval:
                description:
                - "Hello packet interval (Seconds)"
                type: int
            dead_interval:
                description:
                - "Dead router detection time (Seconds)"
                type: int
            retransmit_interval:
                description:
                - "LSA retransmit interval (Seconds)"
                type: int
            transmit_delay:
                description:
                - "LSA transmission delay (Seconds)"
                type: int
            virtual_link_authentication:
                description:
                - "Enable authentication"
                type: bool
            virtual_link_auth_type:
                description:
                - "'message-digest'= Use message-digest authentication; 'null'= Use null
          authentication;"
                type: str
            authentication_key:
                description:
                - "Set authentication key (Authentication key (8 chars))"
                type: str
            message_digest_key:
                description:
                - "Set message digest key (Key ID)"
                type: int
            md5:
                description:
                - "Use MD5 algorithm (Authentication key (16 chars))"
                type: str
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
    "area_ipv4",
    "area_num",
    "auth_cfg",
    "default_cost",
    "filter_lists",
    "nssa_cfg",
    "range_list",
    "shortcut",
    "stub_cfg",
    "uuid",
    "virtual_link_list",
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
        'area_ipv4': {
            'type': 'str',
            'required': True,
        },
        'area_num': {
            'type': 'int',
            'required': True,
        },
        'auth_cfg': {
            'type': 'dict',
            'authentication': {
                'type': 'bool',
            },
            'message_digest': {
                'type': 'bool',
            }
        },
        'filter_lists': {
            'type': 'list',
            'filter_list': {
                'type': 'bool',
            },
            'acl_name': {
                'type': 'str',
            },
            'acl_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            },
            'plist_name': {
                'type': 'str',
            },
            'plist_direction': {
                'type': 'str',
                'choices': ['in', 'out']
            }
        },
        'nssa_cfg': {
            'type': 'dict',
            'nssa': {
                'type': 'bool',
            },
            'no_redistribution': {
                'type': 'bool',
            },
            'no_summary': {
                'type': 'bool',
            },
            'translator_role': {
                'type': 'str',
                'choices': ['always', 'candidate', 'never']
            },
            'default_information_originate': {
                'type': 'bool',
            },
            'metric': {
                'type': 'int',
            },
            'metric_type': {
                'type': 'int',
            }
        },
        'default_cost': {
            'type': 'int',
        },
        'range_list': {
            'type': 'list',
            'area_range_prefix': {
                'type': 'str',
            },
            'option': {
                'type': 'str',
                'choices': ['advertise', 'not-advertise']
            }
        },
        'shortcut': {
            'type': 'str',
            'choices': ['default', 'disable', 'enable']
        },
        'stub_cfg': {
            'type': 'dict',
            'stub': {
                'type': 'bool',
            },
            'no_summary': {
                'type': 'bool',
            }
        },
        'virtual_link_list': {
            'type': 'list',
            'virtual_link_ip_addr': {
                'type': 'str',
            },
            'bfd': {
                'type': 'bool',
            },
            'hello_interval': {
                'type': 'int',
            },
            'dead_interval': {
                'type': 'int',
            },
            'retransmit_interval': {
                'type': 'int',
            },
            'transmit_delay': {
                'type': 'int',
            },
            'virtual_link_authentication': {
                'type': 'bool',
            },
            'virtual_link_auth_type': {
                'type': 'str',
                'choices': ['message-digest', 'null']
            },
            'authentication_key': {
                'type': 'str',
            },
            'message_digest_key': {
                'type': 'int',
            },
            'md5': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(ospf_process_id=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/area/{area-ipv4}+{area-num}"

    f_dict = {}
    f_dict["area-ipv4"] = module.params["area_ipv4"]
    f_dict["area-num"] = module.params["area_num"]
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

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
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/area/{area-ipv4}+{area-num}"

    f_dict = {}
    f_dict["area-ipv4"] = ""
    f_dict["area-num"] = ""
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

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
    for k, v in payload["area"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["area"].get(k) != v:
            change_results["changed"] = True
            config_changes["area"][k] = v

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
    payload = build_json("area", module)
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
