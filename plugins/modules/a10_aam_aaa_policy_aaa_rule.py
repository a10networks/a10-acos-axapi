#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_aaa_policy_aaa_rule
description:
    - Rules of AAA policy
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
    aaa_policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    index:
        description:
        - "Specify AAA rule index"
        type: int
        required: True
    uri:
        description:
        - "Field uri"
        type: list
        required: False
        suboptions:
            match_type:
                description:
                - "'contains'= Match URI if request URI contains specified URI; 'ends-with'= Match
          URI if request URI ends with specified URI; 'equals'= Match URI if request URI
          equals specified URI; 'starts-with'= Match URI if request URI starts with
          specified URI;"
                type: str
            uri_str:
                description:
                - "Specify URI string"
                type: str
    host:
        description:
        - "Field host"
        type: list
        required: False
        suboptions:
            host_match_type:
                description:
                - "'contains'= Match HOST if request HTTP HOST header contains specified hostname;
          'ends-with'= Match HOST if request HTTP HOST header ends with specified
          hostname; 'equals'= Match HOST if request HTTP HOST header equals specified
          hostname; 'starts-with'= Match HOST if request HTTP HOST header starts with
          specified hostname;"
                type: str
            host_str:
                description:
                - "Specify URI string"
                type: str
    port:
        description:
        - "Specify port number for aaa-rule, default is 0 for all port numbers"
        type: int
        required: False
    match_encoded_uri:
        description:
        - "Enable URL decoding for URI matching"
        type: bool
        required: False
    access_list:
        description:
        - "Field access_list"
        type: dict
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id"
                type: int
            acl_name:
                description:
                - "'ip-name'= Apply an IP named access list; 'ipv6-name'= Apply an IPv6 named
          access list;"
                type: str
            name:
                description:
                - "Specify Named Access List"
                type: str
    domain_name:
        description:
        - "Specify domain name to bind to the AAA rule (ex= a10networks.com,
          www.a10networks.com)"
        type: str
        required: False
    user_agent:
        description:
        - "Field user_agent"
        type: list
        required: False
        suboptions:
            user_agent_match_type:
                description:
                - "'contains'= Match request User-Agent header if it contains specified string;
          'ends-with'= Match request User-Agent header if it ends with specified string;
          'equals'= Match request User-Agent header if it equals specified string;
          'starts-with'= Match request User-Agent header if it starts with specified
          string;"
                type: str
            user_agent_str:
                description:
                - "Specify request User-Agent string"
                type: str
    action:
        description:
        - "'allow'= Allow traffic that matches this rule; 'deny'= Deny traffic that
          matches this rule;"
        type: str
        required: False
    authentication_template:
        description:
        - "Specify authentication template name to bind to the AAA rule"
        type: str
        required: False
    authorize_policy:
        description:
        - "Specify authorization policy to bind to the AAA rule"
        type: str
        required: False
    auth_failure_bypass:
        description:
        - "Forward client’s request even though authentication has failed"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total_count'= total_count; 'hit_deny'= hit_deny; 'hit_auth'=
          hit_auth; 'hit_bypass'= hit_bypass; 'failure_bypass'= failure_bypass;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            total_count:
                description:
                - "Field total_count"
                type: str
            hit_deny:
                description:
                - "Field hit_deny"
                type: str
            hit_auth:
                description:
                - "Field hit_auth"
                type: str
            hit_bypass:
                description:
                - "Field hit_bypass"
                type: str
            failure_bypass:
                description:
                - "Field failure_bypass"
                type: str
            index:
                description:
                - "Specify AAA rule index"
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
    "access_list",
    "action",
    "auth_failure_bypass",
    "authentication_template",
    "authorize_policy",
    "domain_name",
    "host",
    "index",
    "match_encoded_uri",
    "port",
    "sampling_enable",
    "stats",
    "uri",
    "user_agent",
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
        'index': {
            'type': 'int',
            'required': True,
        },
        'uri': {
            'type': 'list',
            'match_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with']
            },
            'uri_str': {
                'type': 'str',
            }
        },
        'host': {
            'type': 'list',
            'host_match_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with']
            },
            'host_str': {
                'type': 'str',
            }
        },
        'port': {
            'type': 'int',
        },
        'match_encoded_uri': {
            'type': 'bool',
        },
        'access_list': {
            'type': 'dict',
            'acl_id': {
                'type': 'int',
            },
            'acl_name': {
                'type': 'str',
                'choices': ['ip-name', 'ipv6-name']
            },
            'name': {
                'type': 'str',
            }
        },
        'domain_name': {
            'type': 'str',
        },
        'user_agent': {
            'type': 'list',
            'user_agent_match_type': {
                'type': 'str',
                'choices': ['contains', 'ends-with', 'equals', 'starts-with']
            },
            'user_agent_str': {
                'type': 'str',
            }
        },
        'action': {
            'type': 'str',
            'choices': ['allow', 'deny']
        },
        'authentication_template': {
            'type': 'str',
        },
        'authorize_policy': {
            'type': 'str',
        },
        'auth_failure_bypass': {
            'type': 'bool',
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
                    'all', 'total_count', 'hit_deny', 'hit_auth', 'hit_bypass',
                    'failure_bypass'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'total_count': {
                'type': 'str',
            },
            'hit_deny': {
                'type': 'str',
            },
            'hit_auth': {
                'type': 'str',
            },
            'hit_bypass': {
                'type': 'str',
            },
            'failure_bypass': {
                'type': 'str',
            },
            'index': {
                'type': 'int',
                'required': True,
            }
        }
    })
    # Parent keys
    rv.update(dict(aaa_policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/aaa-policy/{aaa_policy_name}/aaa-rule/{index}"

    f_dict = {}
    f_dict["index"] = module.params["index"]
    f_dict["aaa_policy_name"] = module.params["aaa_policy_name"]

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
    url_base = "/axapi/v3/aam/aaa-policy/{aaa_policy_name}/aaa-rule/{index}"

    f_dict = {}
    f_dict["index"] = ""
    f_dict["aaa_policy_name"] = module.params["aaa_policy_name"]

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
    for k, v in payload["aaa-rule"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["aaa-rule"].get(k) != v:
            change_results["changed"] = True
            config_changes["aaa-rule"][k] = v

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
    payload = build_json("aaa-rule", module)
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
