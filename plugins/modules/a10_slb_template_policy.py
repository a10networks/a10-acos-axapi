#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_template_policy
description:
    - Policy config
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
        - "Policy template name"
        type: str
        required: True
    bw_list_name:
        description:
        - "Specify a blacklist/whitelist name"
        type: str
        required: False
    timeout:
        description:
        - "Define timeout value of PBSLB dynamic entry (Timeout value (minute, default is
          5))"
        type: int
        required: False
    use_destination_ip:
        description:
        - "Use destination IP to match the policy"
        type: bool
        required: False
    over_limit:
        description:
        - "Specify operation in case over limit"
        type: bool
        required: False
    over_limit_reset:
        description:
        - "Reset the connection when it exceeds limit"
        type: bool
        required: False
    over_limit_lockup:
        description:
        - "Don't accept any new connection for certain time (Lockup duration (minute))"
        type: int
        required: False
    over_limit_logging:
        description:
        - "Log a message"
        type: bool
        required: False
    interval:
        description:
        - "Log interval (minute)"
        type: int
        required: False
    bw_list_id:
        description:
        - "Field bw_list_id"
        type: list
        required: False
        suboptions:
            id:
                description:
                - "Specify id that maps to service group (The id number)"
                type: int
            service_group:
                description:
                - "Specify a service group (Specify the service group name)"
                type: str
            pbslb_logging:
                description:
                - "Configure PBSLB logging"
                type: bool
            pbslb_interval:
                description:
                - "Specify logging interval in minutes"
                type: int
            fail:
                description:
                - "Only log unsuccessful connections"
                type: bool
            bw_list_action:
                description:
                - "'drop'= drop the packet; 'reset'= Send reset back;"
                type: str
            logging_drp_rst:
                description:
                - "Configure PBSLB logging"
                type: bool
            action_interval:
                description:
                - "Specify logging interval in minute (default is 3)"
                type: int
    overlap:
        description:
        - "Use overlap mode for geo-location to do longest match"
        type: bool
        required: False
    share:
        description:
        - "Share counters between virtual ports and virtual servers"
        type: bool
        required: False
    full_domain_tree:
        description:
        - "Share counters between geo-location and sub regions"
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
                - "'all'= all; 'fwd-policy-dns-unresolved'= Forward-policy unresolved DNS queries;
          'fwd-policy-dns-outstanding'= Forward-policy current DNS outstanding requests;
          'fwd-policy-snat-fail'= Forward-policy source-nat translation failure; 'fwd-
          policy-hits'= Number of forward-policy requests for this policy template; 'fwd-
          policy-forward-to-internet'= Number of forward-policy requests forwarded to
          internet; 'fwd-policy-forward-to-service-group'= Number of forward-policy
          requests forwarded to service group; 'fwd-policy-forward-to-proxy'= Number of
          forward-policy requests forwarded to proxy; 'fwd-policy-policy-drop'= Number of
          forward-policy requests dropped; 'fwd-policy-source-match-not-found'= Forward-
          policy requests without matching source rule; 'exp-client-hello-not-found'=
          Expected Client HELLO requests not found;"
                type: str
    class_list:
        description:
        - "Field class_list"
        type: dict
        required: False
        suboptions:
            name:
                description:
                - "Class list name or geo-location-class-list name"
                type: str
            client_ip_l3_dest:
                description:
                - "Use destination IP as client IP address"
                type: bool
            client_ip_l7_header:
                description:
                - "Use extract client IP address from L7 header"
                type: bool
            header_name:
                description:
                - "Specify L7 header name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            lid_list:
                description:
                - "Field lid_list"
                type: list
    forward_policy:
        description:
        - "Field forward_policy"
        type: dict
        required: False
        suboptions:
            no_client_conn_reuse:
                description:
                - "Inspects only first request of a connection"
                type: bool
            acos_event_log:
                description:
                - "Enable acos event logging"
                type: bool
            local_logging:
                description:
                - "Enable local logging"
                type: bool
            require_web_category:
                description:
                - "Wait for web category to be resolved before taking proxy decision"
                type: bool
            filtering:
                description:
                - "Field filtering"
                type: list
            san_filtering:
                description:
                - "Field san_filtering"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            action_list:
                description:
                - "Field action_list"
                type: list
            source_list:
                description:
                - "Field source_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            fwd_policy_dns_unresolved:
                description:
                - "Forward-policy unresolved DNS queries"
                type: str
            fwd_policy_dns_outstanding:
                description:
                - "Forward-policy current DNS outstanding requests"
                type: str
            fwd_policy_snat_fail:
                description:
                - "Forward-policy source-nat translation failure"
                type: str
            fwd_policy_hits:
                description:
                - "Number of forward-policy requests for this policy template"
                type: str
            fwd_policy_forward_to_internet:
                description:
                - "Number of forward-policy requests forwarded to internet"
                type: str
            fwd_policy_forward_to_service_group:
                description:
                - "Number of forward-policy requests forwarded to service group"
                type: str
            fwd_policy_forward_to_proxy:
                description:
                - "Number of forward-policy requests forwarded to proxy"
                type: str
            fwd_policy_policy_drop:
                description:
                - "Number of forward-policy requests dropped"
                type: str
            fwd_policy_source_match_not_found:
                description:
                - "Forward-policy requests without matching source rule"
                type: str
            exp_client_hello_not_found:
                description:
                - "Expected Client HELLO requests not found"
                type: str
            name:
                description:
                - "Policy template name"
                type: str
            forward_policy:
                description:
                - "Field forward_policy"
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
AVAILABLE_PROPERTIES = ["bw_list_id", "bw_list_name", "class_list", "forward_policy", "full_domain_tree", "interval", "name", "over_limit", "over_limit_lockup", "over_limit_logging", "over_limit_reset", "overlap", "sampling_enable", "share", "stats", "timeout", "use_destination_ip", "user_tag", "uuid", ]


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
    rv.update({'name': {'type': 'str', 'required': True, },
        'bw_list_name': {'type': 'str', },
        'timeout': {'type': 'int', },
        'use_destination_ip': {'type': 'bool', },
        'over_limit': {'type': 'bool', },
        'over_limit_reset': {'type': 'bool', },
        'over_limit_lockup': {'type': 'int', },
        'over_limit_logging': {'type': 'bool', },
        'interval': {'type': 'int', },
        'bw_list_id': {'type': 'list', 'id': {'type': 'int', }, 'service_group': {'type': 'str', }, 'pbslb_logging': {'type': 'bool', }, 'pbslb_interval': {'type': 'int', }, 'fail': {'type': 'bool', }, 'bw_list_action': {'type': 'str', 'choices': ['drop', 'reset']}, 'logging_drp_rst': {'type': 'bool', }, 'action_interval': {'type': 'int', }},
        'overlap': {'type': 'bool', },
        'share': {'type': 'bool', },
        'full_domain_tree': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'fwd-policy-dns-unresolved', 'fwd-policy-dns-outstanding', 'fwd-policy-snat-fail', 'fwd-policy-hits', 'fwd-policy-forward-to-internet', 'fwd-policy-forward-to-service-group', 'fwd-policy-forward-to-proxy', 'fwd-policy-policy-drop', 'fwd-policy-source-match-not-found', 'exp-client-hello-not-found']}},
        'class_list': {'type': 'dict', 'name': {'type': 'str', }, 'client_ip_l3_dest': {'type': 'bool', }, 'client_ip_l7_header': {'type': 'bool', }, 'header_name': {'type': 'str', }, 'uuid': {'type': 'str', }, 'lid_list': {'type': 'list', 'lidnum': {'type': 'int', 'required': True, }, 'conn_limit': {'type': 'int', }, 'conn_rate_limit': {'type': 'int', }, 'conn_per': {'type': 'int', }, 'request_limit': {'type': 'int', }, 'request_rate_limit': {'type': 'int', }, 'request_per': {'type': 'int', }, 'bw_rate_limit': {'type': 'int', }, 'bw_per': {'type': 'int', }, 'over_limit_action': {'type': 'bool', }, 'action_value': {'type': 'str', 'choices': ['forward', 'reset']}, 'lockout': {'type': 'int', }, 'log': {'type': 'bool', }, 'interval': {'type': 'int', }, 'direct_action': {'type': 'bool', }, 'direct_service_group': {'type': 'str', }, 'direct_pbslb_logging': {'type': 'bool', }, 'direct_pbslb_interval': {'type': 'int', }, 'direct_fail': {'type': 'bool', }, 'direct_action_value': {'type': 'str', 'choices': ['drop', 'reset']}, 'direct_logging_drp_rst': {'type': 'bool', }, 'direct_action_interval': {'type': 'int', }, 'response_code_rate_limit': {'type': 'list', 'code_range_start': {'type': 'int', }, 'code_range_end': {'type': 'int', }, 'threshold': {'type': 'int', }, 'period': {'type': 'int', }}, 'dns64': {'type': 'dict', 'disable': {'type': 'bool', }, 'exclusive_answer': {'type': 'bool', }, 'prefix': {'type': 'str', }}, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }}},
        'forward_policy': {'type': 'dict', 'no_client_conn_reuse': {'type': 'bool', }, 'acos_event_log': {'type': 'bool', }, 'local_logging': {'type': 'bool', }, 'require_web_category': {'type': 'bool', }, 'filtering': {'type': 'list', 'ssli_url_filtering': {'type': 'str', 'choices': ['bypassed-sni-disable', 'intercepted-sni-enable', 'intercepted-http-disable', 'no-sni-allow']}}, 'san_filtering': {'type': 'list', 'ssli_url_filtering_san': {'type': 'str', 'choices': ['enable-san', 'bypassed-san-disable', 'intercepted-san-enable', 'no-san-allow']}}, 'uuid': {'type': 'str', }, 'action_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'action1': {'type': 'str', 'choices': ['forward-to-internet', 'forward-to-service-group', 'forward-to-proxy', 'drop']}, 'fake_sg': {'type': 'str', }, 'real_sg': {'type': 'str', }, 'forward_snat': {'type': 'str', }, 'fall_back': {'type': 'str', }, 'fall_back_snat': {'type': 'str', }, 'proxy_chaining': {'type': 'bool', }, 'proxy_chaining_bypass': {'type': 'bool', }, 'support_cert_fetch': {'type': 'bool', }, 'log': {'type': 'bool', }, 'drop_response_code': {'type': 'int', }, 'drop_message': {'type': 'str', }, 'drop_redirect_url': {'type': 'str', }, 'http_status_code': {'type': 'str', 'choices': ['301', '302']}, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits']}}}, 'source_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'match_class_list': {'type': 'str', }, 'match_any': {'type': 'bool', }, 'match_authorize_policy': {'type': 'str', }, 'priority': {'type': 'int', }, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits', 'destination-match-not-found', 'no-host-info']}}, 'destination': {'type': 'dict', 'class_list_list': {'type': 'list', 'dest_class_list': {'type': 'str', 'required': True, }, 'action': {'type': 'str', }, 'ntype': {'type': 'str', 'choices': ['host', 'url', 'ip']}, 'priority': {'type': 'int', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits']}}}, 'web_reputation_scope_list': {'type': 'list', 'web_reputation_scope': {'type': 'str', 'required': True, }, 'action': {'type': 'str', }, 'ntype': {'type': 'str', 'choices': ['host', 'url']}, 'priority': {'type': 'int', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits']}}}, 'web_category_list_list': {'type': 'list', 'web_category_list': {'type': 'str', 'required': True, }, 'action': {'type': 'str', }, 'ntype': {'type': 'str', 'choices': ['host', 'url']}, 'priority': {'type': 'int', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits']}}}, 'any': {'type': 'dict', 'action': {'type': 'str', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hits']}}}}}},
        'stats': {'type': 'dict', 'fwd_policy_dns_unresolved': {'type': 'str', }, 'fwd_policy_dns_outstanding': {'type': 'str', }, 'fwd_policy_snat_fail': {'type': 'str', }, 'fwd_policy_hits': {'type': 'str', }, 'fwd_policy_forward_to_internet': {'type': 'str', }, 'fwd_policy_forward_to_service_group': {'type': 'str', }, 'fwd_policy_forward_to_proxy': {'type': 'str', }, 'fwd_policy_policy_drop': {'type': 'str', }, 'fwd_policy_source_match_not_found': {'type': 'str', }, 'exp_client_hello_not_found': {'type': 'str', }, 'name': {'type': 'str', 'required': True, }, 'forward_policy': {'type': 'dict', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["policy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["policy"].get(k) != v:
            change_results["changed"] = True
            config_changes["policy"][k] = v

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
    payload = utils.build_json("policy", module.params, AVAILABLE_PROPERTIES)
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
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
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
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["policy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["policy-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["policy"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

if __name__ == '__main__':
    main()
