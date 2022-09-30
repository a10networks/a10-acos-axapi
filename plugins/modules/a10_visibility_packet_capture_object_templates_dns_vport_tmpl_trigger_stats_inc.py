#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_object_templates_dns_vport_tmpl_trigger_stats_inc
description:
    - Configure stats to triggers packet capture on increment
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
    dns_vport_tmpl_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    dnsrrl_total_dropped:
        description:
        - "Enable automatic packet-capture for dns rrl drop"
        type: bool
        required: False
    total_filter_drop:
        description:
        - "Enable automatic packet-capture for query filter drop"
        type: bool
        required: False
    total_max_query_len_drop:
        description:
        - "Enable automatic packet-capture for query too long drop"
        type: bool
        required: False
    rcode_notimpl_receive:
        description:
        - "Enable automatic packet-capture for response rcode type error receive"
        type: bool
        required: False
    rcode_notimpl_response:
        description:
        - "Enable automatic packet-capture for rcode type error response"
        type: bool
        required: False
    gslb_query_bad:
        description:
        - "Enable automatic packet-capture for gslb query bad"
        type: bool
        required: False
    gslb_response_bad:
        description:
        - "Enable automatic packet-capture for gslb response bad"
        type: bool
        required: False
    total_dns_filter_type_drop:
        description:
        - "Enable automatic packet-capture for counters Total DNS Filter Type Drop"
        type: bool
        required: False
    total_dns_filter_class_drop:
        description:
        - "Enable automatic packet-capture for counters Total DNS Filter Class Drop"
        type: bool
        required: False
    dns_filter_type_a_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type A Drop"
        type: bool
        required: False
    dns_filter_type_aaaa_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type AAAA Drop"
        type: bool
        required: False
    dns_filter_type_cname_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type CNAME Drop"
        type: bool
        required: False
    dns_filter_type_mx_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type MX Drop"
        type: bool
        required: False
    dns_filter_type_ns_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type NS Drop"
        type: bool
        required: False
    dns_filter_type_srv_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type SRV Drop"
        type: bool
        required: False
    dns_filter_type_ptr_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type PTR Drop"
        type: bool
        required: False
    dns_filter_type_soa_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type SOA Drop"
        type: bool
        required: False
    dns_filter_type_txt_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type TXT Drop"
        type: bool
        required: False
    dns_filter_type_any_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type Any Drop"
        type: bool
        required: False
    dns_filter_type_others_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Type OTHERS Drop"
        type: bool
        required: False
    dns_filter_class_internet_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class INTERNET Drop"
        type: bool
        required: False
    dns_filter_class_chaos_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class CHAOS Drop"
        type: bool
        required: False
    dns_filter_class_hesiod_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class HESIOD Drop"
        type: bool
        required: False
    dns_filter_class_none_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class NONE Drop"
        type: bool
        required: False
    dns_filter_class_any_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class ANY Drop"
        type: bool
        required: False
    dns_filter_class_others_drop:
        description:
        - "Enable automatic packet-capture for counters DNS Filter Class OTHER Drop"
        type: bool
        required: False
    dns_rpz_action_drop:
        description:
        - "Enable automatic packet-capture for DNS RPZ Action Drop"
        type: bool
        required: False
    dnsrrl_bad_fqdn:
        description:
        - "Enable automatic packet-capture for DNS Response-Rate-Limiting Bad FQDN"
        type: bool
        required: False
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
    "dns_filter_class_any_drop",
    "dns_filter_class_chaos_drop",
    "dns_filter_class_hesiod_drop",
    "dns_filter_class_internet_drop",
    "dns_filter_class_none_drop",
    "dns_filter_class_others_drop",
    "dns_filter_type_a_drop",
    "dns_filter_type_aaaa_drop",
    "dns_filter_type_any_drop",
    "dns_filter_type_cname_drop",
    "dns_filter_type_mx_drop",
    "dns_filter_type_ns_drop",
    "dns_filter_type_others_drop",
    "dns_filter_type_ptr_drop",
    "dns_filter_type_soa_drop",
    "dns_filter_type_srv_drop",
    "dns_filter_type_txt_drop",
    "dns_rpz_action_drop",
    "dnsrrl_bad_fqdn",
    "dnsrrl_total_dropped",
    "gslb_query_bad",
    "gslb_response_bad",
    "rcode_notimpl_receive",
    "rcode_notimpl_response",
    "total_dns_filter_class_drop",
    "total_dns_filter_type_drop",
    "total_filter_drop",
    "total_max_query_len_drop",
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
        'dnsrrl_total_dropped': {
            'type': 'bool',
        },
        'total_filter_drop': {
            'type': 'bool',
        },
        'total_max_query_len_drop': {
            'type': 'bool',
        },
        'rcode_notimpl_receive': {
            'type': 'bool',
        },
        'rcode_notimpl_response': {
            'type': 'bool',
        },
        'gslb_query_bad': {
            'type': 'bool',
        },
        'gslb_response_bad': {
            'type': 'bool',
        },
        'total_dns_filter_type_drop': {
            'type': 'bool',
        },
        'total_dns_filter_class_drop': {
            'type': 'bool',
        },
        'dns_filter_type_a_drop': {
            'type': 'bool',
        },
        'dns_filter_type_aaaa_drop': {
            'type': 'bool',
        },
        'dns_filter_type_cname_drop': {
            'type': 'bool',
        },
        'dns_filter_type_mx_drop': {
            'type': 'bool',
        },
        'dns_filter_type_ns_drop': {
            'type': 'bool',
        },
        'dns_filter_type_srv_drop': {
            'type': 'bool',
        },
        'dns_filter_type_ptr_drop': {
            'type': 'bool',
        },
        'dns_filter_type_soa_drop': {
            'type': 'bool',
        },
        'dns_filter_type_txt_drop': {
            'type': 'bool',
        },
        'dns_filter_type_any_drop': {
            'type': 'bool',
        },
        'dns_filter_type_others_drop': {
            'type': 'bool',
        },
        'dns_filter_class_internet_drop': {
            'type': 'bool',
        },
        'dns_filter_class_chaos_drop': {
            'type': 'bool',
        },
        'dns_filter_class_hesiod_drop': {
            'type': 'bool',
        },
        'dns_filter_class_none_drop': {
            'type': 'bool',
        },
        'dns_filter_class_any_drop': {
            'type': 'bool',
        },
        'dns_filter_class_others_drop': {
            'type': 'bool',
        },
        'dns_rpz_action_drop': {
            'type': 'bool',
        },
        'dnsrrl_bad_fqdn': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(dns_vport_tmpl_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/dns_vport-tmpl/{dns_vport_tmpl_name}/trigger-stats-inc"

    f_dict = {}
    if '/' in module.params["dns_vport_tmpl_name"]:
        f_dict["dns_vport_tmpl_name"] = module.params[
            "dns_vport_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["dns_vport_tmpl_name"] = module.params["dns_vport_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/dns_vport-tmpl/{dns_vport_tmpl_name}/trigger-stats-inc"

    f_dict = {}
    f_dict["dns_vport_tmpl_name"] = module.params["dns_vport_tmpl_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-inc"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-inc"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-inc"][k] = v

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
    payload = utils.build_json("trigger-stats-inc", module.params,
                               AVAILABLE_PROPERTIES)
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
                    "trigger-stats-inc"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "trigger-stats-inc-list"] if info != "NotFound" else info
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
