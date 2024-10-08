#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dns_cache_server
description:
    - DDOS DNS Cache Server Statistics
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            insert_total:
                description:
                - "Insert Total"
                type: str
            insert_success:
                description:
                - "Insert Success"
                type: str
            insert_fail_all:
                description:
                - "Insert Fail"
                type: str
            lookup_invalid_domain:
                description:
                - "Lookup Invalid Domain"
                type: str
            lookup_unexp_err:
                description:
                - "Lookup Unexpected Error"
                type: str
            lookup_full_matched:
                description:
                - "Lookup Fully Matched"
                type: str
            lookup_empty_resp:
                description:
                - "Lookup Empty Response"
                type: str
            lookup_deleg_resp:
                description:
                - "Lookup Delegation Response"
                type: str
            lookup_nxdomain_resp:
                description:
                - "Lookup Nxdomain Response"
                type: str
            lookup_refuse_resp:
                description:
                - "Lookup Refuse Response"
                type: str
            lookup_fwd_server:
                description:
                - "Lookup Forwarded to Server"
                type: str
            lookup_incomp_zone:
                description:
                - "Lookup Incomplete Zone"
                type: str
            lookup_undefined_rtype:
                description:
                - "Lookup Undefined Record Type"
                type: str
            lookup_manual_override_action_forward:
                description:
                - "Lookup DNS Manual Override Action Forward"
                type: str
            lookup_manual_override_action_drop:
                description:
                - "Lookup DNS Manual Override Action Drop"
                type: str
            zt_serial_num_check_attempts:
                description:
                - "Zone Transfer Serial Number Check Started"
                type: str
            zt_axfr_attempts:
                description:
                - "Zone Transfer AXFR Started"
                type: str
            zt_completed_ok:
                description:
                - "Zone Transfer Completed"
                type: str
            zt_completed_no_update:
                description:
                - "Zone Transfer Completed No Update"
                type: str
            zt_dns_process_err:
                description:
                - "Zone Transfer DNS Processing Errors"
                type: str
            zt_records_processed:
                description:
                - "Zone Transfer Records Processed"
                type: str
            lookup_edns_bad_version_resp:
                description:
                - "Lookup EDNS Bad Version Response"
                type: str
            zt_tcp_conn_connect_server_fail:
                description:
                - "Zone Transfer TCP Connect Server Fail"
                type: str
            zt_tcp_conn_rst:
                description:
                - "Zone Transfer TCP RST / FIN Received"
                type: str
            zt_task_no_route_retry:
                description:
                - "Zone Transfer Task No Route Fail"
                type: str
            zt_msg_rcode_notauth:
                description:
                - "Zone Transfer Server Not Auth Fail"
                type: str
            lookup_opcode_notimpl_resp:
                description:
                - "Lookup Opcode Not Implemented Response"
                type: str
            shard_filter_match:
                description:
                - "Lookup Shard Filter Matched"
                type: str
            zt_total_fail:
                description:
                - "Zone Transfer Total Failure"
                type: str
            lookup_manual_override_action_serve:
                description:
                - "Lookup DNS Manual Override Action Serve"
                type: str
            lookup_any_type_query_action_drop:
                description:
                - "Lookup DNS ANY Type Query Action Drop"
                type: str
            lookup_any_type_query_action_refused:
                description:
                - "Lookup DNS ANY Type Query Action Refused"
                type: str
            lookup_any_type_query_action_resp_empty:
                description:
                - "Lookup DNS ANY Type Query Action Response Empty"
                type: str
            lookup_non_auth_zone_query_action_forward:
                description:
                - "Lookup DNS Non-Authoritative Zone Query Action Forward"
                type: str
            lookup_non_auth_zone_query_action_drop:
                description:
                - "Lookup DNS Non-Authoritative Zone Query Action Drop"
                type: str
            lookup_non_auth_zone_query_action_resp_refused:
                description:
                - "Lookup DNS Non-Authoritative Zone Query Action Refused"
                type: str
            lookup_default_action_forward:
                description:
                - "Lookup DNS Default Action Forward"
                type: str
            lookup_default_action_drop:
                description:
                - "Lookup DNS Default Action Drop"
                type: str
            zt_ongoing_tasks:
                description:
                - "Zone Transfer Ongoing tasks"
                type: str
            lookup_dnstcp_rcvd:
                description:
                - "Lookup DNS-TCP Request Received"
                type: str
            lookup_dnsudp_rcvd:
                description:
                - "Lookup DNS-UDP Request Received"
                type: str
            lookup_fwd_shard:
                description:
                - "Lookup Forwarded to Sharding DNS Cache"
                type: str
            dns_prebuild_alloc_fail:
                description:
                - "DNS Prebuild Alloc Fail"
                type: str
            suffix_table_trylock_fail:
                description:
                - "DNS Cache Suffix Table Trylock Fail"
                type: str
            insert_apex_zone_node_fail:
                description:
                - "Insert Apex Zone Node Fail"
                type: str
            insert_suffix_fqdn_node_fail:
                description:
                - "Insert Suffix FQDN Node Fail"
                type: str
            dnssec_rrsig_link_fail:
                description:
                - "DNSSEC RRSIG Link Failure"
                type: str
            alias_subtype_already_exist:
                description:
                - "ALIAS Record Subtype Already Exists"
                type: str
            zone_apex_suffix_node_insert_fail:
                description:
                - "Zone Apex Suffix Node Insert Fail"
                type: str
            lookup_servfail_resp:
                description:
                - "Lookup Server Fail Response"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {
            'type': 'dict',
            'insert_total': {
                'type': 'str',
                },
            'insert_success': {
                'type': 'str',
                },
            'insert_fail_all': {
                'type': 'str',
                },
            'lookup_invalid_domain': {
                'type': 'str',
                },
            'lookup_unexp_err': {
                'type': 'str',
                },
            'lookup_full_matched': {
                'type': 'str',
                },
            'lookup_empty_resp': {
                'type': 'str',
                },
            'lookup_deleg_resp': {
                'type': 'str',
                },
            'lookup_nxdomain_resp': {
                'type': 'str',
                },
            'lookup_refuse_resp': {
                'type': 'str',
                },
            'lookup_fwd_server': {
                'type': 'str',
                },
            'lookup_incomp_zone': {
                'type': 'str',
                },
            'lookup_undefined_rtype': {
                'type': 'str',
                },
            'lookup_manual_override_action_forward': {
                'type': 'str',
                },
            'lookup_manual_override_action_drop': {
                'type': 'str',
                },
            'zt_serial_num_check_attempts': {
                'type': 'str',
                },
            'zt_axfr_attempts': {
                'type': 'str',
                },
            'zt_completed_ok': {
                'type': 'str',
                },
            'zt_completed_no_update': {
                'type': 'str',
                },
            'zt_dns_process_err': {
                'type': 'str',
                },
            'zt_records_processed': {
                'type': 'str',
                },
            'lookup_edns_bad_version_resp': {
                'type': 'str',
                },
            'zt_tcp_conn_connect_server_fail': {
                'type': 'str',
                },
            'zt_tcp_conn_rst': {
                'type': 'str',
                },
            'zt_task_no_route_retry': {
                'type': 'str',
                },
            'zt_msg_rcode_notauth': {
                'type': 'str',
                },
            'lookup_opcode_notimpl_resp': {
                'type': 'str',
                },
            'shard_filter_match': {
                'type': 'str',
                },
            'zt_total_fail': {
                'type': 'str',
                },
            'lookup_manual_override_action_serve': {
                'type': 'str',
                },
            'lookup_any_type_query_action_drop': {
                'type': 'str',
                },
            'lookup_any_type_query_action_refused': {
                'type': 'str',
                },
            'lookup_any_type_query_action_resp_empty': {
                'type': 'str',
                },
            'lookup_non_auth_zone_query_action_forward': {
                'type': 'str',
                },
            'lookup_non_auth_zone_query_action_drop': {
                'type': 'str',
                },
            'lookup_non_auth_zone_query_action_resp_refused': {
                'type': 'str',
                },
            'lookup_default_action_forward': {
                'type': 'str',
                },
            'lookup_default_action_drop': {
                'type': 'str',
                },
            'zt_ongoing_tasks': {
                'type': 'str',
                },
            'lookup_dnstcp_rcvd': {
                'type': 'str',
                },
            'lookup_dnsudp_rcvd': {
                'type': 'str',
                },
            'lookup_fwd_shard': {
                'type': 'str',
                },
            'dns_prebuild_alloc_fail': {
                'type': 'str',
                },
            'suffix_table_trylock_fail': {
                'type': 'str',
                },
            'insert_apex_zone_node_fail': {
                'type': 'str',
                },
            'insert_suffix_fqdn_node_fail': {
                'type': 'str',
                },
            'dnssec_rrsig_link_fail': {
                'type': 'str',
                },
            'alias_subtype_already_exist': {
                'type': 'str',
                },
            'zone_apex_suffix_node_insert_fail': {
                'type': 'str',
                },
            'lookup_servfail_resp': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dns-cache-server"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dns-cache-server"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("dns-cache-server", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dns-cache-server"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dns-cache-server-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["dns-cache-server"]["stats"] if info != "NotFound" else info
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
