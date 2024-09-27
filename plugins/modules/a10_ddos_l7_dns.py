#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l7_dns
description:
    - DDOS DNS Statistics
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
            force_tcp_auth:
                description:
                - "DNS Auth Force-TCP"
                type: str
            dns_auth_udp:
                description:
                - "DNS Auth UDP"
                type: str
            dns_malform_drop:
                description:
                - "DNS Malform Query Dropped"
                type: str
            dns_qry_any_drop:
                description:
                - "DNS Query ANY Dropped"
                type: str
            dst_rate_limit0:
                description:
                - "Dst Request Rate 1 Exceeded"
                type: str
            dst_rate_limit1:
                description:
                - "Dst Request Rate 2 Exceeded"
                type: str
            dst_rate_limit2:
                description:
                - "Dst Request Rate 3 Exceeded"
                type: str
            dst_rate_limit3:
                description:
                - "Dst Request Rate 4 Exceeded"
                type: str
            dst_rate_limit4:
                description:
                - "Dst Request Rate 5 Exceeded"
                type: str
            src_rate_limit0:
                description:
                - "Src Request Rate 1 Exceeded"
                type: str
            src_rate_limit1:
                description:
                - "Src Request Rate 2 Exceeded"
                type: str
            src_rate_limit2:
                description:
                - "Src Request Rate 3 Exceeded"
                type: str
            src_rate_limit3:
                description:
                - "Src Request Rate 4 Exceeded"
                type: str
            src_rate_limit4:
                description:
                - "Src Request Rate 5 Exceeded"
                type: str
            dns_auth_udp_pass:
                description:
                - "DNS Auth UDP Passed"
                type: str
            dns_fqdn_stage2_exceed:
                description:
                - "FQDN Rate Exceeded"
                type: str
            dns_is_nx:
                description:
                - "NXDOMAIN Response"
                type: str
            dns_nx_drop:
                description:
                - "NXDOMAIN Query Dropped"
                type: str
            dns_nx_bl:
                description:
                - "NXDOMAIN Query Blacklisted"
                type: str
            dns_tcp_auth_pass:
                description:
                - "DNS Auth Force-TCP Passed"
                type: str
            dns_auth_udp_fail:
                description:
                - "DNS Auth UDP Failed"
                type: str
            dns_auth_udp_timeout:
                description:
                - "DNS Auth UDP Timeout"
                type: str
            dns_fqdn_label_len_exceed:
                description:
                - "FQDN Label Length Exceeded"
                type: str
            dns_pkt_processed:
                description:
                - "DNS Packets Processed"
                type: str
            dns_query_type_a:
                description:
                - "DNS Query Type A"
                type: str
            dns_query_type_aaaa:
                description:
                - "DNS Query Type AAAA"
                type: str
            dns_query_type_ns:
                description:
                - "DNS Query Type NS"
                type: str
            dns_query_type_cname:
                description:
                - "DNS Query Type CNAME"
                type: str
            dns_query_type_any:
                description:
                - "DNS Query Type ANY"
                type: str
            dns_query_type_srv:
                description:
                - "DNS Query Type SRV"
                type: str
            dns_query_type_mx:
                description:
                - "DNS Query Type MX"
                type: str
            dns_query_type_soa:
                description:
                - "DNS Query Type SOA"
                type: str
            dns_query_type_opt:
                description:
                - "DNS Query Type OPT"
                type: str
            dns_dg_action_permit:
                description:
                - "DNS Domain Group Action Permit"
                type: str
            dns_dg_action_deny:
                description:
                - "DNS Domain Group Action Deny"
                type: str
            dns_fqdn_rate_by_label_count_exceed:
                description:
                - "FQDN Rate by Label Count Exceeded"
                type: str
            dns_udp_auth_retry_gap_drop:
                description:
                - "DNS Auth UDP Retry-Gap Drop"
                type: str
            dns_policy_drop:
                description:
                - "DNS Policy Dropped"
                type: str
            dns_fqdn_label_count_exceed:
                description:
                - "FQDN Label Count Exceeded"
                type: str
            dns_rrtype_drop:
                description:
                - "DNS Record Type Dropped"
                type: str
            force_tcp_auth_timeout:
                description:
                - "DNS Auth Force-TCP With UDP Auth Timeout"
                type: str
            dns_auth_drop:
                description:
                - "DNS Auth Dropped"
                type: str
            dns_auth_resp:
                description:
                - "DNS Auth Responded"
                type: str
            force_tcp_auth_conn_hit:
                description:
                - "DNS Auth Force-TCP With UDP Auth Connection Hit"
                type: str
            dns_auth_udp_fail_bl:
                description:
                - "DNS Auth UDP Fail Blacklisted"
                type: str
            dns_nx_exceed:
                description:
                - "NXDOMAIN Response Rate Exceeded"
                type: str
            dns_query_class_whitelist_miss:
                description:
                - "DNS Query Class Whitelist Miss"
                type: str
            dns_query_class_in:
                description:
                - "DNS Query Class INTERNET"
                type: str
            dns_query_class_csnet:
                description:
                - "DNS Query Class CSNET"
                type: str
            dns_query_class_chaos:
                description:
                - "DNS Query Class CHAOS"
                type: str
            dns_query_class_hs:
                description:
                - "DNS Query Class HESIOD"
                type: str
            dns_query_class_none:
                description:
                - "DNS Query Class NONE"
                type: str
            dns_query_class_any:
                description:
                - "DNS Query Class ANY"
                type: str
            dns_dg_rate_exceed:
                description:
                - "DNS Domain Group Domain Query Rate Exceeded"
                type: str
            dns_outbound_query_response_size_exceed:
                description:
                - "DNS Outbound Query Resp Size Exceeded"
                type: str
            dns_outbound_query_sess_timed_out:
                description:
                - "DNS Outbound Query Session Timed Out"
                type: str
            non_query_opcode_pass_through:
                description:
                - "DNS Non Query Opcode Pass Through"
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
            'force_tcp_auth': {
                'type': 'str',
                },
            'dns_auth_udp': {
                'type': 'str',
                },
            'dns_malform_drop': {
                'type': 'str',
                },
            'dns_qry_any_drop': {
                'type': 'str',
                },
            'dst_rate_limit0': {
                'type': 'str',
                },
            'dst_rate_limit1': {
                'type': 'str',
                },
            'dst_rate_limit2': {
                'type': 'str',
                },
            'dst_rate_limit3': {
                'type': 'str',
                },
            'dst_rate_limit4': {
                'type': 'str',
                },
            'src_rate_limit0': {
                'type': 'str',
                },
            'src_rate_limit1': {
                'type': 'str',
                },
            'src_rate_limit2': {
                'type': 'str',
                },
            'src_rate_limit3': {
                'type': 'str',
                },
            'src_rate_limit4': {
                'type': 'str',
                },
            'dns_auth_udp_pass': {
                'type': 'str',
                },
            'dns_fqdn_stage2_exceed': {
                'type': 'str',
                },
            'dns_is_nx': {
                'type': 'str',
                },
            'dns_nx_drop': {
                'type': 'str',
                },
            'dns_nx_bl': {
                'type': 'str',
                },
            'dns_tcp_auth_pass': {
                'type': 'str',
                },
            'dns_auth_udp_fail': {
                'type': 'str',
                },
            'dns_auth_udp_timeout': {
                'type': 'str',
                },
            'dns_fqdn_label_len_exceed': {
                'type': 'str',
                },
            'dns_pkt_processed': {
                'type': 'str',
                },
            'dns_query_type_a': {
                'type': 'str',
                },
            'dns_query_type_aaaa': {
                'type': 'str',
                },
            'dns_query_type_ns': {
                'type': 'str',
                },
            'dns_query_type_cname': {
                'type': 'str',
                },
            'dns_query_type_any': {
                'type': 'str',
                },
            'dns_query_type_srv': {
                'type': 'str',
                },
            'dns_query_type_mx': {
                'type': 'str',
                },
            'dns_query_type_soa': {
                'type': 'str',
                },
            'dns_query_type_opt': {
                'type': 'str',
                },
            'dns_dg_action_permit': {
                'type': 'str',
                },
            'dns_dg_action_deny': {
                'type': 'str',
                },
            'dns_fqdn_rate_by_label_count_exceed': {
                'type': 'str',
                },
            'dns_udp_auth_retry_gap_drop': {
                'type': 'str',
                },
            'dns_policy_drop': {
                'type': 'str',
                },
            'dns_fqdn_label_count_exceed': {
                'type': 'str',
                },
            'dns_rrtype_drop': {
                'type': 'str',
                },
            'force_tcp_auth_timeout': {
                'type': 'str',
                },
            'dns_auth_drop': {
                'type': 'str',
                },
            'dns_auth_resp': {
                'type': 'str',
                },
            'force_tcp_auth_conn_hit': {
                'type': 'str',
                },
            'dns_auth_udp_fail_bl': {
                'type': 'str',
                },
            'dns_nx_exceed': {
                'type': 'str',
                },
            'dns_query_class_whitelist_miss': {
                'type': 'str',
                },
            'dns_query_class_in': {
                'type': 'str',
                },
            'dns_query_class_csnet': {
                'type': 'str',
                },
            'dns_query_class_chaos': {
                'type': 'str',
                },
            'dns_query_class_hs': {
                'type': 'str',
                },
            'dns_query_class_none': {
                'type': 'str',
                },
            'dns_query_class_any': {
                'type': 'str',
                },
            'dns_dg_rate_exceed': {
                'type': 'str',
                },
            'dns_outbound_query_response_size_exceed': {
                'type': 'str',
                },
            'dns_outbound_query_sess_timed_out': {
                'type': 'str',
                },
            'non_query_opcode_pass_through': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l7-dns"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l7-dns"

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
    payload = utils.build_json("l7-dns", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l7-dns"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l7-dns-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l7-dns"]["stats"] if info != "NotFound" else info
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
