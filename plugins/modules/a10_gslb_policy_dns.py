#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_policy_dns
description:
    - DNS related policy
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
    policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    action:
        description:
        - "Apply DNS action for service"
        type: bool
        required: False
    active_only:
        description:
        - "Only keep active servers"
        type: bool
        required: False
    active_only_fail_safe:
        description:
        - "Continue if no candidate"
        type: bool
        required: False
    dns_addition_mx:
        description:
        - "Append MX Records in Addition Section"
        type: bool
        required: False
    dns_auto_map:
        description:
        - "Automatically build DNS Infrastructure"
        type: bool
        required: False
    backup_alias:
        description:
        - "Return alias name when fail"
        type: bool
        required: False
    backup_server:
        description:
        - "Return fallback server when fail"
        type: bool
        required: False
    external_ip:
        description:
        - "Return DNS response with external IP address"
        type: bool
        required: False
    external_soa:
        description:
        - "Return DNS response with external SOA Record"
        type: bool
        required: False
    cname_detect:
        description:
        - "Apply GSLB for DNS Server response when service is Canonical Name (CNAME)"
        type: bool
        required: False
    ip_replace:
        description:
        - "Replace DNS Server Response with GSLB Service-IPs"
        type: bool
        required: False
    geoloc_alias:
        description:
        - "Return alias name by geo-location"
        type: bool
        required: False
    geoloc_action:
        description:
        - "Apply DNS action by geo-location"
        type: bool
        required: False
    geoloc_policy:
        description:
        - "Apply different policy by geo-location"
        type: bool
        required: False
    selected_only:
        description:
        - "Only keep selected servers"
        type: bool
        required: False
    selected_only_value:
        description:
        - "Answer Number"
        type: int
        required: False
    cache:
        description:
        - "Cache DNS Server response"
        type: bool
        required: False
    aging_time:
        description:
        - "Specify aging-time, default is TTL in DNS record, unit= second (Aging time,
          default 0 means using TTL in DNS record as aging time)"
        type: int
        required: False
    delegation:
        description:
        - "Zone Delegation"
        type: bool
        required: False
    hint:
        description:
        - "'none'= None; 'answer'= Append Hint Records in DNS Answer Section; 'addition'=
          Append Hint Records in DNS Addition Section;"
        type: str
        required: False
    logging:
        description:
        - "'none'= None; 'query'= DNS Query; 'response'= DNS Response; 'both'= Both DNS
          Query and Response;"
        type: str
        required: False
    template:
        description:
        - "Logging template (Logging Template Name)"
        type: str
        required: False
    ttl:
        description:
        - "Specify the TTL value contained in DNS record (TTL value, unit= second, default
          is 10)"
        type: int
        required: False
    use_server_ttl:
        description:
        - "Use DNS Server Response TTL value in GSLB Proxy mode"
        type: bool
        required: False
    server:
        description:
        - "Run GSLB as DNS server mode"
        type: bool
        required: False
    server_srv:
        description:
        - "Provide SRV Records"
        type: bool
        required: False
    server_mx:
        description:
        - "Provide MX Records"
        type: bool
        required: False
    server_naptr:
        description:
        - "Provide NAPTR Records"
        type: bool
        required: False
    server_addition_mx:
        description:
        - "Append MX Records in Addition Section"
        type: bool
        required: False
    server_ns:
        description:
        - "Provide NS Records"
        type: bool
        required: False
    server_auto_ns:
        description:
        - "Provide A-Records for NS-Records automatically"
        type: bool
        required: False
    server_ptr:
        description:
        - "Provide PTR Records"
        type: bool
        required: False
    server_auto_ptr:
        description:
        - "Provide PTR Records automatically"
        type: bool
        required: False
    server_txt:
        description:
        - "Provide TXT Records"
        type: bool
        required: False
    server_custom:
        description:
        - "Provide Custom Records"
        type: bool
        required: False
    server_any:
        description:
        - "Provide All Records"
        type: bool
        required: False
    server_any_with_metric:
        description:
        - "Provide All Records with GSLB Metrics applied to A/AAAA Records"
        type: bool
        required: False
    server_authoritative:
        description:
        - "As authoritative server"
        type: bool
        required: False
    server_sec:
        description:
        - "Provide DNSSEC support"
        type: bool
        required: False
    server_ns_list:
        description:
        - "Append All NS Records in Authoritative Section"
        type: bool
        required: False
    server_full_list:
        description:
        - "Append All A Records in Authoritative Section"
        type: bool
        required: False
    server_mode_only:
        description:
        - "Only run GSLB as DNS server mode"
        type: bool
        required: False
    zone_owner_mode:
        description:
        - "Only run GSLB as DNS server mode with zone ownership"
        type: bool
        required: False
    server_cname:
        description:
        - "Provide CNAME Records"
        type: bool
        required: False
    server_caa:
        description:
        - "Provide CAA Records"
        type: bool
        required: False
    ipv6:
        description:
        - "Field ipv6"
        type: list
        required: False
        suboptions:
            dns_ipv6_option:
                description:
                - "'mix'= Return both AAAA Record and A Record; 'smart'= Return AAAA Record by DNS
          Query Type; 'mapping'= Map A Record to AAAA Record;"
                type: str
            dns_ipv6_mapping_type:
                description:
                - "'addition'= Append Mapped Record in DNS Addition Section; 'answer'= Append
          Mapped Record in DNS Answer Section; 'exclusive'= Only return AAAA Record;
          'replace'= Replace Record with Mapped Record;"
                type: str
    block_action:
        description:
        - "Specify Action"
        type: bool
        required: False
    action_type:
        description:
        - "'drop'= Drop query; 'reject'= Send refuse response; 'ignore'= Send empty
          response;"
        type: str
        required: False
    proxy_block_port_range_list:
        description:
        - "Field proxy_block_port_range_list"
        type: list
        required: False
        suboptions:
            proxy_block_range_from:
                description:
                - "Specify Type Range (From)"
                type: int
            proxy_block_range_to:
                description:
                - "To"
                type: int
    block_value:
        description:
        - "Field block_value"
        type: list
        required: False
        suboptions:
            block_value:
                description:
                - "Specify Type Number"
                type: int
    block_type:
        description:
        - "Field block_type"
        type: str
        required: False
    sticky:
        description:
        - "Make DNS Record sticky for certain time"
        type: bool
        required: False
    sticky_mask:
        description:
        - "Specify IP mask, default is /32"
        type: str
        required: False
    sticky_ipv6_mask:
        description:
        - "Specify IPv6 mask length, default is 128"
        type: int
        required: False
    sticky_aging_time:
        description:
        - "Specify aging-time, unit= min, default is 5 (Aging time)"
        type: int
        required: False
    dynamic_preference:
        description:
        - "Make dynamically change the preference"
        type: bool
        required: False
    dynamic_weight:
        description:
        - "dynamically change the weight"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sticky_options:
        description:
        - "Field sticky_options"
        type: dict
        required: False
        suboptions:
            edns_client_subnet:
                description:
                - "Use ECS for sticky creation and lookup"
                type: bool
            only_ecs:
                description:
                - "Only use ECS for session creation"
                type: bool
            uuid:
                description:
                - "uuid of the object"
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
AVAILABLE_PROPERTIES = [
    "action", "action_type", "active_only", "active_only_fail_safe", "aging_time", "backup_alias", "backup_server", "block_action", "block_type", "block_value", "cache", "cname_detect", "delegation", "dns_addition_mx", "dns_auto_map", "dynamic_preference", "dynamic_weight", "external_ip", "external_soa", "geoloc_action", "geoloc_alias",
    "geoloc_policy", "hint", "ip_replace", "ipv6", "logging", "proxy_block_port_range_list", "selected_only", "selected_only_value", "server", "server_addition_mx", "server_any", "server_any_with_metric", "server_authoritative", "server_auto_ns", "server_auto_ptr", "server_caa", "server_cname", "server_custom", "server_full_list",
    "server_mode_only", "server_mx", "server_naptr", "server_ns", "server_ns_list", "server_ptr", "server_sec", "server_srv", "server_txt", "sticky", "sticky_aging_time", "sticky_ipv6_mask", "sticky_mask", "sticky_options", "template", "ttl", "use_server_ttl", "uuid", "zone_owner_mode",
    ]


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
        'action': {
            'type': 'bool',
            },
        'active_only': {
            'type': 'bool',
            },
        'active_only_fail_safe': {
            'type': 'bool',
            },
        'dns_addition_mx': {
            'type': 'bool',
            },
        'dns_auto_map': {
            'type': 'bool',
            },
        'backup_alias': {
            'type': 'bool',
            },
        'backup_server': {
            'type': 'bool',
            },
        'external_ip': {
            'type': 'bool',
            },
        'external_soa': {
            'type': 'bool',
            },
        'cname_detect': {
            'type': 'bool',
            },
        'ip_replace': {
            'type': 'bool',
            },
        'geoloc_alias': {
            'type': 'bool',
            },
        'geoloc_action': {
            'type': 'bool',
            },
        'geoloc_policy': {
            'type': 'bool',
            },
        'selected_only': {
            'type': 'bool',
            },
        'selected_only_value': {
            'type': 'int',
            },
        'cache': {
            'type': 'bool',
            },
        'aging_time': {
            'type': 'int',
            },
        'delegation': {
            'type': 'bool',
            },
        'hint': {
            'type': 'str',
            'choices': ['none', 'answer', 'addition']
            },
        'logging': {
            'type': 'str',
            'choices': ['none', 'query', 'response', 'both']
            },
        'template': {
            'type': 'str',
            },
        'ttl': {
            'type': 'int',
            },
        'use_server_ttl': {
            'type': 'bool',
            },
        'server': {
            'type': 'bool',
            },
        'server_srv': {
            'type': 'bool',
            },
        'server_mx': {
            'type': 'bool',
            },
        'server_naptr': {
            'type': 'bool',
            },
        'server_addition_mx': {
            'type': 'bool',
            },
        'server_ns': {
            'type': 'bool',
            },
        'server_auto_ns': {
            'type': 'bool',
            },
        'server_ptr': {
            'type': 'bool',
            },
        'server_auto_ptr': {
            'type': 'bool',
            },
        'server_txt': {
            'type': 'bool',
            },
        'server_custom': {
            'type': 'bool',
            },
        'server_any': {
            'type': 'bool',
            },
        'server_any_with_metric': {
            'type': 'bool',
            },
        'server_authoritative': {
            'type': 'bool',
            },
        'server_sec': {
            'type': 'bool',
            },
        'server_ns_list': {
            'type': 'bool',
            },
        'server_full_list': {
            'type': 'bool',
            },
        'server_mode_only': {
            'type': 'bool',
            },
        'zone_owner_mode': {
            'type': 'bool',
            },
        'server_cname': {
            'type': 'bool',
            },
        'server_caa': {
            'type': 'bool',
            },
        'ipv6': {
            'type': 'list',
            'dns_ipv6_option': {
                'type': 'str',
                'choices': ['mix', 'smart', 'mapping']
                },
            'dns_ipv6_mapping_type': {
                'type': 'str',
                'choices': ['addition', 'answer', 'exclusive', 'replace']
                }
            },
        'block_action': {
            'type': 'bool',
            },
        'action_type': {
            'type': 'str',
            'choices': ['drop', 'reject', 'ignore']
            },
        'proxy_block_port_range_list': {
            'type': 'list',
            'proxy_block_range_from': {
                'type': 'int',
                },
            'proxy_block_range_to': {
                'type': 'int',
                }
            },
        'block_value': {
            'type': 'list',
            'block_value': {
                'type': 'int',
                }
            },
        'block_type': {
            'type': 'str',
            'choices': ['a', 'aaaa', 'ns', 'mx', 'srv', 'cname', 'ptr', 'soa', 'txt']
            },
        'sticky': {
            'type': 'bool',
            },
        'sticky_mask': {
            'type': 'str',
            },
        'sticky_ipv6_mask': {
            'type': 'int',
            },
        'sticky_aging_time': {
            'type': 'int',
            },
        'dynamic_preference': {
            'type': 'bool',
            },
        'dynamic_weight': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'sticky_options': {
            'type': 'dict',
            'edns_client_subnet': {
                'type': 'bool',
                },
            'only_ecs': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    # Parent keys
    rv.update(dict(policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{policy_name}/dns"

    f_dict = {}
    if '/' in module.params["policy_name"]:
        f_dict["policy_name"] = module.params["policy_name"].replace("/", "%2F")
    else:
        f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy/{policy_name}/dns"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dns"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns"][k] = v

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
    payload = utils.build_json("dns", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dns"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dns-list"] if info != "NotFound" else info
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
