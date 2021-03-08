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
    server_cname:
        description:
        - "Provide CNAME Records"
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
    "action",
    "action_type",
    "active_only",
    "active_only_fail_safe",
    "aging_time",
    "backup_alias",
    "backup_server",
    "block_action",
    "block_type",
    "block_value",
    "cache",
    "cname_detect",
    "delegation",
    "dns_addition_mx",
    "dns_auto_map",
    "dynamic_preference",
    "dynamic_weight",
    "external_ip",
    "external_soa",
    "geoloc_action",
    "geoloc_alias",
    "geoloc_policy",
    "hint",
    "ip_replace",
    "ipv6",
    "logging",
    "proxy_block_port_range_list",
    "selected_only",
    "selected_only_value",
    "server",
    "server_addition_mx",
    "server_any",
    "server_any_with_metric",
    "server_authoritative",
    "server_auto_ns",
    "server_auto_ptr",
    "server_cname",
    "server_full_list",
    "server_mode_only",
    "server_mx",
    "server_naptr",
    "server_ns",
    "server_ns_list",
    "server_ptr",
    "server_sec",
    "server_srv",
    "server_txt",
    "sticky",
    "sticky_aging_time",
    "sticky_ipv6_mask",
    "sticky_mask",
    "template",
    "ttl",
    "use_server_ttl",
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
        'server_cname': {
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
            'type':
            'str',
            'choices':
            ['a', 'aaaa', 'ns', 'mx', 'srv', 'cname', 'ptr', 'soa', 'txt']
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
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/gslb/policy/{policy_name}/dns"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

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
        for k, v in payload["dns"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["dns"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["dns"][k] = v
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
    payload = build_json("dns", module)
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
