#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_lw_4o6_global
description:
    - Configure LW-4over6 parameters
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
    hairpinning:
        description:
        - "'filter-all'= Disable all Hairpinning; 'filter-none'= Allow all Hairpinning
          (default); 'filter-self-ip'= Block Hairpinning to same IP; 'filter-self-ip-
          port'= Block hairpinning to same IP and Port combination;"
        type: str
        required: False
    icmp_inbound:
        description:
        - "'drop'= Drop Inbound ICMP packets; 'handle'= Handle Inbound ICMP
          packets(default);"
        type: str
        required: False
    nat_prefix_list:
        description:
        - "Configure LW-4over6 NAT Prefix List (LW-4over6 NAT Prefix Class-list)"
        type: str
        required: False
    no_forward_match:
        description:
        - "Field no_forward_match"
        type: dict
        required: False
        suboptions:
            send_icmpv6:
                description:
                - "Send ICMPv6 Type 1 Code 5"
                type: bool
    no_reverse_match:
        description:
        - "Field no_reverse_match"
        type: dict
        required: False
        suboptions:
            send_icmp:
                description:
                - "Send ICMP Type 3 Code 1"
                type: bool
    use_binding_table:
        description:
        - "Bind LW-4over6 binding table for use (LW-4over6 Binding Table Name)"
        type: str
        required: False
    inside_src_access_list:
        description:
        - "Access List for inside IPv4 addresses (ACL ID)"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'entry_count'= Total Entries Configured; 'self_hairpinning_drop'=
          Self-Hairpinning Drops; 'all_hairpinning_drop'= All Hairpinning Drops;
          'no_match_icmpv6_sent'= No-Forward-Match ICMPv6 Sent; 'no_match_icmp_sent'= No-
          Reverse-Match ICMP Sent; 'icmp_inbound_drop'= Inbound ICMP Drops;
          'fwd_lookup_failed'= Forward Route Lookup Failed; 'rev_lookup_failed'= Reverse
          Route Lookup Failed; 'interface_not_configured'= LW-4over6 Interfaces not
          Configured Drops; 'no_binding_table_matches_fwd'= No Forward Binding Table
          Entry Match Drops; 'no_binding_table_matches_rev'= No Reverse Binding Table
          Entry Match Drops; 'session_count'= LW-4over6 Session Count;
          'system_address_drop'= LW-4over6 System Address Drops;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            entry_count:
                description:
                - "Total Entries Configured"
                type: str
            self_hairpinning_drop:
                description:
                - "Self-Hairpinning Drops"
                type: str
            all_hairpinning_drop:
                description:
                - "All Hairpinning Drops"
                type: str
            no_match_icmpv6_sent:
                description:
                - "No-Forward-Match ICMPv6 Sent"
                type: str
            no_match_icmp_sent:
                description:
                - "No-Reverse-Match ICMP Sent"
                type: str
            icmp_inbound_drop:
                description:
                - "Inbound ICMP Drops"
                type: str
            fwd_lookup_failed:
                description:
                - "Forward Route Lookup Failed"
                type: str
            rev_lookup_failed:
                description:
                - "Reverse Route Lookup Failed"
                type: str
            interface_not_configured:
                description:
                - "LW-4over6 Interfaces not Configured Drops"
                type: str
            no_binding_table_matches_fwd:
                description:
                - "No Forward Binding Table Entry Match Drops"
                type: str
            no_binding_table_matches_rev:
                description:
                - "No Reverse Binding Table Entry Match Drops"
                type: str

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
    "hairpinning",
    "icmp_inbound",
    "inside_src_access_list",
    "nat_prefix_list",
    "no_forward_match",
    "no_reverse_match",
    "sampling_enable",
    "stats",
    "use_binding_table",
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
        'hairpinning': {
            'type':
            'str',
            'choices': [
                'filter-all', 'filter-none', 'filter-self-ip',
                'filter-self-ip-port'
            ]
        },
        'icmp_inbound': {
            'type': 'str',
            'choices': ['drop', 'handle']
        },
        'nat_prefix_list': {
            'type': 'str',
        },
        'no_forward_match': {
            'type': 'dict',
            'send_icmpv6': {
                'type': 'bool',
            }
        },
        'no_reverse_match': {
            'type': 'dict',
            'send_icmp': {
                'type': 'bool',
            }
        },
        'use_binding_table': {
            'type': 'str',
        },
        'inside_src_access_list': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'entry_count', 'self_hairpinning_drop',
                    'all_hairpinning_drop', 'no_match_icmpv6_sent',
                    'no_match_icmp_sent', 'icmp_inbound_drop',
                    'fwd_lookup_failed', 'rev_lookup_failed',
                    'interface_not_configured', 'no_binding_table_matches_fwd',
                    'no_binding_table_matches_rev', 'session_count',
                    'system_address_drop'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'entry_count': {
                'type': 'str',
            },
            'self_hairpinning_drop': {
                'type': 'str',
            },
            'all_hairpinning_drop': {
                'type': 'str',
            },
            'no_match_icmpv6_sent': {
                'type': 'str',
            },
            'no_match_icmp_sent': {
                'type': 'str',
            },
            'icmp_inbound_drop': {
                'type': 'str',
            },
            'fwd_lookup_failed': {
                'type': 'str',
            },
            'rev_lookup_failed': {
                'type': 'str',
            },
            'interface_not_configured': {
                'type': 'str',
            },
            'no_binding_table_matches_fwd': {
                'type': 'str',
            },
            'no_binding_table_matches_rev': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lw-4o6/global"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/cgnv6/lw-4o6/global"

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


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["global"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["global"][k] = v
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
    payload = build_json("global", module)
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
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
