#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_ddos_protection
description:
    - Configure CGNV6 DDoS Protection
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
    toggle:
        description:
        - "'enable'= Enable CGNV6 NAT pool DDoS protection (default); 'disable'= Disable
          CGNV6 NAT pool DDoS protection;"
        type: str
        required: False
    logging:
        description:
        - "Field logging"
        type: dict
        required: False
        suboptions:
            logging_toggle:
                description:
                - "'enable'= Enable CGNV6 NAT pool DDoS protection logging (default); 'disable'=
          Disable CGNV6 NAT pool DDoS protection logging;"
                type: str
    packets_per_second:
        description:
        - "Field packets_per_second"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Configure packets-per-second threshold per IP(default 3000000)"
                type: int
            action:
                description:
                - "Field action"
                type: dict
            tcp:
                description:
                - "Configure packets-per-second threshold per TCP port (default= 3000)"
                type: int
            udp:
                description:
                - "Configure packets-per-second threshold per UDP port (default= 3000)"
                type: int
            other:
                description:
                - "Configure packets-per-second threshold for other L4 protocols(default 10000)"
                type: int
            include_existing_session:
                description:
                - "Count traffic associated with existing session into the packets-per-second
          (Default= Disabled)"
                type: bool
    max_hw_entries:
        description:
        - "Configure maximum HW entries"
        type: int
        required: False
    zone:
        description:
        - "Disable NAT IP based on DDoS zone name set in BGP"
        type: str
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
                - "'all'= all; 'l3_entry_added'= L3 Entry Added; 'l3_entry_deleted'= L3 Entry
          Deleted; 'l3_entry_added_to_bgp'= L3 Entry added to BGP;
          'l3_entry_removed_from_bgp'= Entry removed from BGP; 'l3_entry_added_to_hw'= L3
          Entry added to HW; 'l3_entry_removed_from_hw'= L3 Entry removed from HW;
          'l3_entry_too_many'= L3 Too many entries; 'l3_entry_match_drop'= L3 Entry match
          drop; 'l3_entry_match_drop_hw'= L3 HW entry match drop;
          'l3_entry_drop_max_hw_exceeded'= L3 Entry Drop due to HW Limit Exceeded;
          'l4_entry_added'= L4 Entry added; 'l4_entry_deleted'= L4 Entry deleted;
          'l4_entry_added_to_hw'= L4 Entry added to HW; 'l4_entry_removed_from_hw'= L4
          Entry removed from HW; 'l4_hw_out_of_entries'= HW out of L4 entries;
          'l4_entry_match_drop'= L4 Entry match drop; 'l4_entry_match_drop_hw'= L4 HW
          Entry match drop; 'l4_entry_drop_max_hw_exceeded'= L4 Entry Drop due to HW
          Limit Exceeded; 'l4_entry_list_alloc'= L4 Entry list alloc;
          'l4_entry_list_free'= L4 Entry list free; 'l4_entry_list_alloc_failure'= L4
          Entry list alloc failures; 'ip_node_alloc'= Node alloc; 'ip_node_free'= Node
          free; 'ip_node_alloc_failure'= Node alloc failures; 'ip_port_block_alloc'= Port
          block alloc; 'ip_port_block_free'= Port block free;
          'ip_port_block_alloc_failure'= Port block alloc failure;
          'ip_other_block_alloc'= Other block alloc; 'ip_other_block_free'= Other block
          free; 'ip_other_block_alloc_failure'= Other block alloc failure;
          'entry_added_shadow'= Entry added shadow; 'entry_invalidated'= Entry
          invalidated; 'l3_entry_add_to_bgp_failure'= L3 Entry BGP add failures;
          'l3_entry_remove_from_bgp_failure'= L3 entry BGP remove failures;
          'l3_entry_add_to_hw_failure'= L3 entry HW add failure;"
                type: str
    l4_entries:
        description:
        - "Field l4_entries"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ip_entries:
        description:
        - "Field ip_entries"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    disable_nat_ip_by_bgp:
        description:
        - "Field disable_nat_ip_by_bgp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            l3_entry_added:
                description:
                - "L3 Entry Added"
                type: str
            l3_entry_deleted:
                description:
                - "L3 Entry Deleted"
                type: str
            l3_entry_added_to_bgp:
                description:
                - "L3 Entry added to BGP"
                type: str
            l3_entry_removed_from_bgp:
                description:
                - "Entry removed from BGP"
                type: str
            l3_entry_added_to_hw:
                description:
                - "L3 Entry added to HW"
                type: str
            l3_entry_removed_from_hw:
                description:
                - "L3 Entry removed from HW"
                type: str
            l3_entry_too_many:
                description:
                - "L3 Too many entries"
                type: str
            l3_entry_match_drop:
                description:
                - "L3 Entry match drop"
                type: str
            l3_entry_match_drop_hw:
                description:
                - "L3 HW entry match drop"
                type: str
            l3_entry_drop_max_hw_exceeded:
                description:
                - "L3 Entry Drop due to HW Limit Exceeded"
                type: str
            l4_entry_added:
                description:
                - "L4 Entry added"
                type: str
            l4_entry_deleted:
                description:
                - "L4 Entry deleted"
                type: str
            l4_entry_added_to_hw:
                description:
                - "L4 Entry added to HW"
                type: str
            l4_entry_removed_from_hw:
                description:
                - "L4 Entry removed from HW"
                type: str
            l4_hw_out_of_entries:
                description:
                - "HW out of L4 entries"
                type: str
            l4_entry_match_drop:
                description:
                - "L4 Entry match drop"
                type: str
            l4_entry_match_drop_hw:
                description:
                - "L4 HW Entry match drop"
                type: str
            l4_entry_drop_max_hw_exceeded:
                description:
                - "L4 Entry Drop due to HW Limit Exceeded"
                type: str
            l4_entry_list_alloc:
                description:
                - "L4 Entry list alloc"
                type: str
            l4_entry_list_free:
                description:
                - "L4 Entry list free"
                type: str
            l4_entry_list_alloc_failure:
                description:
                - "L4 Entry list alloc failures"
                type: str
            ip_node_alloc:
                description:
                - "Node alloc"
                type: str
            ip_node_free:
                description:
                - "Node free"
                type: str
            ip_node_alloc_failure:
                description:
                - "Node alloc failures"
                type: str
            ip_port_block_alloc:
                description:
                - "Port block alloc"
                type: str
            ip_port_block_free:
                description:
                - "Port block free"
                type: str
            ip_port_block_alloc_failure:
                description:
                - "Port block alloc failure"
                type: str
            ip_other_block_alloc:
                description:
                - "Other block alloc"
                type: str
            ip_other_block_free:
                description:
                - "Other block free"
                type: str
            ip_other_block_alloc_failure:
                description:
                - "Other block alloc failure"
                type: str
            entry_added_shadow:
                description:
                - "Entry added shadow"
                type: str
            entry_invalidated:
                description:
                - "Entry invalidated"
                type: str
            l3_entry_add_to_bgp_failure:
                description:
                - "L3 Entry BGP add failures"
                type: str
            l3_entry_remove_from_bgp_failure:
                description:
                - "L3 entry BGP remove failures"
                type: str
            l3_entry_add_to_hw_failure:
                description:
                - "L3 entry HW add failure"
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
    "disable_nat_ip_by_bgp",
    "ip_entries",
    "l4_entries",
    "logging",
    "max_hw_entries",
    "packets_per_second",
    "sampling_enable",
    "stats",
    "toggle",
    "uuid",
    "zone",
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
        'toggle': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'logging': {
            'type': 'dict',
            'logging_toggle': {
                'type': 'str',
                'choices': ['enable', 'disable']
            }
        },
        'packets_per_second': {
            'type': 'dict',
            'ip': {
                'type': 'int',
            },
            'action': {
                'type': 'dict',
                'action_type': {
                    'type': 'str',
                    'choices': ['log', 'drop', 'redistribute-route']
                },
                'route_map': {
                    'type': 'str',
                },
                'expiration': {
                    'type': 'int',
                },
                'timer_multiply_max': {
                    'type': 'int',
                },
                'remove_wait_timer': {
                    'type': 'int',
                }
            },
            'tcp': {
                'type': 'int',
            },
            'udp': {
                'type': 'int',
            },
            'other': {
                'type': 'int',
            },
            'include_existing_session': {
                'type': 'bool',
            }
        },
        'max_hw_entries': {
            'type': 'int',
        },
        'zone': {
            'type': 'str',
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
                    'all', 'l3_entry_added', 'l3_entry_deleted',
                    'l3_entry_added_to_bgp', 'l3_entry_removed_from_bgp',
                    'l3_entry_added_to_hw', 'l3_entry_removed_from_hw',
                    'l3_entry_too_many', 'l3_entry_match_drop',
                    'l3_entry_match_drop_hw', 'l3_entry_drop_max_hw_exceeded',
                    'l4_entry_added', 'l4_entry_deleted',
                    'l4_entry_added_to_hw', 'l4_entry_removed_from_hw',
                    'l4_hw_out_of_entries', 'l4_entry_match_drop',
                    'l4_entry_match_drop_hw', 'l4_entry_drop_max_hw_exceeded',
                    'l4_entry_list_alloc', 'l4_entry_list_free',
                    'l4_entry_list_alloc_failure', 'ip_node_alloc',
                    'ip_node_free', 'ip_node_alloc_failure',
                    'ip_port_block_alloc', 'ip_port_block_free',
                    'ip_port_block_alloc_failure', 'ip_other_block_alloc',
                    'ip_other_block_free', 'ip_other_block_alloc_failure',
                    'entry_added_shadow', 'entry_invalidated',
                    'l3_entry_add_to_bgp_failure',
                    'l3_entry_remove_from_bgp_failure',
                    'l3_entry_add_to_hw_failure'
                ]
            }
        },
        'l4_entries': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'ip_entries': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'disable_nat_ip_by_bgp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'stats': {
            'type': 'dict',
            'l3_entry_added': {
                'type': 'str',
            },
            'l3_entry_deleted': {
                'type': 'str',
            },
            'l3_entry_added_to_bgp': {
                'type': 'str',
            },
            'l3_entry_removed_from_bgp': {
                'type': 'str',
            },
            'l3_entry_added_to_hw': {
                'type': 'str',
            },
            'l3_entry_removed_from_hw': {
                'type': 'str',
            },
            'l3_entry_too_many': {
                'type': 'str',
            },
            'l3_entry_match_drop': {
                'type': 'str',
            },
            'l3_entry_match_drop_hw': {
                'type': 'str',
            },
            'l3_entry_drop_max_hw_exceeded': {
                'type': 'str',
            },
            'l4_entry_added': {
                'type': 'str',
            },
            'l4_entry_deleted': {
                'type': 'str',
            },
            'l4_entry_added_to_hw': {
                'type': 'str',
            },
            'l4_entry_removed_from_hw': {
                'type': 'str',
            },
            'l4_hw_out_of_entries': {
                'type': 'str',
            },
            'l4_entry_match_drop': {
                'type': 'str',
            },
            'l4_entry_match_drop_hw': {
                'type': 'str',
            },
            'l4_entry_drop_max_hw_exceeded': {
                'type': 'str',
            },
            'l4_entry_list_alloc': {
                'type': 'str',
            },
            'l4_entry_list_free': {
                'type': 'str',
            },
            'l4_entry_list_alloc_failure': {
                'type': 'str',
            },
            'ip_node_alloc': {
                'type': 'str',
            },
            'ip_node_free': {
                'type': 'str',
            },
            'ip_node_alloc_failure': {
                'type': 'str',
            },
            'ip_port_block_alloc': {
                'type': 'str',
            },
            'ip_port_block_free': {
                'type': 'str',
            },
            'ip_port_block_alloc_failure': {
                'type': 'str',
            },
            'ip_other_block_alloc': {
                'type': 'str',
            },
            'ip_other_block_free': {
                'type': 'str',
            },
            'ip_other_block_alloc_failure': {
                'type': 'str',
            },
            'entry_added_shadow': {
                'type': 'str',
            },
            'entry_invalidated': {
                'type': 'str',
            },
            'l3_entry_add_to_bgp_failure': {
                'type': 'str',
            },
            'l3_entry_remove_from_bgp_failure': {
                'type': 'str',
            },
            'l3_entry_add_to_hw_failure': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/ddos-protection"

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
    url_base = "/axapi/v3/cgnv6/ddos-protection"

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
        for k, v in payload["ddos-protection"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ddos-protection"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ddos-protection"][k] = v
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
    payload = build_json("ddos-protection", module)
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
