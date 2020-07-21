#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_ospf_redistribute
description:
    - Redistribute information from another routing protocol
short_description: Configures A10 router.ospf.redistribute
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    ospf_process_id:
        description:
        - Key to identify parent object
    redist_list:
        description:
        - "Field redist_list"
        required: False
        suboptions:
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
            ntype:
                description:
                - "'bgp'= Border Gateway Protocol (BGP); 'connected'= Connected; 'floating-ip'=
          Floating IP; 'ip-nat-list'= IP NAT list; 'lw4o6'= LW4O6 Prefix; 'nat-map'= NAT
          MAP Prefix; 'isis'= ISO IS-IS; 'rip'= Routing Information Protocol (RIP);
          'static'= Static routes;"
            metric_type:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics;"
            tag:
                description:
                - "Set tag for routes redistributed into OSPF (32-bit tag value)"
    ospf_list:
        description:
        - "Field ospf_list"
        required: False
        suboptions:
            tag_ospf:
                description:
                - "Set tag for routes redistributed into OSPF (32-bit tag value)"
            process_id:
                description:
                - "OSPF process ID"
            route_map_ospf:
                description:
                - "Route map reference (Pointer to route-map entries)"
            metric_ospf:
                description:
                - "OSPF default metric (OSPF metric)"
            ospf:
                description:
                - "Open Shortest Path First (OSPF)"
            metric_type_ospf:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics;"
    uuid:
        description:
        - "uuid of the object"
        required: False
    ip_nat_floating_list:
        description:
        - "Field ip_nat_floating_list"
        required: False
        suboptions:
            ip_nat_floating_IP_forward:
                description:
                - "Floating-IP as forward address"
            ip_nat_prefix:
                description:
                - "Address"
    vip_list:
        description:
        - "Field vip_list"
        required: False
        suboptions:
            metric_type_vip:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics;"
            tag_vip:
                description:
                - "Set tag for routes redistributed into OSPF (32-bit tag value)"
            route_map_vip:
                description:
                - "Route map reference (Pointer to route-map entries)"
            type_vip:
                description:
                - "'only-flagged'= Selected Virtual IP (VIP); 'only-not-flagged'= Only not
          flagged;"
            metric_vip:
                description:
                - "OSPF default metric (OSPF metric)"
    route_map_ip_nat:
        description:
        - "Route map reference (Pointer to route-map entries)"
        required: False
    ip_nat:
        description:
        - "IP-NAT"
        required: False
    metric_ip_nat:
        description:
        - "OSPF default metric (OSPF metric)"
        required: False
    tag_ip_nat:
        description:
        - "Set tag for routes redistributed into OSPF (32-bit tag value)"
        required: False
    vip_floating_list:
        description:
        - "Field vip_floating_list"
        required: False
        suboptions:
            vip_address:
                description:
                - "Address"
            vip_floating_IP_forward:
                description:
                - "Floating-IP as forward address"
    metric_type_ip_nat:
        description:
        - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics;"
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
    "ip_nat",
    "ip_nat_floating_list",
    "metric_ip_nat",
    "metric_type_ip_nat",
    "ospf_list",
    "redist_list",
    "route_map_ip_nat",
    "tag_ip_nat",
    "uuid",
    "vip_floating_list",
    "vip_list",
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
        'redist_list': {
            'type': 'list',
            'metric': {
                'type': 'int',
            },
            'route_map': {
                'type': 'str',
            },
            'ntype': {
                'type':
                'str',
                'choices': [
                    'bgp', 'connected', 'floating-ip', 'ip-nat-list', 'lw4o6',
                    'nat-map', 'isis', 'rip', 'static'
                ]
            },
            'metric_type': {
                'type': 'str',
                'choices': ['1', '2']
            },
            'tag': {
                'type': 'int',
            }
        },
        'ospf_list': {
            'type': 'list',
            'tag_ospf': {
                'type': 'int',
            },
            'process_id': {
                'type': 'int',
            },
            'route_map_ospf': {
                'type': 'str',
            },
            'metric_ospf': {
                'type': 'int',
            },
            'ospf': {
                'type': 'bool',
            },
            'metric_type_ospf': {
                'type': 'str',
                'choices': ['1', '2']
            }
        },
        'uuid': {
            'type': 'str',
        },
        'ip_nat_floating_list': {
            'type': 'list',
            'ip_nat_floating_IP_forward': {
                'type': 'str',
            },
            'ip_nat_prefix': {
                'type': 'str',
            }
        },
        'vip_list': {
            'type': 'list',
            'metric_type_vip': {
                'type': 'str',
                'choices': ['1', '2']
            },
            'tag_vip': {
                'type': 'int',
            },
            'route_map_vip': {
                'type': 'str',
            },
            'type_vip': {
                'type': 'str',
                'choices': ['only-flagged', 'only-not-flagged']
            },
            'metric_vip': {
                'type': 'int',
            }
        },
        'route_map_ip_nat': {
            'type': 'str',
        },
        'ip_nat': {
            'type': 'bool',
        },
        'metric_ip_nat': {
            'type': 'int',
        },
        'tag_ip_nat': {
            'type': 'int',
        },
        'vip_floating_list': {
            'type': 'list',
            'vip_address': {
                'type': 'str',
            },
            'vip_floating_IP_forward': {
                'type': 'str',
            }
        },
        'metric_type_ip_nat': {
            'type': 'str',
            'choices': ['1', '2']
        }
    })
    # Parent keys
    rv.update(dict(ospf_process_id=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/redistribute"

    f_dict = {}
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

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
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/redistribute"

    f_dict = {}
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
    if existing_config:
        for k, v in payload["redistribute"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["redistribute"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["redistribute"][k] = v
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
    payload = build_json("redistribute", module)
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
