#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_sessions
description:
    - Field sessions
short_description: Configures A10 sessions
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            ext:
                description:
                - "Field ext"
            sport_rate_limit_exceed:
                description:
                - "Field sport_rate_limit_exceed"
            app:
                description:
                - "Field app"
            fw_dest_zone:
                description:
                - "Field fw_dest_zone"
            src_port:
                description:
                - "Field src_port"
            fw_dest_vserver:
                description:
                - "Field fw_dest_vserver"
            nat_port:
                description:
                - "Field nat_port"
            fw_src_obj_grp:
                description:
                - "Field fw_src_obj_grp"
            dst_ipv4_addr:
                description:
                - "Field dst_ipv4_addr"
            app_sessions:
                description:
                - "Field app_sessions"
            name_str:
                description:
                - "Field name_str"
            app_category:
                description:
                - "Field app_category"
            fw_src_rserver:
                description:
                - "Field fw_src_rserver"
            smp:
                description:
                - "Field smp"
            application:
                description:
                - "Field application"
            nat_ipv4_addr:
                description:
                - "Field nat_ipv4_addr"
            session_list:
                description:
                - "Field session_list"
            fw_dest_obj_grp:
                description:
                - "Field fw_dest_obj_grp"
            src_ipv6_prefix:
                description:
                - "Field src_ipv6_prefix"
            total_sessions:
                description:
                - "Field total_sessions"
            session_id:
                description:
                - "Field session_id"
            check_inside_user:
                description:
                - "Field check_inside_user"
            sport_rate_limit_curr:
                description:
                - "Field sport_rate_limit_curr"
            fw_rule:
                description:
                - "Field fw_rule"
            l4_protocol:
                description:
                - "Field l4_protocol"
            zone_name:
                description:
                - "Field zone_name"
            fw_dest_rserver:
                description:
                - "Field fw_dest_rserver"
            fw_helper_sessions:
                description:
                - "Field fw_helper_sessions"
            fw_ip_type:
                description:
                - "Field fw_ip_type"
            fw_dest_obj:
                description:
                - "Field fw_dest_obj"
            filter_type:
                description:
                - "Field filter_type"
            dst_ipv6_prefix:
                description:
                - "Field dst_ipv6_prefix"
            src_ipv6_addr:
                description:
                - "Field src_ipv6_addr"
            dst_ipv6_addr:
                description:
                - "Field dst_ipv6_addr"
            fw_src_zone:
                description:
                - "Field fw_src_zone"
            src_ipv4_addr:
                description:
                - "Field src_ipv4_addr"
            fw_src_obj:
                description:
                - "Field fw_src_obj"
            dest_port:
                description:
                - "Field dest_port"
    ext:
        description:
        - "Field ext"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    smp:
        description:
        - "Field smp"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"


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
    "ext",
    "oper",
    "smp",
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
        'oper': {
            'type': 'dict',
            'ext': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'session_ext_list': {
                        'type': 'list',
                        'fail': {
                            'type': 'int',
                        },
                        'alloc': {
                            'type': 'int',
                        },
                        'ntype': {
                            'type': 'str',
                        },
                        'free': {
                            'type': 'int',
                        },
                        'cpu_round_robin_fail': {
                            'type': 'int',
                        }
                    }
                }
            },
            'sport_rate_limit_exceed': {
                'type': 'bool',
            },
            'app': {
                'type': 'str',
            },
            'fw_dest_zone': {
                'type': 'str',
            },
            'src_port': {
                'type': 'int',
            },
            'fw_dest_vserver': {
                'type': 'str',
            },
            'nat_port': {
                'type': 'int',
            },
            'fw_src_obj_grp': {
                'type': 'str',
            },
            'dst_ipv4_addr': {
                'type': 'str',
            },
            'app_sessions': {
                'type': 'int',
            },
            'name_str': {
                'type': 'str',
            },
            'app_category': {
                'type': 'str',
            },
            'fw_src_rserver': {
                'type': 'str',
            },
            'smp': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'session_smp_list': {
                        'type': 'list',
                        'alloc': {
                            'type': 'int',
                        },
                        'ntype': {
                            'type': 'str',
                        },
                        'free': {
                            'type': 'int',
                        },
                        'alloc_fail': {
                            'type': 'int',
                        }
                    }
                }
            },
            'application': {
                'type': 'str',
            },
            'nat_ipv4_addr': {
                'type': 'str',
            },
            'session_list': {
                'type': 'list',
                '100ms': {
                    'type': 'str',
                },
                'conn_idx': {
                    'type': 'int',
                },
                'rate': {
                    'type': 'int',
                },
                'service_name': {
                    'type': 'str',
                },
                'duration': {
                    'type': 'int',
                },
                'limit': {
                    'type': 'int',
                },
                'reverse_source': {
                    'type': 'str',
                },
                'reverse_dest': {
                    'type': 'str',
                },
                'app_type': {
                    'type': 'str',
                },
                'protocol': {
                    'type': 'str',
                },
                'rserver_name': {
                    'type': 'str',
                },
                'extension_fields_list': {
                    'type': 'list',
                    'ext_field_name': {
                        'type': 'str',
                    },
                    'ext_field_val': {
                        'type': 'str',
                    }
                },
                'hash': {
                    'type': 'int',
                },
                'sip_call_id': {
                    'type': 'str',
                },
                'app_name': {
                    'type': 'str',
                },
                'forward_dest': {
                    'type': 'str',
                },
                'peak_rate': {
                    'type': 'int',
                },
                'forward_source': {
                    'type': 'str',
                },
                'age': {
                    'type': 'int',
                },
                'drop': {
                    'type': 'int',
                },
                'bytes': {
                    'type': 'int',
                },
                'flags': {
                    'type': 'str',
                },
                'category_name': {
                    'type': 'str',
                }
            },
            'fw_dest_obj_grp': {
                'type': 'str',
            },
            'src_ipv6_prefix': {
                'type': 'str',
            },
            'total_sessions': {
                'type': 'int',
            },
            'session_id': {
                'type': 'str',
            },
            'check_inside_user': {
                'type': 'bool',
            },
            'sport_rate_limit_curr': {
                'type': 'bool',
            },
            'fw_rule': {
                'type': 'str',
            },
            'l4_protocol': {
                'type': 'str',
                'choices': ['udp', 'tcp', 'icmp', 'icmpv6']
            },
            'zone_name': {
                'type': 'str',
            },
            'fw_dest_rserver': {
                'type': 'str',
            },
            'fw_helper_sessions': {
                'type': 'bool',
            },
            'fw_ip_type': {
                'type': 'str',
                'choices': ['ipv4', 'ipv6']
            },
            'fw_dest_obj': {
                'type': 'str',
            },
            'filter_type': {
                'type':
                'str',
                'choices': [
                    'ipv4', 'ipv6', 'nat44', 'nat64', 'persist-ipv6-src-ip',
                    'persist-ipv6-dst-ip', 'persist-ipv6-ssl-id',
                    'persist-dst-ip', 'persist-src-ip', 'persist-uie',
                    'persist-ssl-id', 'radius', 'server', 'virtual-server',
                    'sip', 'sixrd', 'filter', 'ds-lite', 'dns-id-switch',
                    'local', 'fw', 'clear-all', 'full-width', 'debug',
                    'application', 'ipsec', 'diameter', 'zone',
                    'source-port-rate-limit', 'source-port-rate-limitv4',
                    'source-port-rate-limitv6'
                ]
            },
            'dst_ipv6_prefix': {
                'type': 'str',
            },
            'src_ipv6_addr': {
                'type': 'str',
            },
            'dst_ipv6_addr': {
                'type': 'str',
            },
            'fw_src_zone': {
                'type': 'str',
            },
            'src_ipv4_addr': {
                'type': 'str',
            },
            'fw_src_obj': {
                'type': 'str',
            },
            'dest_port': {
                'type': 'int',
            }
        },
        'ext': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'smp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/sessions"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/sessions"

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
        for k, v in payload["sessions"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["sessions"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["sessions"][k] = v
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
    payload = build_json("sessions", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
