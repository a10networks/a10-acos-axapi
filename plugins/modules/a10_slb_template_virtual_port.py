#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_virtual_port
description:
    - Virtual port template
short_description: Configures A10 slb.template.virtual-port
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
    reset_unknown_conn:
        description:
        - "Send reset back if receives TCP packet without SYN or RST flag and it does not
          belong to any existing connections"
        required: False
    ignore_tcp_msl:
        description:
        - "reclaim TCP resource immediately without MSL"
        required: False
    rate:
        description:
        - "Source IP and port rate limit (Packet rate limit)"
        required: False
    snat_msl:
        description:
        - "Source NAT MSL (Source NAT MSL value (seconds))"
        required: False
    allow_syn_otherflags:
        description:
        - "Allow initial SYN packet with other flags"
        required: False
    aflow:
        description:
        - "Use aFlow to eliminate the traffic surge"
        required: False
    conn_limit:
        description:
        - "Connection limit"
        required: False
    drop_unknown_conn:
        description:
        - "Drop conection if receives TCP packet without SYN or RST flag and it does not
          belong to any existing connections"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    reset_l7_on_failover:
        description:
        - "Send reset to L7 client and server connection upon a failover"
        required: False
    pkt_rate_type:
        description:
        - "'src-ip-port'= Source IP and port rate limit; 'src-port'= Source port rate
          limit;"
        required: False
    rate_interval:
        description:
        - "'100ms'= Use 100 ms as sampling interval; 'second'= Use 1 second as sampling
          interval;"
        required: False
    snat_port_preserve:
        description:
        - "Source NAT Port Preservation"
        required: False
    conn_rate_limit_reset:
        description:
        - "Send client reset when connection rate over limit"
        required: False
    when_rr_enable:
        description:
        - "Only do rate limit if CPU RR triggered"
        required: False
    non_syn_initiation:
        description:
        - "Allow initial TCP packet to be non-SYN"
        required: False
    conn_limit_reset:
        description:
        - "Send client reset when connection over limit"
        required: False
    dscp:
        description:
        - "Differentiated Services Code Point (DSCP to Real Server IP Mapping Value)"
        required: False
    pkt_rate_limit_reset:
        description:
        - "send client-side reset (reset after packet limit)"
        required: False
    conn_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        required: False
    conn_rate_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        required: False
    log_options:
        description:
        - "'no-logging'= Do not log over limit event; 'no-repeat-logging'= log once for
          over limit event. Default is log once per minute;"
        required: False
    name:
        description:
        - "Virtual port template name"
        required: True
    allow_vip_to_rport_mapping:
        description:
        - "Allow mapping of VIP to real port"
        required: False
    pkt_rate_interval:
        description:
        - "'100ms'= Source IP and port rate limit per 100ms; 'second'= Source IP and port
          rate limit per second (default);"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    conn_rate_limit:
        description:
        - "Connection rate limit"
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
    "aflow",
    "allow_syn_otherflags",
    "allow_vip_to_rport_mapping",
    "conn_limit",
    "conn_limit_no_logging",
    "conn_limit_reset",
    "conn_rate_limit",
    "conn_rate_limit_no_logging",
    "conn_rate_limit_reset",
    "drop_unknown_conn",
    "dscp",
    "ignore_tcp_msl",
    "log_options",
    "name",
    "non_syn_initiation",
    "pkt_rate_interval",
    "pkt_rate_limit_reset",
    "pkt_rate_type",
    "rate",
    "rate_interval",
    "reset_l7_on_failover",
    "reset_unknown_conn",
    "snat_msl",
    "snat_port_preserve",
    "user_tag",
    "uuid",
    "when_rr_enable",
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
        'reset_unknown_conn': {
            'type': 'bool',
        },
        'ignore_tcp_msl': {
            'type': 'bool',
        },
        'rate': {
            'type': 'int',
        },
        'snat_msl': {
            'type': 'int',
        },
        'allow_syn_otherflags': {
            'type': 'bool',
        },
        'aflow': {
            'type': 'bool',
        },
        'conn_limit': {
            'type': 'int',
        },
        'drop_unknown_conn': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'reset_l7_on_failover': {
            'type': 'bool',
        },
        'pkt_rate_type': {
            'type': 'str',
            'choices': ['src-ip-port', 'src-port']
        },
        'rate_interval': {
            'type': 'str',
            'choices': ['100ms', 'second']
        },
        'snat_port_preserve': {
            'type': 'bool',
        },
        'conn_rate_limit_reset': {
            'type': 'bool',
        },
        'when_rr_enable': {
            'type': 'bool',
        },
        'non_syn_initiation': {
            'type': 'bool',
        },
        'conn_limit_reset': {
            'type': 'bool',
        },
        'dscp': {
            'type': 'int',
        },
        'pkt_rate_limit_reset': {
            'type': 'int',
        },
        'conn_limit_no_logging': {
            'type': 'bool',
        },
        'conn_rate_limit_no_logging': {
            'type': 'bool',
        },
        'log_options': {
            'type': 'str',
            'choices': ['no-logging', 'no-repeat-logging']
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'allow_vip_to_rport_mapping': {
            'type': 'bool',
        },
        'pkt_rate_interval': {
            'type': 'str',
            'choices': ['100ms', 'second']
        },
        'user_tag': {
            'type': 'str',
        },
        'conn_rate_limit': {
            'type': 'int',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/slb/template/virtual-port/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["virtual-port"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["virtual-port"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["virtual-port"][k] = v
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
    payload = build_json("virtual-port", module)
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
