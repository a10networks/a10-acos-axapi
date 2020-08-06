#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_server
description:
    - Server template
short_description: Configures A10 slb.template.server
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
    health_check_disable:
        description:
        - "Disable configured health check configuration"
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for real server;
          'stats-data-disable'= Disable statistical data collection for real server;"
        required: False
    slow_start:
        description:
        - "Slowly ramp up the connection number after server is up"
        required: False
    weight:
        description:
        - "Weight for the Real Servers (Connection Weight (default is 1))"
        required: False
    bw_rate_limit:
        description:
        - "Configure bandwidth rate limit on real server (Bandwidth rate limit in Kbps)"
        required: False
    spoofing_cache:
        description:
        - "Servers under the template are spoofing cache"
        required: False
    conn_limit:
        description:
        - "Connection limit"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    resume:
        description:
        - "Resume accepting new connection after connection number drops below threshold
          (Connection resume threshold)"
        required: False
    max_dynamic_server:
        description:
        - "Maximum dynamic server number (Maximum dynamic server number (default is 255))"
        required: False
    rate_interval:
        description:
        - "'100ms'= Use 100 ms as sampling interval; 'second'= Use 1 second as sampling
          interval;"
        required: False
    till:
        description:
        - "Slow start ends when slow start connection limit reaches a number (default
          4096) (Slow start ends when connection limit reaches this number)"
        required: False
    add:
        description:
        - "Slow start connection limit add by a number every interval (Add by this number
          every interval)"
        required: False
    min_ttl_ratio:
        description:
        - "Minimum TTL to DNS query interval ratio (Minimum TTL ratio (default is 2))"
        required: False
    bw_rate_limit_no_logging:
        description:
        - "Do not log bandwidth rate limit related state transitions"
        required: False
    dynamic_server_prefix:
        description:
        - "Prefix of dynamic server (Prefix of dynamic server (default is 'DRS'))"
        required: False
    initial_slow_start:
        description:
        - "Initial slow start connection limit (default 128)"
        required: False
    every:
        description:
        - "Slow start connection limit increment interval (default 10)"
        required: False
    conn_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on real server"
        required: False
    conn_rate_limit_no_logging:
        description:
        - "Do not log connection over limit event"
        required: False
    name:
        description:
        - "Server template name"
        required: True
    bw_rate_limit_duration:
        description:
        - "Duration in seconds the observed rate needs to honor"
        required: False
    bw_rate_limit_resume:
        description:
        - "Resume server selection after bandwidth drops below this threshold (in Kbps)
          (Bandwidth rate limit resume threshold (in Kbps))"
        required: False
    bw_rate_limit_acct:
        description:
        - "'to-server-only'= Only account for traffic sent to server; 'from-server-only'=
          Only account for traffic received from server; 'all'= Account for all traffic
          sent to and received from server;"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    times:
        description:
        - "Slow start connection limit multiply by a number every interval (default 2)
          (Multiply by this number every interval)"
        required: False
    log_selection_failure:
        description:
        - "Enable real-time logging for server selection failure event"
        required: False
    conn_rate_limit:
        description:
        - "Connection rate limit"
        required: False
    dns_query_interval:
        description:
        - "The interval to query DNS server for the hostname (DNS query interval (in
          minute, default is 10))"
        required: False
    health_check:
        description:
        - "Health Check Monitor (Health monitor name)"
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
    "add",
    "bw_rate_limit",
    "bw_rate_limit_acct",
    "bw_rate_limit_duration",
    "bw_rate_limit_no_logging",
    "bw_rate_limit_resume",
    "conn_limit",
    "conn_limit_no_logging",
    "conn_rate_limit",
    "conn_rate_limit_no_logging",
    "dns_query_interval",
    "dynamic_server_prefix",
    "every",
    "extended_stats",
    "health_check",
    "health_check_disable",
    "initial_slow_start",
    "log_selection_failure",
    "max_dynamic_server",
    "min_ttl_ratio",
    "name",
    "rate_interval",
    "resume",
    "slow_start",
    "spoofing_cache",
    "stats_data_action",
    "till",
    "times",
    "user_tag",
    "uuid",
    "weight",
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
        'health_check_disable': {
            'type': 'bool',
        },
        'stats_data_action': {
            'type': 'str',
            'choices': ['stats-data-enable', 'stats-data-disable']
        },
        'slow_start': {
            'type': 'bool',
        },
        'weight': {
            'type': 'int',
        },
        'bw_rate_limit': {
            'type': 'int',
        },
        'spoofing_cache': {
            'type': 'bool',
        },
        'conn_limit': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'resume': {
            'type': 'int',
        },
        'max_dynamic_server': {
            'type': 'int',
        },
        'rate_interval': {
            'type': 'str',
            'choices': ['100ms', 'second']
        },
        'till': {
            'type': 'int',
        },
        'add': {
            'type': 'int',
        },
        'min_ttl_ratio': {
            'type': 'int',
        },
        'bw_rate_limit_no_logging': {
            'type': 'bool',
        },
        'dynamic_server_prefix': {
            'type': 'str',
        },
        'initial_slow_start': {
            'type': 'int',
        },
        'every': {
            'type': 'int',
        },
        'conn_limit_no_logging': {
            'type': 'bool',
        },
        'extended_stats': {
            'type': 'bool',
        },
        'conn_rate_limit_no_logging': {
            'type': 'bool',
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'bw_rate_limit_duration': {
            'type': 'int',
        },
        'bw_rate_limit_resume': {
            'type': 'int',
        },
        'bw_rate_limit_acct': {
            'type': 'str',
            'choices': ['to-server-only', 'from-server-only', 'all']
        },
        'user_tag': {
            'type': 'str',
        },
        'times': {
            'type': 'int',
        },
        'log_selection_failure': {
            'type': 'bool',
        },
        'conn_rate_limit': {
            'type': 'int',
        },
        'dns_query_interval': {
            'type': 'int',
        },
        'health_check': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server/{name}"

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
    url_base = "/axapi/v3/slb/template/server/{name}"

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
        for k, v in payload["server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["server"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["server"][k] = v
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
    payload = build_json("server", module)
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
