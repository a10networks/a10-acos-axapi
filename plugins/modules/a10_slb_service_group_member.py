#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_service_group_member
description:
    - Service Group Member
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
    service_group_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    name:
        description:
        - "Member name"
        type: str
        required: True
    port:
        description:
        - "Port number"
        type: int
        required: True
    fqdn_name:
        description:
        - "Server hostname - Not applicable if real server is already defined"
        type: str
        required: False
    resolve_as:
        description:
        - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use
          AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as
          AAAA Query to resolve FQDN;"
        type: str
        required: False
    host:
        description:
        - "IP Address - Not applicable if real server is already defined"
        type: str
        required: False
    server_ipv6_addr:
        description:
        - "IPV6 Address - Not applicable if real server is already defined"
        type: str
        required: False
    member_state:
        description:
        - "'enable'= Enable member service port; 'disable'= Disable member service port;
          'disable-with-health-check'= disable member service port, but health check
          work;"
        type: str
        required: False
    member_stats_data_disable:
        description:
        - "Disable statistical data collection"
        type: bool
        required: False
    member_template:
        description:
        - "Real server port template (Real server port template name)"
        type: str
        required: False
    member_priority:
        description:
        - "Priority of Port in the Group (Priority of Port in the Group, default is 1)"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
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
                - "'all'= all; 'total_fwd_bytes'= Bytes processed in forward direction;
          'total_fwd_pkts'= Packets processed in forward direction; 'total_rev_bytes'=
          Bytes processed in reverse direction; 'total_rev_pkts'= Packets processed in
          reverse direction; 'total_conn'= Total established connections;
          'total_rev_pkts_inspected'= Total reverse packets inspected;
          'total_rev_pkts_inspected_status_code_2xx'= Total reverse packets inspected
          status code 2xx; 'total_rev_pkts_inspected_status_code_non_5xx'= Total reverse
          packets inspected status code non 5xx; 'curr_req'= Current requests;
          'total_req'= Total requests; 'total_req_succ'= Total requests successful;
          'peak_conn'= Peak connections; 'response_time'= Response time;
          'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response
          time; 'curr_ssl_conn'= Current SSL connections; 'total_ssl_conn'= Total SSL
          connections; 'curr_conn_overflow'= Current connection counter overflow count;
          'state_flaps'= State flaps count;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "Field state"
                type: str
            hm_key:
                description:
                - "Field hm_key"
                type: int
            hm_index:
                description:
                - "Field hm_index"
                type: int
            drs_list:
                description:
                - "Field drs_list"
                type: list
            alt_list:
                description:
                - "Field alt_list"
                type: list
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current established connections"
                type: str
            total_fwd_bytes:
                description:
                - "Bytes processed in forward direction"
                type: str
            total_fwd_pkts:
                description:
                - "Packets processed in forward direction"
                type: str
            total_rev_bytes:
                description:
                - "Bytes processed in reverse direction"
                type: str
            total_rev_pkts:
                description:
                - "Packets processed in reverse direction"
                type: str
            total_conn:
                description:
                - "Total established connections"
                type: str
            total_rev_pkts_inspected:
                description:
                - "Total reverse packets inspected"
                type: str
            total_rev_pkts_inspected_status_code_2xx:
                description:
                - "Total reverse packets inspected status code 2xx"
                type: str
            total_rev_pkts_inspected_status_code_non_5xx:
                description:
                - "Total reverse packets inspected status code non 5xx"
                type: str
            curr_req:
                description:
                - "Current requests"
                type: str
            total_req:
                description:
                - "Total requests"
                type: str
            total_req_succ:
                description:
                - "Total requests successful"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            response_time:
                description:
                - "Response time"
                type: str
            fastest_rsp_time:
                description:
                - "Fastest response time"
                type: str
            slowest_rsp_time:
                description:
                - "Slowest response time"
                type: str
            curr_ssl_conn:
                description:
                - "Current SSL connections"
                type: str
            total_ssl_conn:
                description:
                - "Total SSL connections"
                type: str
            curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
                type: str
            state_flaps:
                description:
                - "State flaps count"
                type: str
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int

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
    "fqdn_name",
    "host",
    "member_priority",
    "member_state",
    "member_stats_data_disable",
    "member_template",
    "name",
    "oper",
    "port",
    "resolve_as",
    "sampling_enable",
    "server_ipv6_addr",
    "stats",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'port': {
            'type': 'int',
            'required': True,
        },
        'fqdn_name': {
            'type': 'str',
        },
        'resolve_as': {
            'type':
            'str',
            'choices':
            ['resolve-to-ipv4', 'resolve-to-ipv6', 'resolve-to-ipv4-and-ipv6']
        },
        'host': {
            'type': 'str',
        },
        'server_ipv6_addr': {
            'type': 'str',
        },
        'member_state': {
            'type': 'str',
            'choices': ['enable', 'disable', 'disable-with-health-check']
        },
        'member_stats_data_disable': {
            'type': 'bool',
        },
        'member_template': {
            'type': 'str',
        },
        'member_priority': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'total_fwd_bytes', 'total_fwd_pkts',
                    'total_rev_bytes', 'total_rev_pkts', 'total_conn',
                    'total_rev_pkts_inspected',
                    'total_rev_pkts_inspected_status_code_2xx',
                    'total_rev_pkts_inspected_status_code_non_5xx', 'curr_req',
                    'total_req', 'total_req_succ', 'peak_conn',
                    'response_time', 'fastest_rsp_time', 'slowest_rsp_time',
                    'curr_ssl_conn', 'total_ssl_conn', 'curr_conn_overflow',
                    'state_flaps'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type':
                'str',
                'choices': [
                    'UP', 'DOWN', 'MAINTENANCE', 'DIS-UP', 'DIS-DOWN',
                    'DIS-MAINTENANCE', 'DIS-DAMP'
                ]
            },
            'hm_key': {
                'type': 'int',
            },
            'hm_index': {
                'type': 'int',
            },
            'drs_list': {
                'type': 'list',
                'drs_name': {
                    'type': 'str',
                },
                'drs_state': {
                    'type': 'str',
                },
                'drs_hm_key': {
                    'type': 'int',
                },
                'drs_hm_index': {
                    'type': 'int',
                },
                'drs_port': {
                    'type': 'int',
                },
                'drs_priority': {
                    'type': 'int',
                },
                'drs_curr_conn': {
                    'type': 'int',
                },
                'drs_pers_conn': {
                    'type': 'int',
                },
                'drs_total_conn': {
                    'type': 'int',
                },
                'drs_curr_req': {
                    'type': 'int',
                },
                'drs_total_req': {
                    'type': 'int',
                },
                'drs_total_req_succ': {
                    'type': 'int',
                },
                'drs_rev_pkts': {
                    'type': 'int',
                },
                'drs_fwd_pkts': {
                    'type': 'int',
                },
                'drs_rev_bts': {
                    'type': 'int',
                },
                'drs_fwd_bts': {
                    'type': 'int',
                },
                'drs_peak_conn': {
                    'type': 'int',
                },
                'drs_rsp_time': {
                    'type': 'int',
                },
                'drs_frsp_time': {
                    'type': 'int',
                },
                'drs_srsp_time': {
                    'type': 'int',
                }
            },
            'alt_list': {
                'type': 'list',
                'alt_name': {
                    'type': 'str',
                },
                'alt_port': {
                    'type': 'int',
                },
                'alt_state': {
                    'type': 'str',
                },
                'alt_curr_conn': {
                    'type': 'int',
                },
                'alt_total_conn': {
                    'type': 'int',
                },
                'alt_rev_pkts': {
                    'type': 'int',
                },
                'alt_fwd_pkts': {
                    'type': 'int',
                },
                'alt_peak_conn': {
                    'type': 'int',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'curr_conn': {
                'type': 'str',
            },
            'total_fwd_bytes': {
                'type': 'str',
            },
            'total_fwd_pkts': {
                'type': 'str',
            },
            'total_rev_bytes': {
                'type': 'str',
            },
            'total_rev_pkts': {
                'type': 'str',
            },
            'total_conn': {
                'type': 'str',
            },
            'total_rev_pkts_inspected': {
                'type': 'str',
            },
            'total_rev_pkts_inspected_status_code_2xx': {
                'type': 'str',
            },
            'total_rev_pkts_inspected_status_code_non_5xx': {
                'type': 'str',
            },
            'curr_req': {
                'type': 'str',
            },
            'total_req': {
                'type': 'str',
            },
            'total_req_succ': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'str',
            },
            'response_time': {
                'type': 'str',
            },
            'fastest_rsp_time': {
                'type': 'str',
            },
            'slowest_rsp_time': {
                'type': 'str',
            },
            'curr_ssl_conn': {
                'type': 'str',
            },
            'total_ssl_conn': {
                'type': 'str',
            },
            'curr_conn_overflow': {
                'type': 'str',
            },
            'state_flaps': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            }
        }
    })
    # Parent keys
    rv.update(dict(service_group_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    f_dict["name"] = module.params["name"]
    f_dict["port"] = module.params["port"]
    f_dict["service_group_name"] = module.params["service_group_name"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


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


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/slb/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    f_dict["name"] = ""
    f_dict["port"] = ""
    f_dict["service_group_name"] = module.params["service_group_name"]

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
        for k, v in payload["member"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["member"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["member"][k] = v
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
    payload = build_json("member", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
