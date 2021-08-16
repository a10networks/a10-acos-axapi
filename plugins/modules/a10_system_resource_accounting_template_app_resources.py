#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_resource_accounting_template_app_resources
description:
    - Enter the application resource limits
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    gslb_device_cfg:
        description:
        - "Field gslb_device_cfg"
        type: dict
        required: False
        suboptions:
            gslb_device_max:
                description:
                - "Enter the number of gslb-device allowed (gslb-device count (default is max-
          value))"
                type: int
            gslb_device_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_geo_location_cfg:
        description:
        - "Field gslb_geo_location_cfg"
        type: dict
        required: False
        suboptions:
            gslb_geo_location_max:
                description:
                - "Enter the number of gslb-geo-location allowed (gslb-geo-location count (default
          is max-value))"
                type: int
            gslb_geo_location_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_ip_list_cfg:
        description:
        - "Field gslb_ip_list_cfg"
        type: dict
        required: False
        suboptions:
            gslb_ip_list_max:
                description:
                - "Enter the number of gslb-ip-list allowed (gslb-ip-list count (default is max-
          value))"
                type: int
            gslb_ip_list_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_policy_cfg:
        description:
        - "Field gslb_policy_cfg"
        type: dict
        required: False
        suboptions:
            gslb_policy_max:
                description:
                - "Enter the number of gslb-policy allowed (gslb-policy count (default is max-
          value))"
                type: int
            gslb_policy_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_service_cfg:
        description:
        - "Field gslb_service_cfg"
        type: dict
        required: False
        suboptions:
            gslb_service_max:
                description:
                - "Enter the number of gslb-service allowed (gslb-service count (default is max-
          value)"
                type: int
            gslb_service_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_service_ip_cfg:
        description:
        - "Field gslb_service_ip_cfg"
        type: dict
        required: False
        suboptions:
            gslb_service_ip_max:
                description:
                - "Enter the number of gslb-service-ip allowed (gslb-service-ip count (default is
          max-value))"
                type: int
            gslb_service_ip_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_service_port_cfg:
        description:
        - "Field gslb_service_port_cfg"
        type: dict
        required: False
        suboptions:
            gslb_service_port_max:
                description:
                - "Enter the number of gslb-service-port allowed ( gslb-service-port count
          (default is max-value))"
                type: int
            gslb_service_port_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_site_cfg:
        description:
        - "Field gslb_site_cfg"
        type: dict
        required: False
        suboptions:
            gslb_site_max:
                description:
                - "Enter the number of gslb-site allowed (gslb-site count (default is max-value))"
                type: int
            gslb_site_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_svc_group_cfg:
        description:
        - "Field gslb_svc_group_cfg"
        type: dict
        required: False
        suboptions:
            gslb_svc_group_max:
                description:
                - "Enter the number of gslb-svc-group allowed (gslb-svc-group count (default is
          max-value))"
                type: int
            gslb_svc_group_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_template_cfg:
        description:
        - "Field gslb_template_cfg"
        type: dict
        required: False
        suboptions:
            gslb_template_max:
                description:
                - "Enter the number of gslb-template allowed (gslb-template count (default is max-
          value))"
                type: int
            gslb_template_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    gslb_zone_cfg:
        description:
        - "Field gslb_zone_cfg"
        type: dict
        required: False
        suboptions:
            gslb_zone_max:
                description:
                - "Enter the number of gslb-zone allowed (gslb-zone count (default is max-value))"
                type: int
            gslb_zone_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    health_monitor_cfg:
        description:
        - "Field health_monitor_cfg"
        type: dict
        required: False
        suboptions:
            health_monitor_max:
                description:
                - "Enter the number of health monitors allowed (health-monitor count (default is
          max-value))"
                type: int
            health_monitor_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    real_port_cfg:
        description:
        - "Field real_port_cfg"
        type: dict
        required: False
        suboptions:
            real_port_max:
                description:
                - "Enter the number of real-ports allowed (real-port count (default is max-value))"
                type: int
            real_port_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    real_server_cfg:
        description:
        - "Field real_server_cfg"
        type: dict
        required: False
        suboptions:
            real_server_max:
                description:
                - "Enter the number of real-servers allowed (real-server count (default is max-
          value))"
                type: int
            real_server_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    service_group_cfg:
        description:
        - "Field service_group_cfg"
        type: dict
        required: False
        suboptions:
            service_group_max:
                description:
                - "Enter the number of service groups allowed (service-group count (default is
          max-value))"
                type: int
            service_group_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    virtual_server_cfg:
        description:
        - "Field virtual_server_cfg"
        type: dict
        required: False
        suboptions:
            virtual_server_max:
                description:
                - "Enter the number of virtual-servers allowed (virtual-server count (default is
          max-value))"
                type: int
            virtual_server_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
                type: int
    threshold:
        description:
        - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "gslb_device_cfg",
    "gslb_geo_location_cfg",
    "gslb_ip_list_cfg",
    "gslb_policy_cfg",
    "gslb_service_cfg",
    "gslb_service_ip_cfg",
    "gslb_service_port_cfg",
    "gslb_site_cfg",
    "gslb_svc_group_cfg",
    "gslb_template_cfg",
    "gslb_zone_cfg",
    "health_monitor_cfg",
    "real_port_cfg",
    "real_server_cfg",
    "service_group_cfg",
    "threshold",
    "uuid",
    "virtual_server_cfg",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
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
        'gslb_device_cfg': {
            'type': 'dict',
            'gslb_device_max': {
                'type': 'int',
            },
            'gslb_device_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_geo_location_cfg': {
            'type': 'dict',
            'gslb_geo_location_max': {
                'type': 'int',
            },
            'gslb_geo_location_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_ip_list_cfg': {
            'type': 'dict',
            'gslb_ip_list_max': {
                'type': 'int',
            },
            'gslb_ip_list_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_policy_cfg': {
            'type': 'dict',
            'gslb_policy_max': {
                'type': 'int',
            },
            'gslb_policy_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_service_cfg': {
            'type': 'dict',
            'gslb_service_max': {
                'type': 'int',
            },
            'gslb_service_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_service_ip_cfg': {
            'type': 'dict',
            'gslb_service_ip_max': {
                'type': 'int',
            },
            'gslb_service_ip_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_service_port_cfg': {
            'type': 'dict',
            'gslb_service_port_max': {
                'type': 'int',
            },
            'gslb_service_port_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_site_cfg': {
            'type': 'dict',
            'gslb_site_max': {
                'type': 'int',
            },
            'gslb_site_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_svc_group_cfg': {
            'type': 'dict',
            'gslb_svc_group_max': {
                'type': 'int',
            },
            'gslb_svc_group_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_template_cfg': {
            'type': 'dict',
            'gslb_template_max': {
                'type': 'int',
            },
            'gslb_template_min_guarantee': {
                'type': 'int',
            }
        },
        'gslb_zone_cfg': {
            'type': 'dict',
            'gslb_zone_max': {
                'type': 'int',
            },
            'gslb_zone_min_guarantee': {
                'type': 'int',
            }
        },
        'health_monitor_cfg': {
            'type': 'dict',
            'health_monitor_max': {
                'type': 'int',
            },
            'health_monitor_min_guarantee': {
                'type': 'int',
            }
        },
        'real_port_cfg': {
            'type': 'dict',
            'real_port_max': {
                'type': 'int',
            },
            'real_port_min_guarantee': {
                'type': 'int',
            }
        },
        'real_server_cfg': {
            'type': 'dict',
            'real_server_max': {
                'type': 'int',
            },
            'real_server_min_guarantee': {
                'type': 'int',
            }
        },
        'service_group_cfg': {
            'type': 'dict',
            'service_group_max': {
                'type': 'int',
            },
            'service_group_min_guarantee': {
                'type': 'int',
            }
        },
        'virtual_server_cfg': {
            'type': 'dict',
            'virtual_server_max': {
                'type': 'int',
            },
            'virtual_server_min_guarantee': {
                'type': 'int',
            }
        },
        'threshold': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-accounting/template/{template_name}/app-resources"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


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
    url_base = "/axapi/v3/system/resource-accounting/template/{template_name}/app-resources"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["app-resources"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["app-resources"].get(k) != v:
            change_results["changed"] = True
            config_changes["app-resources"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("app-resources", module)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
