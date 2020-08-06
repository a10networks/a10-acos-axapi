#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_resource_accounting_template_app_resources
description:
    - Enter the application resource limits
short_description: Configures A10 system.resource.accounting.template.app-resources
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    template_name:
        description:
        - Key to identify parent object    gslb_site_cfg:
        description:
        - "Field gslb_site_cfg"
        required: False
        suboptions:
            gslb_site_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            gslb_site_max:
                description:
                - "Enter the number of gslb-site allowed (gslb-site count (default is max-value))"
    gslb_policy_cfg:
        description:
        - "Field gslb_policy_cfg"
        required: False
        suboptions:
            gslb_policy_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            gslb_policy_max:
                description:
                - "Enter the number of gslb-policy allowed (gslb-policy count (default is max-
          value))"
    gslb_service_cfg:
        description:
        - "Field gslb_service_cfg"
        required: False
        suboptions:
            gslb_service_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            gslb_service_max:
                description:
                - "Enter the number of gslb-service allowed (gslb-service count (default is max-
          value)"
    gslb_geo_location_cfg:
        description:
        - "Field gslb_geo_location_cfg"
        required: False
        suboptions:
            gslb_geo_location_max:
                description:
                - "Enter the number of gslb-geo-location allowed (gslb-geo-location count (default
          is max-value))"
            gslb_geo_location_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    uuid:
        description:
        - "uuid of the object"
        required: False
    real_server_cfg:
        description:
        - "Field real_server_cfg"
        required: False
        suboptions:
            real_server_max:
                description:
                - "Enter the number of real-servers allowed (real-server count (default is max-
          value))"
            real_server_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    gslb_ip_list_cfg:
        description:
        - "Field gslb_ip_list_cfg"
        required: False
        suboptions:
            gslb_ip_list_max:
                description:
                - "Enter the number of gslb-ip-list allowed (gslb-ip-list count (default is max-
          value))"
            gslb_ip_list_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    gslb_template_cfg:
        description:
        - "Field gslb_template_cfg"
        required: False
        suboptions:
            gslb_template_max:
                description:
                - "Enter the number of gslb-template allowed (gslb-template count (default is max-
          value))"
            gslb_template_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    gslb_zone_cfg:
        description:
        - "Field gslb_zone_cfg"
        required: False
        suboptions:
            gslb_zone_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            gslb_zone_max:
                description:
                - "Enter the number of gslb-zone allowed (gslb-zone count (default is max-value))"
    gslb_device_cfg:
        description:
        - "Field gslb_device_cfg"
        required: False
        suboptions:
            gslb_device_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            gslb_device_max:
                description:
                - "Enter the number of gslb-device allowed (gslb-device count (default is max-
          value))"
    virtual_server_cfg:
        description:
        - "Field virtual_server_cfg"
        required: False
        suboptions:
            virtual_server_max:
                description:
                - "Enter the number of virtual-servers allowed (virtual-server count (default is
          max-value))"
            virtual_server_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    real_port_cfg:
        description:
        - "Field real_port_cfg"
        required: False
        suboptions:
            real_port_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
            real_port_max:
                description:
                - "Enter the number of real-ports allowed (real-port count (default is max-value))"
    health_monitor_cfg:
        description:
        - "Field health_monitor_cfg"
        required: False
        suboptions:
            health_monitor_max:
                description:
                - "Enter the number of health monitors allowed (health-monitor count (default is
          max-value))"
            health_monitor_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    threshold:
        description:
        - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
        required: False
    gslb_svc_group_cfg:
        description:
        - "Field gslb_svc_group_cfg"
        required: False
        suboptions:
            gslb_svc_group_max:
                description:
                - "Enter the number of gslb-svc-group allowed (gslb-svc-group count (default is
          max-value))"
            gslb_svc_group_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    service_group_cfg:
        description:
        - "Field service_group_cfg"
        required: False
        suboptions:
            service_group_max:
                description:
                - "Enter the number of service groups allowed (service-group count (default is
          max-value))"
            service_group_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    gslb_service_port_cfg:
        description:
        - "Field gslb_service_port_cfg"
        required: False
        suboptions:
            gslb_service_port_max:
                description:
                - "Enter the number of gslb-service-port allowed ( gslb-service-port count
          (default is max-value))"
            gslb_service_port_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"
    gslb_service_ip_cfg:
        description:
        - "Field gslb_service_ip_cfg"
        required: False
        suboptions:
            gslb_service_ip_max:
                description:
                - "Enter the number of gslb-service-ip allowed (gslb-service-ip count (default is
          max-value))"
            gslb_service_ip_min_guarantee:
                description:
                - "Minimum guaranteed value ( Minimum guaranteed value)"

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
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'gslb_site_cfg': {
            'type': 'dict',
            'gslb_site_min_guarantee': {
                'type': 'int',
            },
            'gslb_site_max': {
                'type': 'int',
            }
        },
        'gslb_policy_cfg': {
            'type': 'dict',
            'gslb_policy_min_guarantee': {
                'type': 'int',
            },
            'gslb_policy_max': {
                'type': 'int',
            }
        },
        'gslb_service_cfg': {
            'type': 'dict',
            'gslb_service_min_guarantee': {
                'type': 'int',
            },
            'gslb_service_max': {
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
        'uuid': {
            'type': 'str',
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
        'gslb_ip_list_cfg': {
            'type': 'dict',
            'gslb_ip_list_max': {
                'type': 'int',
            },
            'gslb_ip_list_min_guarantee': {
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
            'gslb_zone_min_guarantee': {
                'type': 'int',
            },
            'gslb_zone_max': {
                'type': 'int',
            }
        },
        'gslb_device_cfg': {
            'type': 'dict',
            'gslb_device_min_guarantee': {
                'type': 'int',
            },
            'gslb_device_max': {
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
        'real_port_cfg': {
            'type': 'dict',
            'real_port_min_guarantee': {
                'type': 'int',
            },
            'real_port_max': {
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
        'threshold': {
            'type': 'int',
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
        'service_group_cfg': {
            'type': 'dict',
            'service_group_max': {
                'type': 'int',
            },
            'service_group_min_guarantee': {
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
        'gslb_service_ip_cfg': {
            'type': 'dict',
            'gslb_service_ip_max': {
                'type': 'int',
            },
            'gslb_service_ip_min_guarantee': {
                'type': 'int',
            }
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
    if existing_config:
        for k, v in payload["app-resources"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["app-resources"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["app-resources"][k] = v
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
    payload = build_json("app-resources", module)
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
