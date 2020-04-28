#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_system_resource_accounting_template
description:
    - Create resource accounting template
short_description: Configures A10 system.resource.accounting.template
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - present
          - absent
          - noop
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
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
    app_resources:
        description:
        - "Field app_resources"
        required: False
        suboptions:
            gslb_site_cfg:
                description:
                - "Field gslb_site_cfg"
            gslb_policy_cfg:
                description:
                - "Field gslb_policy_cfg"
            gslb_service_cfg:
                description:
                - "Field gslb_service_cfg"
            gslb_geo_location_cfg:
                description:
                - "Field gslb_geo_location_cfg"
            uuid:
                description:
                - "uuid of the object"
            real_server_cfg:
                description:
                - "Field real_server_cfg"
            gslb_ip_list_cfg:
                description:
                - "Field gslb_ip_list_cfg"
            gslb_template_cfg:
                description:
                - "Field gslb_template_cfg"
            gslb_zone_cfg:
                description:
                - "Field gslb_zone_cfg"
            gslb_device_cfg:
                description:
                - "Field gslb_device_cfg"
            virtual_server_cfg:
                description:
                - "Field virtual_server_cfg"
            real_port_cfg:
                description:
                - "Field real_port_cfg"
            health_monitor_cfg:
                description:
                - "Field health_monitor_cfg"
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
            gslb_svc_group_cfg:
                description:
                - "Field gslb_svc_group_cfg"
            service_group_cfg:
                description:
                - "Field service_group_cfg"
            gslb_service_port_cfg:
                description:
                - "Field gslb_service_port_cfg"
            gslb_service_ip_cfg:
                description:
                - "Field gslb_service_ip_cfg"
    name:
        description:
        - "Enter template name"
        required: True
    system_resources:
        description:
        - "Field system_resources"
        required: False
        suboptions:
            l4_session_limit_cfg:
                description:
                - "Field l4_session_limit_cfg"
            l7cps_limit_cfg:
                description:
                - "Field l7cps_limit_cfg"
            l4cps_limit_cfg:
                description:
                - "Field l4cps_limit_cfg"
            uuid:
                description:
                - "uuid of the object"
            natcps_limit_cfg:
                description:
                - "Field natcps_limit_cfg"
            sslcps_limit_cfg:
                description:
                - "Field sslcps_limit_cfg"
            fwcps_limit_cfg:
                description:
                - "Field fwcps_limit_cfg"
            ssl_throughput_limit_cfg:
                description:
                - "Field ssl_throughput_limit_cfg"
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
            bw_limit_cfg:
                description:
                - "Field bw_limit_cfg"
            concurrent_session_limit_cfg:
                description:
                - "Field concurrent_session_limit_cfg"
    user_tag:
        description:
        - "Customized tag"
        required: False
    network_resources:
        description:
        - "Field network_resources"
        required: False
        suboptions:
            static_ipv6_route_cfg:
                description:
                - "Field static_ipv6_route_cfg"
            uuid:
                description:
                - "uuid of the object"
            ipv4_acl_line_cfg:
                description:
                - "Field ipv4_acl_line_cfg"
            static_ipv4_route_cfg:
                description:
                - "Field static_ipv4_route_cfg"
            static_arp_cfg:
                description:
                - "Field static_arp_cfg"
            object_group_clause_cfg:
                description:
                - "Field object_group_clause_cfg"
            static_mac_cfg:
                description:
                - "Field static_mac_cfg"
            object_group_cfg:
                description:
                - "Field object_group_cfg"
            static_neighbor_cfg:
                description:
                - "Field static_neighbor_cfg"
            threshold:
                description:
                - "Enter the threshold as a percentage (Threshold in percentage(default is 100%))"
            ipv6_acl_line_cfg:
                description:
                - "Field ipv6_acl_line_cfg"
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["app_resources","name","network_resources","system_resources","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        app_resources=dict(type='dict',gslb_site_cfg=dict(type='dict',gslb_site_min_guarantee=dict(type='int',),gslb_site_max=dict(type='int',)),gslb_policy_cfg=dict(type='dict',gslb_policy_min_guarantee=dict(type='int',),gslb_policy_max=dict(type='int',)),gslb_service_cfg=dict(type='dict',gslb_service_min_guarantee=dict(type='int',),gslb_service_max=dict(type='int',)),gslb_geo_location_cfg=dict(type='dict',gslb_geo_location_max=dict(type='int',),gslb_geo_location_min_guarantee=dict(type='int',)),uuid=dict(type='str',),real_server_cfg=dict(type='dict',real_server_max=dict(type='int',),real_server_min_guarantee=dict(type='int',)),gslb_ip_list_cfg=dict(type='dict',gslb_ip_list_max=dict(type='int',),gslb_ip_list_min_guarantee=dict(type='int',)),gslb_template_cfg=dict(type='dict',gslb_template_max=dict(type='int',),gslb_template_min_guarantee=dict(type='int',)),gslb_zone_cfg=dict(type='dict',gslb_zone_min_guarantee=dict(type='int',),gslb_zone_max=dict(type='int',)),gslb_device_cfg=dict(type='dict',gslb_device_min_guarantee=dict(type='int',),gslb_device_max=dict(type='int',)),virtual_server_cfg=dict(type='dict',virtual_server_max=dict(type='int',),virtual_server_min_guarantee=dict(type='int',)),real_port_cfg=dict(type='dict',real_port_min_guarantee=dict(type='int',),real_port_max=dict(type='int',)),health_monitor_cfg=dict(type='dict',health_monitor_max=dict(type='int',),health_monitor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),gslb_svc_group_cfg=dict(type='dict',gslb_svc_group_max=dict(type='int',),gslb_svc_group_min_guarantee=dict(type='int',)),service_group_cfg=dict(type='dict',service_group_max=dict(type='int',),service_group_min_guarantee=dict(type='int',)),gslb_service_port_cfg=dict(type='dict',gslb_service_port_max=dict(type='int',),gslb_service_port_min_guarantee=dict(type='int',)),gslb_service_ip_cfg=dict(type='dict',gslb_service_ip_max=dict(type='int',),gslb_service_ip_min_guarantee=dict(type='int',))),
        name=dict(type='str',required=True,),
        system_resources=dict(type='dict',l4_session_limit_cfg=dict(type='dict',l4_session_limit_max=dict(type='str',),l4_session_limit_min_guarantee=dict(type='str',)),l7cps_limit_cfg=dict(type='dict',l7cps_limit_max=dict(type='int',)),l4cps_limit_cfg=dict(type='dict',l4cps_limit_max=dict(type='int',)),uuid=dict(type='str',),natcps_limit_cfg=dict(type='dict',natcps_limit_max=dict(type='int',)),sslcps_limit_cfg=dict(type='dict',sslcps_limit_max=dict(type='int',)),fwcps_limit_cfg=dict(type='dict',fwcps_limit_max=dict(type='int',)),ssl_throughput_limit_cfg=dict(type='dict',ssl_throughput_limit_watermark_disable=dict(type='bool',),ssl_throughput_limit_max=dict(type='int',)),threshold=dict(type='int',),bw_limit_cfg=dict(type='dict',bw_limit_max=dict(type='int',),bw_limit_watermark_disable=dict(type='bool',)),concurrent_session_limit_cfg=dict(type='dict',concurrent_session_limit_max=dict(type='int',))),
        user_tag=dict(type='str',),
        network_resources=dict(type='dict',static_ipv6_route_cfg=dict(type='dict',static_ipv6_route_max=dict(type='int',),static_ipv6_route_min_guarantee=dict(type='int',)),uuid=dict(type='str',),ipv4_acl_line_cfg=dict(type='dict',ipv4_acl_line_min_guarantee=dict(type='int',),ipv4_acl_line_max=dict(type='int',)),static_ipv4_route_cfg=dict(type='dict',static_ipv4_route_max=dict(type='int',),static_ipv4_route_min_guarantee=dict(type='int',)),static_arp_cfg=dict(type='dict',static_arp_min_guarantee=dict(type='int',),static_arp_max=dict(type='int',)),object_group_clause_cfg=dict(type='dict',object_group_clause_min_guarantee=dict(type='int',),object_group_clause_max=dict(type='int',)),static_mac_cfg=dict(type='dict',static_mac_min_guarantee=dict(type='int',),static_mac_max=dict(type='int',)),object_group_cfg=dict(type='dict',object_group_min_guarantee=dict(type='int',),object_group_max=dict(type='int',)),static_neighbor_cfg=dict(type='dict',static_neighbor_max=dict(type='int',),static_neighbor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),ipv6_acl_line_cfg=dict(type='dict',ipv6_acl_line_max=dict(type='int',),ipv6_acl_line_min_guarantee=dict(type='int',))),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-accounting/template/{name}"

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

    for k,v in param.items():
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
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/resource-accounting/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

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
        for k, v in payload["template"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["template"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["template"][k] = v
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
    payload = build_json("template", module)
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()