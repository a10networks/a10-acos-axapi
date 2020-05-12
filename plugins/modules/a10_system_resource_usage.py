#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_system_resource_usage
description:
    - Configure System Resource Usage
short_description: Configures A10 system.resource-usage
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            visibility_mon_entity_default:
                description:
                - "Field visibility_mon_entity_default"
            nat_pool_addr_min:
                description:
                - "Field nat_pool_addr_min"
            radius_table_size_max:
                description:
                - "Field radius_table_size_max"
            radius_table_size_default:
                description:
                - "Field radius_table_size_default"
            auth_portal_image_file_size_default:
                description:
                - "Field auth_portal_image_file_size_default"
            auth_portal_html_file_size_max:
                description:
                - "Field auth_portal_html_file_size_max"
            aflex_table_entry_count_min:
                description:
                - "Field aflex_table_entry_count_min"
            aflex_table_entry_count_max:
                description:
                - "Field aflex_table_entry_count_max"
            visibility_mon_entity_min:
                description:
                - "Field visibility_mon_entity_min"
            authz_policy_number_default:
                description:
                - "Field authz_policy_number_default"
            auth_portal_image_file_size_max:
                description:
                - "Field auth_portal_image_file_size_max"
            aflex_table_entry_count_default:
                description:
                - "Field aflex_table_entry_count_default"
            l4_session_count_max:
                description:
                - "Field l4_session_count_max"
            aflex_file_size_default:
                description:
                - "Field aflex_file_size_default"
            l4_session_count_default:
                description:
                - "Field l4_session_count_default"
            radius_table_size_min:
                description:
                - "Field radius_table_size_min"
            nat_pool_addr_default:
                description:
                - "Field nat_pool_addr_default"
            class_list_ac_min:
                description:
                - "Field class_list_ac_min"
            class_list_ac_max:
                description:
                - "Field class_list_ac_max"
            visibility_mon_entity_max:
                description:
                - "Field visibility_mon_entity_max"
            class_list_ipv6_addr_default:
                description:
                - "Field class_list_ipv6_addr_default"
            l4_session_count_min:
                description:
                - "Field l4_session_count_min"
            auth_portal_image_file_size_min:
                description:
                - "Field auth_portal_image_file_size_min"
            class_list_ipv6_addr_max:
                description:
                - "Field class_list_ipv6_addr_max"
            aflex_file_size_min:
                description:
                - "Field aflex_file_size_min"
            aflex_authz_collection_number_default:
                description:
                - "Field aflex_authz_collection_number_default"
            authz_policy_number_max:
                description:
                - "Field authz_policy_number_max"
            authz_policy_number_min:
                description:
                - "Field authz_policy_number_min"
            class_list_ipv6_addr_min:
                description:
                - "Field class_list_ipv6_addr_min"
            aflex_file_size_max:
                description:
                - "Field aflex_file_size_max"
            auth_portal_html_file_size_default:
                description:
                - "Field auth_portal_html_file_size_default"
            aflex_authz_collection_number_min:
                description:
                - "Field aflex_authz_collection_number_min"
            nat_pool_addr_max:
                description:
                - "Field nat_pool_addr_max"
            aflex_authz_collection_number_max:
                description:
                - "Field aflex_authz_collection_number_max"
            auth_portal_html_file_size_min:
                description:
                - "Field auth_portal_html_file_size_min"
            class_list_ac_default:
                description:
                - "Field class_list_ac_default"
    l4_session_count:
        description:
        - "Total Sessions in the System"
        required: False
    nat_pool_addr_count:
        description:
        - "Total configurable NAT Pool addresses in the System"
        required: False
    max_aflex_authz_collection_number:
        description:
        - "Specify the maximum number of collections supported by aFleX authorization"
        required: False
    visibility:
        description:
        - "Field visibility"
        required: False
        suboptions:
            monitored_entity_count:
                description:
                - "Total number of monitored entities for visibility"
            uuid:
                description:
                - "uuid of the object"
    class_list_ipv6_addr_count:
        description:
        - "Total IPv6 addresses for class-list"
        required: False
    authz_policy_number:
        description:
        - "Specify the maximum number of authorization policies"
        required: False
    max_aflex_file_size:
        description:
        - "Set maximum aFleX file size (Maximum file size in KBytes, default is 32K)"
        required: False
    class_list_ac_entry_count:
        description:
        - "Total entries for AC class-list"
        required: False
    ssl_dma_memory:
        description:
        - "Total SSL DMA memory needed in units of MB. Will be rounded to closest multiple of 2MB"
        required: False
    radius_table_size:
        description:
        - "Total configurable CGNV6 RADIUS Table entries"
        required: False
    aflex_table_entry_count:
        description:
        - "Total aFleX table entry in the system (Total aFlex entry in the system)"
        required: False
    ssl_context_memory:
        description:
        - "Total SSL context memory needed in units of MB. Will be rounded to closest multiple of 2MB"
        required: False
    auth_portal_html_file_size:
        description:
        - "Specify maximum html file size for each html page in auth portal (in KB)"
        required: False
    auth_portal_image_file_size:
        description:
        - "Specify maximum image file size for default portal (in KB)"
        required: False
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
AVAILABLE_PROPERTIES = ["aflex_table_entry_count","auth_portal_html_file_size","auth_portal_image_file_size","authz_policy_number","class_list_ac_entry_count","class_list_ipv6_addr_count","l4_session_count","max_aflex_authz_collection_number","max_aflex_file_size","nat_pool_addr_count","oper","radius_table_size","ssl_context_memory","ssl_dma_memory","uuid","visibility",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', visibility_mon_entity_default=dict(type='int', ), nat_pool_addr_min=dict(type='int', ), radius_table_size_max=dict(type='int', ), radius_table_size_default=dict(type='int', ), auth_portal_image_file_size_default=dict(type='int', ), auth_portal_html_file_size_max=dict(type='int', ), aflex_table_entry_count_min=dict(type='int', ), aflex_table_entry_count_max=dict(type='int', ), visibility_mon_entity_min=dict(type='int', ), authz_policy_number_default=dict(type='int', ), auth_portal_image_file_size_max=dict(type='int', ), aflex_table_entry_count_default=dict(type='int', ), l4_session_count_max=dict(type='int', ), aflex_file_size_default=dict(type='int', ), l4_session_count_default=dict(type='int', ), radius_table_size_min=dict(type='int', ), nat_pool_addr_default=dict(type='int', ), class_list_ac_min=dict(type='int', ), class_list_ac_max=dict(type='int', ), visibility_mon_entity_max=dict(type='int', ), class_list_ipv6_addr_default=dict(type='int', ), l4_session_count_min=dict(type='int', ), auth_portal_image_file_size_min=dict(type='int', ), class_list_ipv6_addr_max=dict(type='int', ), aflex_file_size_min=dict(type='int', ), aflex_authz_collection_number_default=dict(type='int', ), authz_policy_number_max=dict(type='int', ), authz_policy_number_min=dict(type='int', ), class_list_ipv6_addr_min=dict(type='int', ), aflex_file_size_max=dict(type='int', ), auth_portal_html_file_size_default=dict(type='int', ), aflex_authz_collection_number_min=dict(type='int', ), nat_pool_addr_max=dict(type='int', ), aflex_authz_collection_number_max=dict(type='int', ), auth_portal_html_file_size_min=dict(type='int', ), class_list_ac_default=dict(type='int', )),
        l4_session_count=dict(type='int', ),
        nat_pool_addr_count=dict(type='int', ),
        max_aflex_authz_collection_number=dict(type='int', ),
        visibility=dict(type='dict', monitored_entity_count=dict(type='int', ), uuid=dict(type='str', )),
        class_list_ipv6_addr_count=dict(type='int', ),
        authz_policy_number=dict(type='int', ),
        max_aflex_file_size=dict(type='int', ),
        class_list_ac_entry_count=dict(type='int', ),
        ssl_dma_memory=dict(type='int', ),
        radius_table_size=dict(type='int', ),
        aflex_table_entry_count=dict(type='int', ),
        ssl_context_memory=dict(type='int', ),
        auth_portal_html_file_size=dict(type='int', ),
        auth_portal_image_file_size=dict(type='int', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-usage"

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
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
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
    url_base = "/axapi/v3/system/resource-usage"

    f_dict = {}

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
        for k, v in payload["resource-usage"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["resource-usage"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["resource-usage"][k] = v
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
    payload = build_json("resource-usage", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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