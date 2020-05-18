#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_visibility_monitored_entity
description:
    - Display Monitoring entities
short_description: Configures A10 visibility.monitored-entity
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
    ansible_protocol:
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
            topk:
                description:
                - "Field topk"
            sessions:
                description:
                - "Field sessions"
            all_keys:
                description:
                - "Field all_keys"
            secondary:
                description:
                - "Field secondary"
            mon_entity_list:
                description:
                - "Field mon_entity_list"
            detail:
                description:
                - "Field detail"
            primary_keys:
                description:
                - "Field primary_keys"
    topk:
        description:
        - "Field topk"
        required: False
        suboptions:
            sources:
                description:
                - "Field sources"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    sessions:
        description:
        - "Field sessions"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    detail:
        description:
        - "Field detail"
        required: False
        suboptions:
            debug:
                description:
                - "Field debug"
            uuid:
                description:
                - "uuid of the object"
    secondary:
        description:
        - "Field secondary"
        required: False
        suboptions:
            topk:
                description:
                - "Field topk"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["detail","oper","secondary","sessions","topk","uuid",]

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
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', topk=dict(type='dict', oper=dict(type='dict', metric_topk_list=dict(type='list', metric_name=dict(type='str', ), topk_list=dict(type='list', protocol=dict(type='str', ), ip_addr=dict(type='str', ), metric_value=dict(type='str', ), port=dict(type='int', )))), sources=dict(type='dict', oper=dict(type='dict', l4_proto=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), metric_topk_list=dict(type='list', metric_name=dict(type='str', ), topk_list=dict(type='list', ip_addr=dict(type='str', ), metric_value=dict(type='str', ))), l4_port=dict(type='int', )))), sessions=dict(type='dict', oper=dict(type='dict', mon_entity_list=dict(type='list', l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), session_list=dict(type='list', rev_src_ip=dict(type='str', ), fwd_src_ip=dict(type='str', ), fwd_src_port=dict(type='int', ), proto=dict(type='str', ), rev_src_port=dict(type='int', ), fwd_dst_port=dict(type='int', ), rev_dst_port=dict(type='int', ), rev_dst_ip=dict(type='str', ), fwd_dst_ip=dict(type='str', )), l4_proto=dict(type='str', ), sec_entity_list=dict(type='list', l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), session_list=dict(type='list', rev_src_ip=dict(type='str', ), fwd_src_ip=dict(type='str', ), fwd_src_port=dict(type='int', ), proto=dict(type='str', ), rev_src_port=dict(type='int', ), fwd_dst_port=dict(type='int', ), rev_dst_port=dict(type='int', ), rev_dst_ip=dict(type='str', ), fwd_dst_ip=dict(type='str', )), l4_proto=dict(type='str', ))))), all_keys=dict(type='bool', ), secondary=dict(type='dict', oper=dict(type='dict', ), topk=dict(type='dict', oper=dict(type='dict', l4_proto=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), metric_topk_list=dict(type='list', metric_name=dict(type='str', ), topk_list=dict(type='list', protocol=dict(type='str', ), ip_addr=dict(type='str', ), metric_value=dict(type='str', ), port=dict(type='int', ))), l4_port=dict(type='int', )), sources=dict(type='dict', oper=dict(type='dict', l4_proto=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), metric_topk_list=dict(type='list', metric_name=dict(type='str', ), topk_list=dict(type='list', ip_addr=dict(type='str', ), metric_value=dict(type='str', ))), l4_port=dict(type='int', ))))), mon_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), sec_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), ha_state=dict(type='str', )), ha_state=dict(type='str', )), detail=dict(type='dict', oper=dict(type='dict', all_keys=dict(type='bool', ), mon_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), entity_metric_list=dict(type='list', current=dict(type='str', ), threshold=dict(type='str', ), metric_name=dict(type='str', ), anomaly=dict(type='str', )), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), sec_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), entity_metric_list=dict(type='list', current=dict(type='str', ), threshold=dict(type='str', ), metric_name=dict(type='str', ), anomaly=dict(type='str', )), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), ha_state=dict(type='str', )), ha_state=dict(type='str', )), primary_keys=dict(type='bool', )), debug=dict(type='dict', oper=dict(type='dict', all_keys=dict(type='bool', ), mon_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), entity_metric_list=dict(type='list', std_dev=dict(type='str', ), min=dict(type='str', ), max=dict(type='str', ), metric_name=dict(type='str', ), current=dict(type='str', ), threshold=dict(type='str', ), anomaly=dict(type='str', ), mean=dict(type='str', )), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), sec_entity_list=dict(type='list', uuid=dict(type='str', ), l4_port=dict(type='int', ), entity_key=dict(type='str', ), ipv4_addr=dict(type='str', ), ipv6_addr=dict(type='str', ), entity_metric_list=dict(type='list', std_dev=dict(type='str', ), min=dict(type='str', ), max=dict(type='str', ), metric_name=dict(type='str', ), current=dict(type='str', ), threshold=dict(type='str', ), anomaly=dict(type='str', ), mean=dict(type='str', )), mode=dict(type='str', ), l4_proto=dict(type='str', ), flat_oid=dict(type='int', ), ha_state=dict(type='str', )), ha_state=dict(type='str', )), primary_keys=dict(type='bool', )))), primary_keys=dict(type='bool', )),
        topk=dict(type='dict', sources=dict(type='dict', uuid=dict(type='str', )), uuid=dict(type='str', )),
        uuid=dict(type='str', ),
        sessions=dict(type='dict', uuid=dict(type='str', )),
        detail=dict(type='dict', debug=dict(type='dict', uuid=dict(type='str', )), uuid=dict(type='str', )),
        secondary=dict(type='dict', topk=dict(type='dict', sources=dict(type='dict', uuid=dict(type='str', )), uuid=dict(type='str', )))
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/monitored-entity"

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
    url_base = "/axapi/v3/visibility/monitored-entity"

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
        for k, v in payload["monitored-entity"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["monitored-entity"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["monitored-entity"][k] = v
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
    payload = build_json("monitored-entity", module)
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
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

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
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