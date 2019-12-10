#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_scaleout_cluster
description:
    - Configure scaleout cluster
short_description: Configures A10 scaleout.cluster
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
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
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    local_device:
        description:
        - "Field local_device"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            session_sync_interface:
                description:
                - "Field session_sync_interface"
            id:
                description:
                - "Field id"
            priority:
                description:
                - "Field priority"
            action:
                description:
                - "'enable'= enable; 'disable'= disable; "
            l2_redirect:
                description:
                - "Field l2_redirect"
            tracking_template:
                description:
                - "Field tracking_template"
            start_delay:
                description:
                - "Field start_delay"
    cluster_id:
        description:
        - "Scaleout cluster-id"
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    cluster_devices:
        description:
        - "Field cluster_devices"
        required: False
        suboptions:
            cluster_discovery_timeout:
                description:
                - "Field cluster_discovery_timeout"
            device_id_list:
                description:
                - "Field device_id_list"
            uuid:
                description:
                - "uuid of the object"
    follow_vcs:
        description:
        - "Field follow_vcs"
        required: False
    device_groups:
        description:
        - "Field device_groups"
        required: False
        suboptions:
            device_group_list:
                description:
                - "Field device_group_list"
            uuid:
                description:
                - "uuid of the object"
    service_config:
        description:
        - "Field service_config"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            template_list:
                description:
                - "Field template_list"
    db_config:
        description:
        - "Field db_config"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    tracking_template:
        description:
        - "Field tracking_template"
        required: False
        suboptions:
            template_list:
                description:
                - "Field template_list"

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["cluster_devices","cluster_id","db_config","device_groups","follow_vcs","local_device","service_config","tracking_template","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        local_device=dict(type='dict',uuid=dict(type='str',),session_sync_interface=dict(type='dict',ve_cfg=dict(type='list',ve=dict(type='int',)),uuid=dict(type='str',),trunk_cfg=dict(type='list',trunk=dict(type='int',)),eth_cfg=dict(type='list',ethernet=dict(type='str',))),id=dict(type='int',),priority=dict(type='int',),action=dict(type='str',choices=['enable','disable']),l2_redirect=dict(type='dict',ethernet_vlan=dict(type='int',),redirect_eth=dict(type='str',),redirect_trunk=dict(type='int',),trunk_vlan=dict(type='int',),uuid=dict(type='str',)),tracking_template=dict(type='dict',template_list=dict(type='list',uuid=dict(type='str',),threshold_cfg=dict(type='list',threshold=dict(type='int',),action=dict(type='str',choices=['down','exit-cluster'])),user_tag=dict(type='str',),template=dict(type='str',required=True,))),start_delay=dict(type='int',)),
        cluster_id=dict(type='int',required=True,),
        uuid=dict(type='str',),
        cluster_devices=dict(type='dict',cluster_discovery_timeout=dict(type='dict',timer_val=dict(type='int',),uuid=dict(type='str',)),device_id_list=dict(type='list',action=dict(type='str',choices=['enable','disable']),device_id=dict(type='int',required=True,),uuid=dict(type='str',),user_tag=dict(type='str',),ip=dict(type='str',)),uuid=dict(type='str',)),
        follow_vcs=dict(type='bool',),
        device_groups=dict(type='dict',device_group_list=dict(type='list',device_group=dict(type='int',required=True,),device_id_list=dict(type='list',device_id_start=dict(type='int',),device_id_end=dict(type='int',)),uuid=dict(type='str',),user_tag=dict(type='str',)),uuid=dict(type='str',)),
        service_config=dict(type='dict',uuid=dict(type='str',),template_list=dict(type='list',device_group=dict(type='int',),bucket_count=dict(type='int',),name=dict(type='str',required=True,),user_tag=dict(type='str',),uuid=dict(type='str',))),
        db_config=dict(type='dict',uuid=dict(type='str',)),
        tracking_template=dict(type='dict',template_list=dict(type='list',uuid=dict(type='str',),threshold_cfg=dict(type='list',threshold=dict(type='int',),action=dict(type='str',choices=['down','exit-cluster'])),user_tag=dict(type='str',),template=dict(type='str',required=True,)))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/scaleout/cluster/{cluster-id}"

    f_dict = {}
    f_dict["cluster-id"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/scaleout/cluster/{cluster-id}"

    f_dict = {}
    f_dict["cluster-id"] = module.params["cluster_id"]

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["cluster"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["cluster"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["cluster"][k] = v
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
    payload = build_json("cluster", module)
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

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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