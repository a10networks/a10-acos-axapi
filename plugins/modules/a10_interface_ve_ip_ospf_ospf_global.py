#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_interface_ve_ip_ospf_ospf_global
description:
    - Global setting for Open Shortest Path First for IPv4 (OSPF)
short_description: Configures A10 interface.ve.ip.ospf.ospf-global
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
    ve_ifnum:
        description:
        - Key to identify parent object
    cost:
        description:
        - "Interface cost"
        required: False
    dead_interval:
        description:
        - "Interval after which a neighbor is declared dead (Seconds)"
        required: False
    authentication_key:
        description:
        - "Authentication password (key) (The OSPF password (key))"
        required: False
    network:
        description:
        - "Field network"
        required: False
        suboptions:
            broadcast:
                description:
                - "Specify OSPF broadcast multi-access network"
            point_to_multipoint:
                description:
                - "Specify OSPF point-to-multipoint network"
            non_broadcast:
                description:
                - "Specify OSPF NBMA network"
            point_to_point:
                description:
                - "Specify OSPF point-to-point network"
            p2mp_nbma:
                description:
                - "Specify non-broadcast point-to-multipoint network"
    mtu_ignore:
        description:
        - "Ignores the MTU in DBD packets"
        required: False
    transmit_delay:
        description:
        - "Link state transmit delay (Seconds)"
        required: False
    authentication_cfg:
        description:
        - "Field authentication_cfg"
        required: False
        suboptions:
            authentication:
                description:
                - "Enable authentication"
            value:
                description:
                - "'message-digest'= Use message-digest authentication; 'null'= Use no authentication; "
    retransmit_interval:
        description:
        - "Time between retransmitting lost link state advertisements (Seconds)"
        required: False
    bfd_cfg:
        description:
        - "Field bfd_cfg"
        required: False
        suboptions:
            disable:
                description:
                - "Disable BFD"
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
    disable:
        description:
        - "'all'= All functionality; "
        required: False
    hello_interval:
        description:
        - "Time between HELLO packets (Seconds)"
        required: False
    database_filter_cfg:
        description:
        - "Field database_filter_cfg"
        required: False
        suboptions:
            database_filter:
                description:
                - "'all'= Filter all LSA; "
            out:
                description:
                - "Outgoing LSA"
    priority:
        description:
        - "Router priority"
        required: False
    mtu:
        description:
        - "OSPF interface MTU (MTU size)"
        required: False
    message_digest_cfg:
        description:
        - "Field message_digest_cfg"
        required: False
        suboptions:
            message_digest_key:
                description:
                - "Message digest authentication password (key) (Key id)"
            md5:
                description:
                - "Field md5"
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
AVAILABLE_PROPERTIES = ["authentication_cfg","authentication_key","bfd_cfg","cost","database_filter_cfg","dead_interval","disable","hello_interval","message_digest_cfg","mtu","mtu_ignore","network","priority","retransmit_interval","transmit_delay","uuid",]

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
        cost=dict(type='int', ),
        dead_interval=dict(type='int', ),
        authentication_key=dict(type='str', ),
        network=dict(type='dict', broadcast=dict(type='bool', ), point_to_multipoint=dict(type='bool', ), non_broadcast=dict(type='bool', ), point_to_point=dict(type='bool', ), p2mp_nbma=dict(type='bool', )),
        mtu_ignore=dict(type='bool', ),
        transmit_delay=dict(type='int', ),
        authentication_cfg=dict(type='dict', authentication=dict(type='bool', ), value=dict(type='str', choices=['message-digest', 'null'])),
        retransmit_interval=dict(type='int', ),
        bfd_cfg=dict(type='dict', disable=dict(type='bool', ), bfd=dict(type='bool', )),
        disable=dict(type='str', choices=['all']),
        hello_interval=dict(type='int', ),
        database_filter_cfg=dict(type='dict', database_filter=dict(type='str', choices=['all']), out=dict(type='bool', )),
        priority=dict(type='int', ),
        mtu=dict(type='int', ),
        message_digest_cfg=dict(type='list', message_digest_key=dict(type='int', ), md5=dict(type='dict', md5_value=dict(type='str', ), encrypted=dict(type='str', ))),
        uuid=dict(type='str', )
    ))
   
    # Parent keys
    rv.update(dict(
        ve_ifnum=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ip/ospf/ospf-global"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

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
    url_base = "/axapi/v3/interface/ve/{ve_ifnum}/ip/ospf/ospf-global"

    f_dict = {}
    f_dict["ve_ifnum"] = module.params["ve_ifnum"]

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
        for k, v in payload["ospf-global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ospf-global"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ospf-global"][k] = v
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
    payload = build_json("ospf-global", module)
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