#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_ipv6_access_list
description:
    - Configure a IPv6 Access List
short_description: Configures A10 ipv6.access-list
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
    rules:
        description:
        - "Field rules"
        required: False
        suboptions:
            geo_location:
                description:
                - "Specify geo-location name"
            icmp_type:
                description:
                - "ICMP type number"
            service_obj_group:
                description:
                - "Service object group (Source object group name)"
            udp:
                description:
                - "protocol UDP"
            tcp:
                description:
                - "protocol TCP"
            src_range:
                description:
                - "match only packets in the range of port numbers (Starting Port Number)"
            any_code:
                description:
                - "Any ICMP code"
            src_lt:
                description:
                - "Match only packets with a lower port number"
            special_code:
                description:
                - "'addr-unreachable'= Code 3, address unreachable; 'admin-prohibited'= Code 1, admin prohibited; 'no-route'= Code 0, no route to destination; 'not-neighbour'= Code 2, not neighbor; 'port-unreachable'= Code 4, destination port unreachable; "
            src_port_end:
                description:
                - "Ending Port Number"
            dst_port_end:
                description:
                - "Edning Destination Port Number"
            dst_range:
                description:
                - "Match only packets in the range of port numbers (Starting Destination Port Number)"
            established:
                description:
                - "TCP established"
            seq_num:
                description:
                - "Sequence Number"
            src_any:
                description:
                - "Any source host"
            ipv6:
                description:
                - "Any Internet Protocol"
            fragments:
                description:
                - "IP fragments"
            icmp_code:
                description:
                - "ICMP code number"
            src_object_group:
                description:
                - "Network object group (Source network object group name)"
            dst_eq:
                description:
                - "Match only packets on a given destination port (port number)"
            dst_subnet:
                description:
                - "Destination Address"
            src_subnet:
                description:
                - "Source Address"
            vlan:
                description:
                - "VLAN ID"
            dscp:
                description:
                - "DSCP"
            action:
                description:
                - "'deny'= Deny; 'permit'= Permit; 'l3-vlan-fwd-disable'= Disable L3 forwarding between VLANs; "
            trunk:
                description:
                - "Ethernet trunk (trunk number)"
            icmp:
                description:
                - "Internet Control Message Protocol"
            dst_gt:
                description:
                - "Match only packets with a greater port number"
            acl_log:
                description:
                - "Log matches against this entry"
            src_gt:
                description:
                - "Match only packets with a greater port number"
            remark:
                description:
                - "Access list entry comment (Notes for this ACL)"
            dst_object_group:
                description:
                - "Destination network object group name"
            any_type:
                description:
                - "Any ICMP type"
            dst_any:
                description:
                - "Any destination host"
            src_host:
                description:
                - "A single source host (Host address)"
            dst_lt:
                description:
                - "Match only packets with a lesser port number"
            ethernet:
                description:
                - "Ethernet interface (Port number)"
            special_type:
                description:
                - "'echo-reply'= Type 129, echo reply; 'echo-request'= help Type 128, echo request; 'packet-too-big'= Type 2, packet too big; 'param-prob'= Type 4, parameter problem; 'time-exceeded'= Type 3, time exceeded; 'dest-unreachable'= Type 1, destination unreachable; "
            src_eq:
                description:
                - "Match only packets on a given source port (port number)"
            dst_host:
                description:
                - "A single destination host (Host address)"
    name:
        description:
        - "Named Access List"
        required: True
    user_tag:
        description:
        - "Customized tag"
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
AVAILABLE_PROPERTIES = ["name","rules","user_tag","uuid",]

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
        rules=dict(type='list', geo_location=dict(type='str', ), icmp_type=dict(type='int', ), service_obj_group=dict(type='str', ), udp=dict(type='bool', ), tcp=dict(type='bool', ), src_range=dict(type='int', ), any_code=dict(type='bool', ), src_lt=dict(type='int', ), special_code=dict(type='str', choices=['addr-unreachable', 'admin-prohibited', 'no-route', 'not-neighbour', 'port-unreachable']), src_port_end=dict(type='int', ), dst_port_end=dict(type='int', ), dst_range=dict(type='int', ), established=dict(type='bool', ), seq_num=dict(type='int', ), src_any=dict(type='bool', ), ipv6=dict(type='bool', ), fragments=dict(type='bool', ), icmp_code=dict(type='int', ), src_object_group=dict(type='str', ), dst_eq=dict(type='int', ), dst_subnet=dict(type='str', ), src_subnet=dict(type='str', ), vlan=dict(type='int', ), dscp=dict(type='int', ), action=dict(type='str', choices=['deny', 'permit', 'l3-vlan-fwd-disable']), trunk=dict(type='str', ), icmp=dict(type='bool', ), dst_gt=dict(type='int', ), acl_log=dict(type='bool', ), src_gt=dict(type='int', ), remark=dict(type='str', ), dst_object_group=dict(type='str', ), any_type=dict(type='bool', ), dst_any=dict(type='bool', ), src_host=dict(type='str', ), dst_lt=dict(type='int', ), ethernet=dict(type='str', ), special_type=dict(type='str', choices=['echo-reply', 'echo-request', 'packet-too-big', 'param-prob', 'time-exceeded', 'dest-unreachable']), src_eq=dict(type='int', ), dst_host=dict(type='str', )),
        name=dict(type='str', required=True, ),
        user_tag=dict(type='str', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ipv6/access-list/{name}"

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
    url_base = "/axapi/v3/ipv6/access-list/{name}"

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
        for k, v in payload["access-list"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["access-list"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["access-list"][k] = v
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
    payload = build_json("access-list", module)
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