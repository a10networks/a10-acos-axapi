#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_sys_ut_event_action
description:
    - Specify event parameters
short_description: Configures A10 sys-ut.event.action
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
    event_number:
        description:
        - Key to identify parent object
    direction:
        description:
        - "'send'= Test event; 'expect'= Expected result; 'wait'= Introduce a delay; "
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    drop:
        description:
        - "Packet drop. Only allowed for output spec"
        required: False
    udp:
        description:
        - "Field udp"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            nat_pool:
                description:
                - "Nat pool port"
            src_port:
                description:
                - "Source port value"
            length:
                description:
                - "Total packet length starting at UDP header"
            dest_port:
                description:
                - "Dest port"
            dest_port_value:
                description:
                - "Dest port value"
    tcp:
        description:
        - "Field tcp"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            seq_number:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            nat_pool:
                description:
                - "Nat pool port"
            src_port:
                description:
                - "Source port value"
            urgent:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            window:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            ack_seq_number:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            flags:
                description:
                - "Field flags"
            dest_port:
                description:
                - "Dest port"
            dest_port_value:
                description:
                - "Dest port value"
            options:
                description:
                - "Field options"
    delay:
        description:
        - "Delay in seconds"
        required: False
    l2:
        description:
        - "Field l2"
        required: False
        suboptions:
            protocol:
                description:
                - "'arp'= arp; 'ipv4'= ipv4; 'ipv6'= ipv6; "
            uuid:
                description:
                - "uuid of the object"
            ethertype:
                description:
                - "L2 frame type"
            mac_list:
                description:
                - "Field mac_list"
            vlan:
                description:
                - "Vlan ID on the packet. 0 is untagged"
            value:
                description:
                - "ethertype number"
    l3:
        description:
        - "Field l3"
        required: False
        suboptions:
            protocol:
                description:
                - "L4 Protocol"
            uuid:
                description:
                - "uuid of the object"
            checksum:
                description:
                - "'valid'= valid; 'invalid'= invalid; "
            value:
                description:
                - "protocol number"
            ip_list:
                description:
                - "Field ip_list"
            ttl:
                description:
                - "Field ttl"
            ntype:
                description:
                - "'tcp'= tcp; 'udp'= udp; 'icmp'= icmp; "
    template:
        description:
        - "Packet template"
        required: False
    ignore_validation:
        description:
        - "Field ignore_validation"
        required: False
        suboptions:
            all:
                description:
                - "Skip validation"
            uuid:
                description:
                - "uuid of the object"
            l4:
                description:
                - "Dont validate L4 header"
            l2:
                description:
                - "Dont validate L2 header"
            l3:
                description:
                - "Dont validate L3 header"
            l1:
                description:
                - "Dont validate TX descriptor. This includes Tx port, Len & vlan"
    l1:
        description:
        - "Field l1"
        required: False
        suboptions:
            eth_list:
                description:
                - "Field eth_list"
            uuid:
                description:
                - "uuid of the object"
            auto:
                description:
                - "Auto calculate pkt len"
            value:
                description:
                - "Total packet length starting at L2 header"
            length:
                description:
                - "packet length"
            trunk_list:
                description:
                - "Field trunk_list"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["delay","direction","drop","ignore_validation","l1","l2","l3","tcp","template","udp","uuid",]

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
        direction=dict(type='str', required=True, choices=['send', 'expect', 'wait']),
        uuid=dict(type='str', ),
        drop=dict(type='bool', ),
        udp=dict(type='dict', uuid=dict(type='str', ), checksum=dict(type='str', choices=['valid', 'invalid']), nat_pool=dict(type='str', ), src_port=dict(type='int', ), length=dict(type='int', ), dest_port=dict(type='bool', ), dest_port_value=dict(type='int', )),
        tcp=dict(type='dict', uuid=dict(type='str', ), checksum=dict(type='str', choices=['valid', 'invalid']), seq_number=dict(type='str', choices=['valid', 'invalid']), nat_pool=dict(type='str', ), src_port=dict(type='int', ), urgent=dict(type='str', choices=['valid', 'invalid']), window=dict(type='str', choices=['valid', 'invalid']), ack_seq_number=dict(type='str', choices=['valid', 'invalid']), flags=dict(type='dict', ece=dict(type='bool', ), urg=dict(type='bool', ), uuid=dict(type='str', ), ack=dict(type='bool', ), cwr=dict(type='bool', ), psh=dict(type='bool', ), syn=dict(type='bool', ), rst=dict(type='bool', ), fin=dict(type='bool', )), dest_port=dict(type='bool', ), dest_port_value=dict(type='int', ), options=dict(type='dict', uuid=dict(type='str', ), mss=dict(type='int', ), sack_type=dict(type='str', choices=['permitted', 'block']), time_stamp_enable=dict(type='bool', ), nop=dict(type='bool', ), wscale=dict(type='int', ))),
        delay=dict(type='int', ),
        l2=dict(type='dict', protocol=dict(type='str', choices=['arp', 'ipv4', 'ipv6']), uuid=dict(type='str', ), ethertype=dict(type='bool', ), mac_list=dict(type='list', ethernet=dict(type='str', ), ve=dict(type='str', ), src_dst=dict(type='str', required=True, choices=['dest', 'src']), address_type=dict(type='str', choices=['broadcast', 'multicast']), nat_pool=dict(type='str', ), value=dict(type='str', ), trunk=dict(type='str', ), virtual_server=dict(type='str', ), uuid=dict(type='str', )), vlan=dict(type='int', ), value=dict(type='int', )),
        l3=dict(type='dict', protocol=dict(type='bool', ), uuid=dict(type='str', ), checksum=dict(type='str', choices=['valid', 'invalid']), value=dict(type='int', ), ip_list=dict(type='list', ve=dict(type='str', ), virtual_server=dict(type='str', ), src_dst=dict(type='str', required=True, choices=['dest', 'src']), nat_pool=dict(type='str', ), trunk=dict(type='str', ), ipv6_address=dict(type='str', ), ethernet=dict(type='str', ), ipv4_address=dict(type='str', ), uuid=dict(type='str', )), ttl=dict(type='int', ), ntype=dict(type='str', choices=['tcp', 'udp', 'icmp'])),
        template=dict(type='str', ),
        ignore_validation=dict(type='dict', all=dict(type='bool', ), uuid=dict(type='str', ), l4=dict(type='bool', ), l2=dict(type='bool', ), l3=dict(type='bool', ), l1=dict(type='bool', )),
        l1=dict(type='dict', eth_list=dict(type='list', ethernet_start=dict(type='str', ), ethernet_end=dict(type='str', )), uuid=dict(type='str', ), auto=dict(type='bool', ), value=dict(type='int', ), length=dict(type='bool', ), trunk_list=dict(type='list', trunk_start=dict(type='int', ), trunk_end=dict(type='int', )))
    ))
   
    # Parent keys
    rv.update(dict(
        event_number=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/sys-ut/event/{event_number}/action/{direction}"

    f_dict = {}
    f_dict["direction"] = module.params["direction"]
    f_dict["event_number"] = module.params["event_number"]

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
    url_base = "/axapi/v3/sys-ut/event/{event_number}/action/{direction}"

    f_dict = {}
    f_dict["direction"] = ""
    f_dict["event_number"] = module.params["event_number"]

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
        for k, v in payload["action"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["action"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["action"][k] = v
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
    payload = build_json("action", module)
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