#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_interface_trunk_ip
description:
    - Global IP configuration subcommands
short_description: Configures A10 interface.trunk.ip
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    trunk_ifnum:
        description:
        - Key to identify parent object
    nat:
        description:
        - "Field nat"
        required: False
        suboptions:
            inside:
                description:
                - "Configure interface as inside"
            outside:
                description:
                - "Configure interface as outside"
    uuid:
        description:
        - "uuid of the object"
        required: False
    address_list:
        description:
        - "Field address_list"
        required: False
        suboptions:
            ipv4_address:
                description:
                - "IP address"
            ipv4_netmask:
                description:
                - "IP subnet mask"
    generate_membership_query:
        description:
        - "Enable Membership Query"
        required: False
    cache_spoofing_port:
        description:
        - "This interface connects to spoofing cache"
        required: False
    router:
        description:
        - "Field router"
        required: False
        suboptions:
            isis:
                description:
                - "Field isis"
    allow_promiscuous_vip:
        description:
        - "Allow traffic to be associated with promiscuous VIP"
        required: False
    server:
        description:
        - "Server facing interface for IPv4/v6 traffic"
        required: False
    max_resp_time:
        description:
        - "Maximum Response Time (Max Response Time (Default is 100))"
        required: False
    query_interval:
        description:
        - "1 - 255 (Default is 125)"
        required: False
    helper_address_list:
        description:
        - "Field helper_address_list"
        required: False
        suboptions:
            helper_address:
                description:
                - "Helper address for DHCP packets (IP address)"
    stateful_firewall:
        description:
        - "Field stateful_firewall"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            class_list:
                description:
                - "Class List (Class List Name)"
            inside:
                description:
                - "Inside (private) interface for stateful firewall"
            outside:
                description:
                - "Outside (public) interface for stateful firewall"
            acl_id:
                description:
                - "ACL id"
            access_list:
                description:
                - "Access-list for traffic from the outside"
    client:
        description:
        - "Client facing interface for IPv4/v6 traffic"
        required: False
    rip:
        description:
        - "Field rip"
        required: False
        suboptions:
            receive_cfg:
                description:
                - "Field receive_cfg"
            uuid:
                description:
                - "uuid of the object"
            receive_packet:
                description:
                - "Enable receiving packet through the specified interface"
            split_horizon_cfg:
                description:
                - "Field split_horizon_cfg"
            authentication:
                description:
                - "Field authentication"
            send_cfg:
                description:
                - "Field send_cfg"
            send_packet:
                description:
                - "Enable sending packets through the specified interface"
    ttl_ignore:
        description:
        - "Ignore TTL decrement for a received packet"
        required: False
    dhcp:
        description:
        - "Use DHCP to configure IP address"
        required: False
    ospf:
        description:
        - "Field ospf"
        required: False
        suboptions:
            ospf_ip_list:
                description:
                - "Field ospf_ip_list"
            ospf_global:
                description:
                - "Field ospf_global"
    slb_partition_redirect:
        description:
        - "Redirect SLB traffic across partition"
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
AVAILABLE_PROPERTIES = ["address_list","allow_promiscuous_vip","cache_spoofing_port","client","dhcp","generate_membership_query","helper_address_list","max_resp_time","nat","ospf","query_interval","rip","router","server","slb_partition_redirect","stateful_firewall","ttl_ignore","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        nat=dict(type='dict',inside=dict(type='bool',),outside=dict(type='bool',)),
        uuid=dict(type='str',),
        address_list=dict(type='list',ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',)),
        generate_membership_query=dict(type='bool',),
        cache_spoofing_port=dict(type='bool',),
        router=dict(type='dict',isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),
        allow_promiscuous_vip=dict(type='bool',),
        server=dict(type='bool',),
        max_resp_time=dict(type='int',),
        query_interval=dict(type='int',),
        helper_address_list=dict(type='list',helper_address=dict(type='str',)),
        stateful_firewall=dict(type='dict',uuid=dict(type='str',),class_list=dict(type='str',),inside=dict(type='bool',),outside=dict(type='bool',),acl_id=dict(type='int',),access_list=dict(type='bool',)),
        client=dict(type='bool',),
        rip=dict(type='dict',receive_cfg=dict(type='dict',receive=dict(type='bool',),version=dict(type='str',choices=['1','2','1-2'])),uuid=dict(type='str',),receive_packet=dict(type='bool',),split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),authentication=dict(type='dict',key_chain=dict(type='dict',key_chain=dict(type='str',)),mode=dict(type='dict',mode=dict(type='str',choices=['md5','text'])),str=dict(type='dict',string=dict(type='str',))),send_cfg=dict(type='dict',version=dict(type='str',choices=['1','2','1-compatible','1-2']),send=dict(type='bool',)),send_packet=dict(type='bool',)),
        ttl_ignore=dict(type='bool',),
        dhcp=dict(type='bool',),
        ospf=dict(type='dict',ospf_ip_list=dict(type='list',dead_interval=dict(type='int',),authentication_key=dict(type='str',),uuid=dict(type='str',),mtu_ignore=dict(type='bool',),transmit_delay=dict(type='int',),value=dict(type='str',choices=['message-digest','null']),priority=dict(type='int',),authentication=dict(type='bool',),cost=dict(type='int',),database_filter=dict(type='str',choices=['all']),hello_interval=dict(type='int',),ip_addr=dict(type='str',required=True,),retransmit_interval=dict(type='int',),message_digest_cfg=dict(type='list',md5_value=dict(type='str',),message_digest_key=dict(type='int',),encrypted=dict(type='str',)),out=dict(type='bool',)),ospf_global=dict(type='dict',cost=dict(type='int',),dead_interval=dict(type='int',),authentication_key=dict(type='str',),network=dict(type='dict',broadcast=dict(type='bool',),point_to_multipoint=dict(type='bool',),non_broadcast=dict(type='bool',),point_to_point=dict(type='bool',),p2mp_nbma=dict(type='bool',)),mtu_ignore=dict(type='bool',),transmit_delay=dict(type='int',),authentication_cfg=dict(type='dict',authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null'])),retransmit_interval=dict(type='int',),bfd_cfg=dict(type='dict',disable=dict(type='bool',),bfd=dict(type='bool',)),disable=dict(type='str',choices=['all']),hello_interval=dict(type='int',),database_filter_cfg=dict(type='dict',database_filter=dict(type='str',choices=['all']),out=dict(type='bool',)),priority=dict(type='int',),mtu=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5=dict(type='dict',md5_value=dict(type='str',),encrypted=dict(type='str',))),uuid=dict(type='str',))),
        slb_partition_redirect=dict(type='bool',)
    ))
   
    # Parent keys
    rv.update(dict(
        trunk_ifnum=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/trunk/{trunk_ifnum}/ip"

    f_dict = {}
    f_dict["trunk_ifnum"] = module.params["trunk_ifnum"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/trunk/{trunk_ifnum}/ip"

    f_dict = {}
    f_dict["trunk_ifnum"] = module.params["trunk_ifnum"]

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
        for k, v in payload["ip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ip"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ip"][k] = v
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
    payload = build_json("ip", module)
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