#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_ethernet_ipv6
description:
    - Global IPv6 configuration subcommands
short_description: Configures A10 interface.ethernet.ipv6
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
    ethernet_ifnum:
        description:
        - Key to identify parent object
    uuid:
        description:
        - "uuid of the object"
        required: False
    address_list:
        description:
        - "Field address_list"
        required: False
        suboptions:
            address_type:
                description:
                - "'anycast'= Configure an IPv6 anycast address; 'link-local'= Configure an IPv6 link local address; "
            ipv6_addr:
                description:
                - "Set the IPv6 address of an interface"
    inside:
        description:
        - "Configure interface as inside"
        required: False
    ipv6_enable:
        description:
        - "Enable IPv6 processing"
        required: False
    rip:
        description:
        - "Field rip"
        required: False
        suboptions:
            split_horizon_cfg:
                description:
                - "Field split_horizon_cfg"
            uuid:
                description:
                - "uuid of the object"
    outside:
        description:
        - "Configure interface as outside"
        required: False
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
            acl_name:
                description:
                - "Access-list Name"
            inside:
                description:
                - "Inside (private) interface for stateful firewall"
            outside:
                description:
                - "Outside (public) interface for stateful firewall"
            access_list:
                description:
                - "Access-list for traffic from the outside"
    ttl_ignore:
        description:
        - "Ignore TTL decrement for a received packet before sending out"
        required: False
    router:
        description:
        - "Field router"
        required: False
        suboptions:
            ripng:
                description:
                - "Field ripng"
            ospf:
                description:
                - "Field ospf"
            isis:
                description:
                - "Field isis"
    access_list_cfg:
        description:
        - "Field access_list_cfg"
        required: False
        suboptions:
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
    ospf:
        description:
        - "Field ospf"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
            cost_cfg:
                description:
                - "Field cost_cfg"
            priority_cfg:
                description:
                - "Field priority_cfg"
            hello_interval_cfg:
                description:
                - "Field hello_interval_cfg"
            mtu_ignore_cfg:
                description:
                - "Field mtu_ignore_cfg"
            retransmit_interval_cfg:
                description:
                - "Field retransmit_interval_cfg"
            disable:
                description:
                - "Disable BFD"
            transmit_delay_cfg:
                description:
                - "Field transmit_delay_cfg"
            neighbor_cfg:
                description:
                - "Field neighbor_cfg"
            network_list:
                description:
                - "Field network_list"
            dead_interval_cfg:
                description:
                - "Field dead_interval_cfg"
    router_adver:
        description:
        - "Field router_adver"
        required: False
        suboptions:
            max_interval:
                description:
                - "Set Router Advertisement Max Interval (default= 600) (Max Router Advertisement Interval (seconds))"
            default_lifetime:
                description:
                - "Set Router Advertisement Default Lifetime (default= 1800) (Default Lifetime (seconds))"
            reachable_time:
                description:
                - "Set Router Advertisement Reachable ime (default= 0) (Reachable Time (milliseconds))"
            other_config_action:
                description:
                - "'enable'= Enable the Other Stateful Configuration flag; 'disable'= Disable the Other Stateful Configuration flag (default); "
            floating_ip_default_vrid:
                description:
                - "Use a floating IP as the source address for Router advertisements"
            managed_config_action:
                description:
                - "'enable'= Enable the Managed Address Configuration flag; 'disable'= Disable the Managed Address Configuration flag (default); "
            min_interval:
                description:
                - "Set Router Advertisement Min Interval (default= 200) (Min Router Advertisement Interval (seconds))"
            rate_limit:
                description:
                - "Rate Limit the processing of incoming Router Solicitations (Max Number of Router Solicitations to process per second)"
            adver_mtu_disable:
                description:
                - "Disable Router Advertisement MTU Option"
            prefix_list:
                description:
                - "Field prefix_list"
            floating_ip:
                description:
                - "Use a floating IP as the source address for Router advertisements"
            adver_vrid:
                description:
                - "Specify ha VRRP-A vrid"
            use_floating_ip_default_vrid:
                description:
                - "Use a floating IP as the source address for Router advertisements"
            action:
                description:
                - "'enable'= Enable Router Advertisements on this interface; 'disable'= Disable Router Advertisements on this interface; "
            adver_vrid_default:
                description:
                - "Default VRRP-A vrid"
            adver_mtu:
                description:
                - "Set Router Advertisement MTU Option"
            retransmit_timer:
                description:
                - "Set Router Advertisement Retransmit Timer (default= 0)"
            hop_limit:
                description:
                - "Set Router Advertisement Hop Limit (default= 255)"
            use_floating_ip:
                description:
                - "Use a floating IP as the source address for Router advertisements"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["access_list_cfg","address_list","inside","ipv6_enable","ospf","outside","rip","router","router_adver","stateful_firewall","ttl_ignore","uuid",]

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
        uuid=dict(type='str',),
        address_list=dict(type='list',address_type=dict(type='str',choices=['anycast','link-local']),ipv6_addr=dict(type='str',)),
        inside=dict(type='bool',),
        ipv6_enable=dict(type='bool',),
        rip=dict(type='dict',split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),uuid=dict(type='str',)),
        outside=dict(type='bool',),
        stateful_firewall=dict(type='dict',uuid=dict(type='str',),class_list=dict(type='str',),acl_name=dict(type='str',),inside=dict(type='bool',),outside=dict(type='bool',),access_list=dict(type='bool',)),
        ttl_ignore=dict(type='bool',),
        router=dict(type='dict',ripng=dict(type='dict',uuid=dict(type='str',),rip=dict(type='bool',)),ospf=dict(type='dict',area_list=dict(type='list',area_id_addr=dict(type='str',),tag=dict(type='str',),instance_id=dict(type='int',),area_id_num=dict(type='int',)),uuid=dict(type='str',)),isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),
        access_list_cfg=dict(type='dict',inbound=dict(type='bool',),v6_acl_name=dict(type='str',)),
        ospf=dict(type='dict',uuid=dict(type='str',),bfd=dict(type='bool',),cost_cfg=dict(type='list',cost=dict(type='int',),instance_id=dict(type='int',)),priority_cfg=dict(type='list',priority=dict(type='int',),instance_id=dict(type='int',)),hello_interval_cfg=dict(type='list',hello_interval=dict(type='int',),instance_id=dict(type='int',)),mtu_ignore_cfg=dict(type='list',mtu_ignore=dict(type='bool',),instance_id=dict(type='int',)),retransmit_interval_cfg=dict(type='list',retransmit_interval=dict(type='int',),instance_id=dict(type='int',)),disable=dict(type='bool',),transmit_delay_cfg=dict(type='list',transmit_delay=dict(type='int',),instance_id=dict(type='int',)),neighbor_cfg=dict(type='list',neighbor_priority=dict(type='int',),neighbor_poll_interval=dict(type='int',),neig_inst=dict(type='int',),neighbor=dict(type='str',),neighbor_cost=dict(type='int',)),network_list=dict(type='list',broadcast_type=dict(type='str',choices=['broadcast','non-broadcast','point-to-point','point-to-multipoint']),p2mp_nbma=dict(type='bool',),network_instance_id=dict(type='int',)),dead_interval_cfg=dict(type='list',dead_interval=dict(type='int',),instance_id=dict(type='int',))),
        router_adver=dict(type='dict',max_interval=dict(type='int',),default_lifetime=dict(type='int',),reachable_time=dict(type='int',),other_config_action=dict(type='str',choices=['enable','disable']),floating_ip_default_vrid=dict(type='str',),managed_config_action=dict(type='str',choices=['enable','disable']),min_interval=dict(type='int',),rate_limit=dict(type='int',),adver_mtu_disable=dict(type='bool',),prefix_list=dict(type='list',not_autonomous=dict(type='bool',),not_on_link=dict(type='bool',),valid_lifetime=dict(type='int',),prefix=dict(type='str',),preferred_lifetime=dict(type='int',)),floating_ip=dict(type='str',),adver_vrid=dict(type='int',),use_floating_ip_default_vrid=dict(type='bool',),action=dict(type='str',choices=['enable','disable']),adver_vrid_default=dict(type='bool',),adver_mtu=dict(type='int',),retransmit_timer=dict(type='int',),hop_limit=dict(type='int',),use_floating_ip=dict(type='bool',))
    ))
   
    # Parent keys
    rv.update(dict(
        ethernet_ifnum=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ethernet/{ethernet_ifnum}/ipv6"

    f_dict = {}
    f_dict["ethernet_ifnum"] = module.params["ethernet_ifnum"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ethernet/{ethernet_ifnum}/ipv6"

    f_dict = {}
    f_dict["ethernet_ifnum"] = module.params["ethernet_ifnum"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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
        if v:
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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["ipv6"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["ipv6"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["ipv6"][k] = v
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
    except a10_ex.Exists:
        result["changed"] = False
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
    payload = build_json("ipv6", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
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
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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