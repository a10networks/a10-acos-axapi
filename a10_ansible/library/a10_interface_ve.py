#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_ve
description:
    - None
short_description: Configures A10 interface.ve
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
    ifnum:
        description:
        - "None"
        required: True
    name:
        description:
        - "None"
        required: False
    l3_vlan_fwd_disable:
        description:
        - "None"
        required: False
    mtu:
        description:
        - "None"
        required: False
    trap_source:
        description:
        - "None"
        required: False
    action:
        description:
        - "None"
        required: False
    icmp_rate_limit:
        description:
        - "Field icmp_rate_limit"
        required: False
        suboptions:
            normal:
                description:
                - "None"
            lockup:
                description:
                - "None"
            lockup_period:
                description:
                - "None"
    icmpv6_rate_limit:
        description:
        - "Field icmpv6_rate_limit"
        required: False
        suboptions:
            normal_v6:
                description:
                - "None"
            lockup_v6:
                description:
                - "None"
            lockup_period_v6:
                description:
                - "None"
    access_list:
        description:
        - "Field access_list"
        required: False
        suboptions:
            acl_id:
                description:
                - "None"
            acl_name:
                description:
                - "None"
    uuid:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            dhcp:
                description:
                - "None"
            address_list:
                description:
                - "Field address_list"
            allow_promiscuous_vip:
                description:
                - "None"
            client:
                description:
                - "None"
            server:
                description:
                - "None"
            helper_address_list:
                description:
                - "Field helper_address_list"
            inside:
                description:
                - "None"
            outside:
                description:
                - "None"
            ttl_ignore:
                description:
                - "None"
            slb_partition_redirect:
                description:
                - "None"
            generate_membership_query:
                description:
                - "None"
            query_interval:
                description:
                - "None"
            max_resp_time:
                description:
                - "None"
            uuid:
                description:
                - "None"
            stateful_firewall:
                description:
                - "Field stateful_firewall"
            router:
                description:
                - "Field router"
            rip:
                description:
                - "Field rip"
            ospf:
                description:
                - "Field ospf"
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
            ipv6_enable:
                description:
                - "None"
            v6_acl_name:
                description:
                - "None"
            inbound:
                description:
                - "None"
            inside:
                description:
                - "None"
            outside:
                description:
                - "None"
            ttl_ignore:
                description:
                - "None"
            router_adver:
                description:
                - "Field router_adver"
            uuid:
                description:
                - "None"
            stateful_firewall:
                description:
                - "Field stateful_firewall"
            router:
                description:
                - "Field router"
            rip:
                description:
                - "Field rip"
            ospf:
                description:
                - "Field ospf"
    ddos:
        description:
        - "Field ddos"
        required: False
        suboptions:
            outside:
                description:
                - "None"
            inside:
                description:
                - "None"
            uuid:
                description:
                - "None"
    nptv6:
        description:
        - "Field nptv6"
        required: False
        suboptions:
            domain_list:
                description:
                - "Field domain_list"
    map:
        description:
        - "Field map"
        required: False
        suboptions:
            translation:
                description:
                - "Field translation"
    lw_4o6:
        description:
        - "Field lw_4o6"
        required: False
        suboptions:
            outside:
                description:
                - "None"
            inside:
                description:
                - "None"
            uuid:
                description:
                - "None"
    bfd:
        description:
        - "Field bfd"
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
            echo:
                description:
                - "None"
            demand:
                description:
                - "None"
            interval_cfg:
                description:
                - "Field interval_cfg"
            uuid:
                description:
                - "None"
    isis:
        description:
        - "Field isis"
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
            bfd_cfg:
                description:
                - "Field bfd_cfg"
            circuit_type:
                description:
                - "None"
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
            padding:
                description:
                - "None"
            hello_interval_list:
                description:
                - "Field hello_interval_list"
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
            lsp_interval:
                description:
                - "None"
            mesh_group:
                description:
                - "Field mesh_group"
            metric_list:
                description:
                - "Field metric_list"
            network:
                description:
                - "None"
            password_list:
                description:
                - "Field password_list"
            priority_list:
                description:
                - "Field priority_list"
            retransmit_interval:
                description:
                - "None"
            wide_metric_list:
                description:
                - "Field wide_metric_list"
            uuid:
                description:
                - "None"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["access_list","action","bfd","ddos","icmp_rate_limit","icmpv6_rate_limit","ifnum","ip","ipv6","isis","l3_vlan_fwd_disable","lw_4o6","map","mtu","name","nptv6","sampling_enable","trap_source","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        ifnum=dict(type='int',required=True,),
        name=dict(type='str',),
        l3_vlan_fwd_disable=dict(type='bool',),
        mtu=dict(type='int',),
        trap_source=dict(type='bool',),
        action=dict(type='str',choices=['enable','disable']),
        icmp_rate_limit=dict(type='dict',normal=dict(type='int',),lockup=dict(type='int',),lockup_period=dict(type='int',)),
        icmpv6_rate_limit=dict(type='dict',normal_v6=dict(type='int',),lockup_v6=dict(type='int',),lockup_period_v6=dict(type='int',)),
        access_list=dict(type='dict',acl_id=dict(type='int',),acl_name=dict(type='str',)),
        uuid=dict(type='str',),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num_pkts','num_total_bytes','num_unicast_pkts','num_broadcast_pkts','num_multicast_pkts','num_tx_pkts','num_total_tx_bytes','num_unicast_tx_pkts','num_broadcast_tx_pkts','num_multicast_tx_pkts','rate_pkt_sent','rate_byte_sent','rate_pkt_rcvd','rate_byte_rcvd','load_interval'])),
        ip=dict(type='dict',dhcp=dict(type='bool',),address_list=dict(type='list',ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',)),allow_promiscuous_vip=dict(type='bool',),client=dict(type='bool',),server=dict(type='bool',),helper_address_list=dict(type='list',helper_address=dict(type='str',)),inside=dict(type='bool',),outside=dict(type='bool',),ttl_ignore=dict(type='bool',),slb_partition_redirect=dict(type='bool',),generate_membership_query=dict(type='bool',),query_interval=dict(type='int',),max_resp_time=dict(type='int',),uuid=dict(type='str',),stateful_firewall=dict(type='dict',inside=dict(type='bool',),class_list=dict(type='str',),outside=dict(type='bool',),access_list=dict(type='bool',),acl_id=dict(type='int',),uuid=dict(type='str',)),router=dict(type='dict',isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),rip=dict(type='dict',authentication=dict(type='dict',str=dict(type='dict',string=dict(type='str',)),mode=dict(type='dict',mode=dict(type='str',choices=['md5','text'])),key_chain=dict(type='dict',key_chain=dict(type='str',))),send_packet=dict(type='bool',),receive_packet=dict(type='bool',),send_cfg=dict(type='dict',send=dict(type='bool',),version=dict(type='str',choices=['1','2','1-compatible','1-2'])),receive_cfg=dict(type='dict',receive=dict(type='bool',),version=dict(type='str',choices=['1','2','1-2'])),split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),uuid=dict(type='str',)),ospf=dict(type='dict',ospf_global=dict(type='dict',authentication_cfg=dict(type='dict',authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null'])),authentication_key=dict(type='str',),bfd_cfg=dict(type='dict',bfd=dict(type='bool',),disable=dict(type='bool',)),cost=dict(type='int',),database_filter_cfg=dict(type='dict',database_filter=dict(type='str',choices=['all']),out=dict(type='bool',)),dead_interval=dict(type='int',),disable=dict(type='str',choices=['all']),hello_interval=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5=dict(type='dict',md5_value=dict(type='str',),encrypted=dict(type='str',))),mtu=dict(type='int',),mtu_ignore=dict(type='bool',),network=dict(type='dict',broadcast=dict(type='bool',),non_broadcast=dict(type='bool',),point_to_point=dict(type='bool',),point_to_multipoint=dict(type='bool',),p2mp_nbma=dict(type='bool',)),priority=dict(type='int',),retransmit_interval=dict(type='int',),transmit_delay=dict(type='int',),uuid=dict(type='str',)),ospf_ip_list=dict(type='list',ip_addr=dict(type='str',required=True,),authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null']),authentication_key=dict(type='str',),cost=dict(type='int',),database_filter=dict(type='str',choices=['all']),out=dict(type='bool',),dead_interval=dict(type='int',),hello_interval=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5_value=dict(type='str',),encrypted=dict(type='str',)),mtu_ignore=dict(type='bool',),priority=dict(type='int',),retransmit_interval=dict(type='int',),transmit_delay=dict(type='int',),uuid=dict(type='str',)))),
        ipv6=dict(type='dict',address_list=dict(type='list',ipv6_addr=dict(type='str',),address_type=dict(type='str',choices=['anycast','link-local'])),ipv6_enable=dict(type='bool',),v6_acl_name=dict(type='str',),inbound=dict(type='bool',),inside=dict(type='bool',),outside=dict(type='bool',),ttl_ignore=dict(type='bool',),router_adver=dict(type='dict',action=dict(type='str',choices=['enable','disable']),default_lifetime=dict(type='int',),hop_limit=dict(type='int',),max_interval=dict(type='int',),min_interval=dict(type='int',),rate_limit=dict(type='int',),reachable_time=dict(type='int',),retransmit_timer=dict(type='int',),adver_mtu_disable=dict(type='bool',),adver_mtu=dict(type='int',),prefix_list=dict(type='list',prefix=dict(type='str',),not_autonomous=dict(type='bool',),not_on_link=dict(type='bool',),preferred_lifetime=dict(type='int',),valid_lifetime=dict(type='int',)),managed_config_action=dict(type='str',choices=['enable','disable']),other_config_action=dict(type='str',choices=['enable','disable']),adver_vrid=dict(type='int',),use_floating_ip=dict(type='bool',),floating_ip=dict(type='str',),adver_vrid_default=dict(type='bool',),use_floating_ip_default_vrid=dict(type='bool',),floating_ip_default_vrid=dict(type='str',)),uuid=dict(type='str',),stateful_firewall=dict(type='dict',inside=dict(type='bool',),class_list=dict(type='str',),outside=dict(type='bool',),access_list=dict(type='bool',),acl_name=dict(type='str',),uuid=dict(type='str',)),router=dict(type='dict',ripng=dict(type='dict',rip=dict(type='bool',),uuid=dict(type='str',)),ospf=dict(type='dict',area_list=dict(type='list',area_id_num=dict(type='int',),area_id_addr=dict(type='str',),tag=dict(type='str',),instance_id=dict(type='int',)),uuid=dict(type='str',)),isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),rip=dict(type='dict',split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),uuid=dict(type='str',)),ospf=dict(type='dict',network_list=dict(type='list',broadcast_type=dict(type='str',choices=['broadcast','non-broadcast','point-to-point','point-to-multipoint']),p2mp_nbma=dict(type='bool',),network_instance_id=dict(type='int',)),bfd=dict(type='bool',),disable=dict(type='bool',),cost_cfg=dict(type='list',cost=dict(type='int',),instance_id=dict(type='int',)),dead_interval_cfg=dict(type='list',dead_interval=dict(type='int',),instance_id=dict(type='int',)),hello_interval_cfg=dict(type='list',hello_interval=dict(type='int',),instance_id=dict(type='int',)),mtu_ignore_cfg=dict(type='list',mtu_ignore=dict(type='bool',),instance_id=dict(type='int',)),neighbor_cfg=dict(type='list',neighbor=dict(type='str',),neig_inst=dict(type='int',),neighbor_cost=dict(type='int',),neighbor_poll_interval=dict(type='int',),neighbor_priority=dict(type='int',)),priority_cfg=dict(type='list',priority=dict(type='int',),instance_id=dict(type='int',)),retransmit_interval_cfg=dict(type='list',retransmit_interval=dict(type='int',),instance_id=dict(type='int',)),transmit_delay_cfg=dict(type='list',transmit_delay=dict(type='int',),instance_id=dict(type='int',)),uuid=dict(type='str',))),
        ddos=dict(type='dict',outside=dict(type='bool',),inside=dict(type='bool',),uuid=dict(type='str',)),
        nptv6=dict(type='dict',domain_list=dict(type='list',domain_name=dict(type='str',required=True,),bind_type=dict(type='str',required=True,choices=['inside','outside']),uuid=dict(type='str',))),
        map=dict(type='dict',translation=dict(type='dict',inside=dict(type='bool',),outside=dict(type='bool',),uuid=dict(type='str',))),
        lw_4o6=dict(type='dict',outside=dict(type='bool',),inside=dict(type='bool',),uuid=dict(type='str',)),
        bfd=dict(type='dict',authentication=dict(type='dict',key_id=dict(type='int',),method=dict(type='str',choices=['md5','meticulous-md5','meticulous-sha1','sha1','simple']),password=dict(type='str',),encrypted=dict(type='str',)),echo=dict(type='bool',),demand=dict(type='bool',),interval_cfg=dict(type='dict',interval=dict(type='int',),min_rx=dict(type='int',),multiplier=dict(type='int',)),uuid=dict(type='str',)),
        isis=dict(type='dict',authentication=dict(type='dict',send_only_list=dict(type='list',send_only=dict(type='bool',),level=dict(type='str',choices=['level-1','level-2'])),mode_list=dict(type='list',mode=dict(type='str',choices=['md5']),level=dict(type='str',choices=['level-1','level-2'])),key_chain_list=dict(type='list',key_chain=dict(type='str',),level=dict(type='str',choices=['level-1','level-2']))),bfd_cfg=dict(type='dict',bfd=dict(type='bool',),disable=dict(type='bool',)),circuit_type=dict(type='str',choices=['level-1','level-1-2','level-2-only']),csnp_interval_list=dict(type='list',csnp_interval=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),padding=dict(type='bool',),hello_interval_list=dict(type='list',hello_interval=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),hello_interval_minimal_list=dict(type='list',hello_interval_minimal=dict(type='bool',),level=dict(type='str',choices=['level-1','level-2'])),hello_multiplier_list=dict(type='list',hello_multiplier=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),lsp_interval=dict(type='int',),mesh_group=dict(type='dict',value=dict(type='int',),blocked=dict(type='bool',)),metric_list=dict(type='list',metric=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),network=dict(type='str',choices=['broadcast','point-to-point']),password_list=dict(type='list',password=dict(type='str',),level=dict(type='str',choices=['level-1','level-2'])),priority_list=dict(type='list',priority=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),retransmit_interval=dict(type='int',),wide_metric_list=dict(type='list',wide_metric=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),uuid=dict(type='str',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ve/{ifnum}"
    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ifnum}"
    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

    return url_base.format(**f_dict)


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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("ve", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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

def update(module, result):
    payload = build_json("ve", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()