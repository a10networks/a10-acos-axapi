#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_ospf
description:
    - None
short_description: Configures A10 router.ospf
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
    distribute_internal_list:
        description:
        - "Field distribute_internal_list"
        required: False
        suboptions:
            di_cost:
                description:
                - "None"
            di_area_ipv4:
                description:
                - "None"
            di_area_num:
                description:
                - "None"
            di_type:
                description:
                - "None"
    distribute_lists:
        description:
        - "Field distribute_lists"
        required: False
        suboptions:
            ospf_id:
                description:
                - "None"
            direction:
                description:
                - "None"
            protocol:
                description:
                - "None"
            option:
                description:
                - "None"
            value:
                description:
                - "None"
    default_metric:
        description:
        - "None"
        required: False
    auto_cost_reference_bandwidth:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    router_id:
        description:
        - "Field router_id"
        required: False
        suboptions:
            value:
                description:
                - "None"
    neighbor_list:
        description:
        - "Field neighbor_list"
        required: False
        suboptions:
            priority:
                description:
                - "None"
            cost:
                description:
                - "None"
            poll_interval:
                description:
                - "None"
            address:
                description:
                - "None"
    ospf_1:
        description:
        - "Field ospf_1"
        required: False
        suboptions:
            abr_type:
                description:
                - "Field abr_type"
    host_list:
        description:
        - "Field host_list"
        required: False
        suboptions:
            host_address:
                description:
                - "None"
            area_cfg:
                description:
                - "Field area_cfg"
    log_adjacency_changes_cfg:
        description:
        - "Field log_adjacency_changes_cfg"
        required: False
        suboptions:
            state:
                description:
                - "None"
    area_list:
        description:
        - "Field area_list"
        required: False
        suboptions:
            nssa_cfg:
                description:
                - "Field nssa_cfg"
            uuid:
                description:
                - "None"
            filter_lists:
                description:
                - "Field filter_lists"
            area_num:
                description:
                - "None"
            virtual_link_list:
                description:
                - "Field virtual_link_list"
            stub_cfg:
                description:
                - "Field stub_cfg"
            shortcut:
                description:
                - "None"
            auth_cfg:
                description:
                - "Field auth_cfg"
            range_list:
                description:
                - "Field range_list"
            default_cost:
                description:
                - "None"
            area_ipv4:
                description:
                - "None"
    maximum_area:
        description:
        - "None"
        required: False
    summary_address_list:
        description:
        - "Field summary_address_list"
        required: False
        suboptions:
            summary_address:
                description:
                - "None"
            not_advertise:
                description:
                - "None"
            tag:
                description:
                - "None"
    rfc1583_compatible:
        description:
        - "None"
        required: False
    max_concurrent_dd:
        description:
        - "None"
        required: False
    process_id:
        description:
        - "None"
        required: True
    passive_interface:
        description:
        - "Field passive_interface"
        required: False
        suboptions:
            tunnel_cfg:
                description:
                - "Field tunnel_cfg"
            loopback_cfg:
                description:
                - "Field loopback_cfg"
            ve_cfg:
                description:
                - "Field ve_cfg"
            lif_cfg:
                description:
                - "Field lif_cfg"
            trunk_cfg:
                description:
                - "Field trunk_cfg"
            eth_cfg:
                description:
                - "Field eth_cfg"
    default_information:
        description:
        - "Field default_information"
        required: False
        suboptions:
            originate:
                description:
                - "None"
            uuid:
                description:
                - "None"
            always:
                description:
                - "None"
            metric:
                description:
                - "None"
            route_map:
                description:
                - "None"
            metric_type:
                description:
                - "None"
    overflow:
        description:
        - "Field overflow"
        required: False
        suboptions:
            database:
                description:
                - "Field database"
    bfd_all_interfaces:
        description:
        - "None"
        required: False
    distance:
        description:
        - "Field distance"
        required: False
        suboptions:
            distance_value:
                description:
                - "None"
            distance_ospf:
                description:
                - "Field distance_ospf"
    redistribute:
        description:
        - "Field redistribute"
        required: False
        suboptions:
            redist_list:
                description:
                - "Field redist_list"
            ospf_list:
                description:
                - "Field ospf_list"
            uuid:
                description:
                - "None"
            ip_nat_floating_list:
                description:
                - "Field ip_nat_floating_list"
            vip_list:
                description:
                - "Field vip_list"
            route_map_ip_nat:
                description:
                - "None"
            ip_nat:
                description:
                - "None"
            metric_ip_nat:
                description:
                - "None"
            tag_ip_nat:
                description:
                - "None"
            vip_floating_list:
                description:
                - "Field vip_floating_list"
            metric_type_ip_nat:
                description:
                - "None"
    user_tag:
        description:
        - "None"
        required: False
    network_list:
        description:
        - "Field network_list"
        required: False
        suboptions:
            network_ipv4_cidr:
                description:
                - "None"
            network_ipv4:
                description:
                - "None"
            network_area:
                description:
                - "Field network_area"
            network_ipv4_mask:
                description:
                - "None"
    timers:
        description:
        - "Field timers"
        required: False
        suboptions:
            spf:
                description:
                - "Field spf"
    ha_standby_extra_cost:
        description:
        - "Field ha_standby_extra_cost"
        required: False
        suboptions:
            group:
                description:
                - "None"
            extra_cost:
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
AVAILABLE_PROPERTIES = ["area_list","auto_cost_reference_bandwidth","bfd_all_interfaces","default_information","default_metric","distance","distribute_internal_list","distribute_lists","ha_standby_extra_cost","host_list","log_adjacency_changes_cfg","max_concurrent_dd","maximum_area","neighbor_list","network_list","ospf_1","overflow","passive_interface","process_id","redistribute","rfc1583_compatible","router_id","summary_address_list","timers","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        distribute_internal_list=dict(type='list',di_cost=dict(type='int',),di_area_ipv4=dict(type='str',),di_area_num=dict(type='int',),di_type=dict(type='str',choices=['lw4o6','floating-ip','ip-nat','ip-nat-list','vip','vip-only-flagged'])),
        distribute_lists=dict(type='list',ospf_id=dict(type='int',),direction=dict(type='str',choices=['in','out']),protocol=dict(type='str',choices=['bgp','connected','floating-ip','lw4o6','ip-nat','ip-nat-list','isis','ospf','rip','static']),option=dict(type='str',choices=['only-flagged','only-not-flagged']),value=dict(type='str',)),
        default_metric=dict(type='int',),
        auto_cost_reference_bandwidth=dict(type='int',),
        uuid=dict(type='str',),
        router_id=dict(type='dict',value=dict(type='str',)),
        neighbor_list=dict(type='list',priority=dict(type='int',),cost=dict(type='int',),poll_interval=dict(type='int',),address=dict(type='str',)),
        ospf_1=dict(type='dict',abr_type=dict(type='dict',option=dict(type='str',choices=['cisco','ibm','shortcut','standard']))),
        host_list=dict(type='list',host_address=dict(type='str',),area_cfg=dict(type='dict',area_ipv4=dict(type='str',),cost=dict(type='int',),area_num=dict(type='int',))),
        log_adjacency_changes_cfg=dict(type='dict',state=dict(type='str',choices=['detail','disable'])),
        area_list=dict(type='list',nssa_cfg=dict(type='dict',default_information_originate=dict(type='bool',),translator_role=dict(type='str',choices=['always','candidate','never']),metric=dict(type='int',),nssa=dict(type='bool',),no_redistribution=dict(type='bool',),no_summary=dict(type='bool',),metric_type=dict(type='int',)),uuid=dict(type='str',),filter_lists=dict(type='list',acl_name=dict(type='str',),acl_direction=dict(type='str',choices=['in','out']),filter_list=dict(type='bool',),plist_name=dict(type='str',),plist_direction=dict(type='str',choices=['in','out'])),area_num=dict(type='int',required=True,),virtual_link_list=dict(type='list',dead_interval=dict(type='int',),message_digest_key=dict(type='int',),hello_interval=dict(type='int',),bfd=dict(type='bool',),transmit_delay=dict(type='int',),virtual_link_authentication=dict(type='bool',),virtual_link_ip_addr=dict(type='str',),virtual_link_auth_type=dict(type='str',choices=['message-digest','null']),authentication_key=dict(type='str',),retransmit_interval=dict(type='int',),md5=dict(type='str',)),stub_cfg=dict(type='dict',stub=dict(type='bool',),no_summary=dict(type='bool',)),shortcut=dict(type='str',choices=['default','disable','enable']),auth_cfg=dict(type='dict',authentication=dict(type='bool',),message_digest=dict(type='bool',)),range_list=dict(type='list',area_range_prefix=dict(type='str',),option=dict(type='str',choices=['advertise','not-advertise'])),default_cost=dict(type='int',),area_ipv4=dict(type='str',required=True,)),
        maximum_area=dict(type='int',),
        summary_address_list=dict(type='list',summary_address=dict(type='str',),not_advertise=dict(type='bool',),tag=dict(type='int',)),
        rfc1583_compatible=dict(type='bool',),
        max_concurrent_dd=dict(type='int',),
        process_id=dict(type='int',required=True,),
        passive_interface=dict(type='dict',tunnel_cfg=dict(type='list',tunnel=dict(type='str',),tunnel_address=dict(type='str',)),loopback_cfg=dict(type='list',loopback_address=dict(type='str',),loopback=dict(type='str',)),ve_cfg=dict(type='list',ve_address=dict(type='str',),ve=dict(type='str',)),lif_cfg=dict(type='list',lif=dict(type='str',),lif_address=dict(type='str',)),trunk_cfg=dict(type='list',trunk_address=dict(type='str',),trunk=dict(type='str',)),eth_cfg=dict(type='list',ethernet=dict(type='str',),eth_address=dict(type='str',))),
        default_information=dict(type='dict',originate=dict(type='bool',),uuid=dict(type='str',),always=dict(type='bool',),metric=dict(type='int',),route_map=dict(type='str',),metric_type=dict(type='int',)),
        overflow=dict(type='dict',database=dict(type='dict',count=dict(type='int',),recovery_time=dict(type='int',),limit=dict(type='str',choices=['hard','soft']),db_external=dict(type='int',))),
        bfd_all_interfaces=dict(type='bool',),
        distance=dict(type='dict',distance_value=dict(type='int',),distance_ospf=dict(type='dict',distance_external=dict(type='int',),distance_intra_area=dict(type='int',),distance_inter_area=dict(type='int',))),
        redistribute=dict(type='dict',redist_list=dict(type='list',metric=dict(type='int',),route_map=dict(type='str',),ntype=dict(type='str',choices=['bgp','connected','floating-ip','ip-nat-list','lw4o6','nat-map','isis','rip','static']),metric_type=dict(type='str',choices=['1','2']),tag=dict(type='int',)),ospf_list=dict(type='list',tag_ospf=dict(type='int',),process_id=dict(type='int',),route_map_ospf=dict(type='str',),metric_ospf=dict(type='int',),ospf=dict(type='bool',),metric_type_ospf=dict(type='str',choices=['1','2'])),uuid=dict(type='str',),ip_nat_floating_list=dict(type='list',ip_nat_floating_IP_forward=dict(type='str',),ip_nat_prefix=dict(type='str',)),vip_list=dict(type='list',metric_type_vip=dict(type='str',choices=['1','2']),tag_vip=dict(type='int',),route_map_vip=dict(type='str',),type_vip=dict(type='str',choices=['only-flagged','only-not-flagged']),metric_vip=dict(type='int',)),route_map_ip_nat=dict(type='str',),ip_nat=dict(type='bool',),metric_ip_nat=dict(type='int',),tag_ip_nat=dict(type='int',),vip_floating_list=dict(type='list',vip_address=dict(type='str',),vip_floating_IP_forward=dict(type='str',)),metric_type_ip_nat=dict(type='str',choices=['1','2'])),
        user_tag=dict(type='str',),
        network_list=dict(type='list',network_ipv4_cidr=dict(type='str',),network_ipv4=dict(type='str',),network_area=dict(type='dict',network_area_num=dict(type='int',),network_area_ipv4=dict(type='str',),instance_value=dict(type='int',)),network_ipv4_mask=dict(type='str',)),
        timers=dict(type='dict',spf=dict(type='dict',exp=dict(type='dict',max_delay=dict(type='int',),min_delay=dict(type='int',)))),
        ha_standby_extra_cost=dict(type='list',group=dict(type='int',),extra_cost=dict(type='int',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ospf/{process-id}"
    f_dict = {}
    f_dict["process-id"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ospf/{process-id}"
    f_dict = {}
    f_dict["process-id"] = module.params["process-id"]

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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("ospf", module)
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

def update(module, result, existing_config):
    payload = build_json("ospf", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

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
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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