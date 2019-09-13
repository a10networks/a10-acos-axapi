#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_isis
description:
    - Intermediate System - Intermediate System (IS-IS)
short_description: Configures A10 router.isis
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
    partition:
        description:
        - Destination/target partition for object/command
    domain_password_cfg:
        description:
        - "Field domain_password_cfg"
        required: False
        suboptions:
            password:
                description:
                - "Set the authentication password for a routing domain (Routing domain password)"
            authenticate:
                description:
                - "Field authenticate"
    max_lsp_lifetime:
        description:
        - "Set maximum LSP lifetime (Maximum LSP lifetime in seconds)"
        required: False
    tag:
        description:
        - "ISO routing area tag"
        required: True
    lsp_refresh_interval:
        description:
        - "Set LSP refresh interval (LSP refresh time in seconds)"
        required: False
    set_overload_bit_cfg:
        description:
        - "Field set_overload_bit_cfg"
        required: False
        suboptions:
            suppress_cfg:
                description:
                - "Field suppress_cfg"
            set_overload_bit:
                description:
                - "Signal other touers not to use us in SPF"
            on_startup:
                description:
                - "Field on_startup"
    net_list:
        description:
        - "Field net_list"
        required: False
        suboptions:
            net:
                description:
                - "A Network Entity Title for this process (XX.XXXX. ... .XXXX.XX  Network entity title (NET))"
    uuid:
        description:
        - "uuid of the object"
        required: False
    bfd:
        description:
        - "'all-interfaces'= Enable BFD on all interfaces; "
        required: False
    metric_style_list:
        description:
        - "Field metric_style_list"
        required: False
        suboptions:
            ntype:
                description:
                - "'narrow'= Use old style of TLVs with narrow metric; 'wide'= Use new style of TLVs to carry wider metric; 'transition'= Send and accept both styles of TLVs during transition; 'narrow-transition'= Send old style of TLVs with narrow metric with accepting both styles of TLVs; 'wide-transition'= Send new style of TLVs to carry wider metric with accepting both styles of TLVs; "
            level:
                description:
                - "'level-1'= Level-1 only; 'level-1-2'= Level-1-2; 'level-2'= Level-2 only; "
    authentication:
        description:
        - "Field authentication"
        required: False
        suboptions:
            send_only_list:
                description:
                - "Field send_only_list"
            mode_list:
                description:
                - "Field mode_list"
            key_chain_list:
                description:
                - "Field key_chain_list"
    ignore_lsp_errors:
        description:
        - "Ignore LSPs with bad checksums"
        required: False
    protocol_list:
        description:
        - "Field protocol_list"
        required: False
        suboptions:
            protocol_topology:
                description:
                - "Protocol Topology"
    log_adjacency_changes_cfg:
        description:
        - "Field log_adjacency_changes_cfg"
        required: False
        suboptions:
            state:
                description:
                - "'detail'= Log changes in adjacency state; 'disable'= Disable logging; "
    spf_interval_exp_list:
        description:
        - "Field spf_interval_exp_list"
        required: False
        suboptions:
            max:
                description:
                - "Maximum Delay between receiving a change to SPF calculation in milliseconds"
            min:
                description:
                - "Minimum Delay between receiving a change to SPF calculation in milliseconds"
            level:
                description:
                - "'level-1'= Set interval for level 1 only; 'level-2'= Set interval for level 2 only; "
    passive_interface_list:
        description:
        - "Field passive_interface_list"
        required: False
        suboptions:
            lif:
                description:
                - "Logical interface (Lif interface number)"
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
            loopback:
                description:
                - "Loopback interface (Port number)"
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
            ethernet:
                description:
                - "Ethernet interface (Port number)"
    summary_address_list:
        description:
        - "Field summary_address_list"
        required: False
        suboptions:
            prefix:
                description:
                - "IP network prefix"
            level:
                description:
                - "'level-1'= Summarize into level-1 area; 'level-1-2'= Summarize into both area and sub-domain; 'level-2'= Summarize into level-2 sub-domain; "
    adjacency_check:
        description:
        - "Check ISIS neighbor protocol support"
        required: False
    default_information:
        description:
        - "'originate'= Distribute a default route; "
        required: False
    address_family:
        description:
        - "Field address_family"
        required: False
        suboptions:
            ipv6:
                description:
                - "Field ipv6"
    redistribute:
        description:
        - "Field redistribute"
        required: False
        suboptions:
            vip_list:
                description:
                - "Field vip_list"
            redist_list:
                description:
                - "Field redist_list"
            isis:
                description:
                - "Field isis"
            uuid:
                description:
                - "uuid of the object"
    ha_standby_extra_cost:
        description:
        - "Field ha_standby_extra_cost"
        required: False
        suboptions:
            group:
                description:
                - "Group (Group ID)"
            extra_cost:
                description:
                - "The extra cost value"
    lsp_gen_interval_list:
        description:
        - "Field lsp_gen_interval_list"
        required: False
        suboptions:
            interval:
                description:
                - "Minimum interval in seconds"
            level:
                description:
                - "'level-1'= Set interval for level 1 only; 'level-2'= Set interval for level 2 only; "
    is_type:
        description:
        - "'level-1'= Act as a station router only; 'level-1-2'= Act as both a station router and an area router; 'level-2-only'= Act as an area router only; "
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    distance_list:
        description:
        - "Field distance_list"
        required: False
        suboptions:
            distance:
                description:
                - "ISIS Administrative Distance (Distance value)"
            System_ID:
                description:
                - "System-ID in XXXX.XXXX.XXXX"
            acl:
                description:
                - "Access list name"
    area_password_cfg:
        description:
        - "Field area_password_cfg"
        required: False
        suboptions:
            password:
                description:
                - "Configure the authentication password for an area (Area password)"
            authenticate:
                description:
                - "Field authenticate"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["address_family","adjacency_check","area_password_cfg","authentication","bfd","default_information","distance_list","domain_password_cfg","ha_standby_extra_cost","ignore_lsp_errors","is_type","log_adjacency_changes_cfg","lsp_gen_interval_list","lsp_refresh_interval","max_lsp_lifetime","metric_style_list","net_list","passive_interface_list","protocol_list","redistribute","set_overload_bit_cfg","spf_interval_exp_list","summary_address_list","tag","user_tag","uuid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        domain_password_cfg=dict(type='dict',password=dict(type='str',),authenticate=dict(type='dict',snp=dict(type='str',choices=['send-only','validate']))),
        max_lsp_lifetime=dict(type='int',),
        tag=dict(type='str',required=True,),
        lsp_refresh_interval=dict(type='int',),
        set_overload_bit_cfg=dict(type='dict',suppress_cfg=dict(type='dict',interlevel=dict(type='bool',),external=dict(type='bool',)),set_overload_bit=dict(type='bool',),on_startup=dict(type='dict',delay=dict(type='int',),wait_for_bgp=dict(type='bool',))),
        net_list=dict(type='list',net=dict(type='str',)),
        uuid=dict(type='str',),
        bfd=dict(type='str',choices=['all-interfaces']),
        metric_style_list=dict(type='list',ntype=dict(type='str',choices=['narrow','wide','transition','narrow-transition','wide-transition']),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),
        authentication=dict(type='dict',send_only_list=dict(type='list',send_only=dict(type='bool',),level=dict(type='str',choices=['level-1','level-2'])),mode_list=dict(type='list',mode=dict(type='str',choices=['md5']),level=dict(type='str',choices=['level-1','level-2'])),key_chain_list=dict(type='list',key_chain=dict(type='str',),level=dict(type='str',choices=['level-1','level-2']))),
        ignore_lsp_errors=dict(type='bool',),
        protocol_list=dict(type='list',protocol_topology=dict(type='bool',)),
        log_adjacency_changes_cfg=dict(type='dict',state=dict(type='str',choices=['detail','disable'])),
        spf_interval_exp_list=dict(type='list',max=dict(type='int',),min=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),
        passive_interface_list=dict(type='list',lif=dict(type='str',),ve=dict(type='str',),loopback=dict(type='str',),tunnel=dict(type='str',),trunk=dict(type='str',),ethernet=dict(type='str',)),
        summary_address_list=dict(type='list',prefix=dict(type='str',),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),
        adjacency_check=dict(type='bool',),
        default_information=dict(type='str',choices=['originate']),
        address_family=dict(type='dict',ipv6=dict(type='dict',distance=dict(type='int',),redistribute=dict(type='dict',vip_list=dict(type='list',vip_metric=dict(type='int',),vip_level=dict(type='str',choices=['level-1','level-1-2','level-2']),vip_metric_type=dict(type='str',choices=['external','internal']),vip_type=dict(type='str',choices=['only-flagged','only-not-flagged']),vip_route_map=dict(type='str',)),redist_list=dict(type='list',metric=dict(type='int',),route_map=dict(type='str',),ntype=dict(type='str',choices=['bgp','connected','floating-ip','ip-nat-list','ip-nat','lw4o6','nat-map','nat64','ospf','rip','static']),metric_type=dict(type='str',choices=['external','internal']),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),isis=dict(type='dict',level_2_from=dict(type='dict',into_2=dict(type='dict',distribute_list=dict(type='str',),level_1=dict(type='bool',))),level_1_from=dict(type='dict',into_1=dict(type='dict',level_2=dict(type='bool',),distribute_list=dict(type='str',)))),uuid=dict(type='str',)),uuid=dict(type='str',),multi_topology_cfg=dict(type='dict',multi_topology=dict(type='bool',),level_transition=dict(type='bool',),transition=dict(type='bool',),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),adjacency_check=dict(type='bool',),summary_prefix_list=dict(type='list',prefix=dict(type='str',),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),default_information=dict(type='str',choices=['originate']))),
        redistribute=dict(type='dict',vip_list=dict(type='list',vip_metric=dict(type='int',),vip_level=dict(type='str',choices=['level-1','level-1-2','level-2']),vip_metric_type=dict(type='str',choices=['external','internal']),vip_type=dict(type='str',choices=['only-flagged','only-not-flagged']),vip_route_map=dict(type='str',)),redist_list=dict(type='list',metric=dict(type='int',),route_map=dict(type='str',),ntype=dict(type='str',choices=['bgp','connected','floating-ip','ip-nat-list','ip-nat','lw4o6','nat-map','ospf','rip','static']),metric_type=dict(type='str',choices=['external','internal']),level=dict(type='str',choices=['level-1','level-1-2','level-2'])),isis=dict(type='dict',level_2_from=dict(type='dict',into_2=dict(type='dict',distribute_list=dict(type='str',),level_1=dict(type='bool',))),level_1_from=dict(type='dict',into_1=dict(type='dict',level_2=dict(type='bool',),distribute_list=dict(type='str',)))),uuid=dict(type='str',)),
        ha_standby_extra_cost=dict(type='list',group=dict(type='int',),extra_cost=dict(type='int',)),
        lsp_gen_interval_list=dict(type='list',interval=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),
        is_type=dict(type='str',choices=['level-1','level-1-2','level-2-only']),
        user_tag=dict(type='str',),
        distance_list=dict(type='list',distance=dict(type='int',),System_ID=dict(type='str',),acl=dict(type='str',)),
        area_password_cfg=dict(type='dict',password=dict(type='str',),authenticate=dict(type='dict',snp=dict(type='str',choices=['send-only','validate'])))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/isis/{tag}"

    f_dict = {}
    f_dict["tag"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/isis/{tag}"

    f_dict = {}
    f_dict["tag"] = module.params["tag"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["isis"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["isis"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["isis"][k] = v
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
    payload = build_json("isis", module)
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

def replace(module, result, existing_config):
    payload = build_json("isis", module)
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
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

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