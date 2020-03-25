#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_rule_set
description:
    - Configure Security policy Rule Set
short_description: Configures A10 rule-set
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            rule_stats:
                description:
                - "Field rule_stats"
            name:
                description:
                - "Rule set name"
            policy_deny:
                description:
                - "Field policy_deny"
            policy_rule_count:
                description:
                - "Field policy_rule_count"
            policy_reset:
                description:
                - "Field policy_reset"
            rule_list:
                description:
                - "Field rule_list"
            policy_unmatched_drop:
                description:
                - "Field policy_unmatched_drop"
            policy_status:
                description:
                - "Field policy_status"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
            policy_permit:
                description:
                - "Field policy_permit"
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            reset:
                description:
                - "Reset counter"
            deny:
                description:
                - "Denied counter"
            name:
                description:
                - "Rule set name"
            permit:
                description:
                - "Permitted counter"
            unmatched_drops:
                description:
                - "Unmatched drops counter"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
            rule_list:
                description:
                - "Field rule_list"
    name:
        description:
        - "Rule set name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'unmatched-drops'= Unmatched drops counter; 'permit'= Permitted counter; 'deny'= Denied counter; 'reset'= Reset counter; "
    rule_list:
        description:
        - "Field rule_list"
        required: False
        suboptions:
            cgnv6_fixed_nat_log:
                description:
                - "Enable logging"
            forward_listen_on_port:
                description:
                - "Listen on port"
            cgnv6_policy:
                description:
                - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT; "
            cgnv6_log:
                description:
                - "Enable logging"
            forward_log:
                description:
                - "Enable logging"
            cgnv6_lsn_log:
                description:
                - "Enable logging"
            listen_on_port:
                description:
                - "Listen on port"
            move_rule:
                description:
                - "Field move_rule"
            src_ipv6_any:
                description:
                - "'any'= Any IPv6 address; "
            idle_timeout:
                description:
                - "TCP/UDP idle-timeout"
            fwlog:
                description:
                - "Enable logging"
            src_zone_any:
                description:
                - "'any'= any; "
            ip_version:
                description:
                - "'v4'= IPv4 rule; 'v6'= IPv6 rule; "
            action:
                description:
                - "'permit'= permit; 'deny'= deny; 'reset'= reset; "
            policy:
                description:
                - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet; "
            source_list:
                description:
                - "Field source_list"
            dst_zone_any:
                description:
                - "'any'= any; "
            status:
                description:
                - "'enable'= Enable rule; 'disable'= Disable rule; "
            dst_ipv4_any:
                description:
                - "'any'= Any IPv4 address; "
            src_zone:
                description:
                - "Zone name"
            src_ipv4_any:
                description:
                - "'any'= Any IPv4 address; "
            log:
                description:
                - "Enable logging"
            dst_zone:
                description:
                - "Zone name"
            service_any:
                description:
                - "'any'= any; "
            remark:
                description:
                - "Rule entry comment (Notes for this rule)"
            name:
                description:
                - "Rule name"
            cgnv6_lsn_lid:
                description:
                - "LSN LID"
            uuid:
                description:
                - "uuid of the object"
            user_tag:
                description:
                - "Customized tag"
            dst_ipv6_any:
                description:
                - "'any'= Any IPv6 address; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            service_list:
                description:
                - "Field service_list"
            dest_list:
                description:
                - "Field dest_list"
            fw_log:
                description:
                - "Enable logging"
    session_statistic:
        description:
        - "'enable'= Enable session based statistic (Default); 'disable'= Disable session based statistic; "
        required: False
    rules_by_zone:
        description:
        - "Field rules_by_zone"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["name","oper","remark","rule_list","rules_by_zone","sampling_enable","session_statistic","stats","user_tag","uuid",]

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
        oper=dict(type='dict',rule_stats=dict(type='list',rule_hitcount=dict(type='int',),rule_action=dict(type='str',),rule_status=dict(type='str',),rule_name=dict(type='str',)),name=dict(type='str',required=True,),policy_deny=dict(type='int',),policy_rule_count=dict(type='int',),policy_reset=dict(type='int',),rule_list=dict(type='list',oper=dict(type='dict',status=dict(type='str',),denybytes=dict(type='int',),sessionother=dict(type='int',),activesessionother=dict(type='int',),activesessiontcp=dict(type='int',),permitbytes=dict(type='int',),sessiontcp=dict(type='int',),activesessionicmp=dict(type='int',),sessionicmp=dict(type='int',),activesessiontotal=dict(type='int',),hitcount=dict(type='int',),sessiontotal=dict(type='int',),totalbytes=dict(type='int',),action=dict(type='str',),resetbytes=dict(type='int',),sessionudp=dict(type='int',),activesessionudp=dict(type='int',)),name=dict(type='str',required=True,)),policy_unmatched_drop=dict(type='int',),policy_status=dict(type='str',),rules_by_zone=dict(type='dict',oper=dict(type='dict',group_list=dict(type='list',to=dict(type='str',),from=dict(type='str',),rule_list=dict(type='list',dest_list=dict(type='list',dest=dict(type='str',)),action=dict(type='str',),source_list=dict(type='list',source=dict(type='str',)),name=dict(type='str',),service_list=dict(type='list',service=dict(type='str',)))))),policy_permit=dict(type='int',)),
        remark=dict(type='str',),
        stats=dict(type='dict',reset=dict(type='str',),deny=dict(type='str',),name=dict(type='str',required=True,),permit=dict(type='str',),unmatched_drops=dict(type='str',),rules_by_zone=dict(type='dict',stats=dict(type='dict',dummy=dict(type='str',))),rule_list=dict(type='list',stats=dict(type='dict',active_session_other=dict(type='str',),session_icmp=dict(type='str',),hit_count=dict(type='str',),active_session_tcp=dict(type='str',),session_other=dict(type='str',),active_session_icmp=dict(type='str',),permit_bytes=dict(type='str',),reset_bytes=dict(type='str',),session_tcp=dict(type='str',),session_udp=dict(type='str',),active_session_udp=dict(type='str',),deny_bytes=dict(type='str',)),name=dict(type='str',required=True,))),
        name=dict(type='str',required=True,),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','unmatched-drops','permit','deny','reset'])),
        rule_list=dict(type='list',cgnv6_fixed_nat_log=dict(type='bool',),forward_listen_on_port=dict(type='bool',),cgnv6_policy=dict(type='str',choices=['lsn-lid','fixed-nat']),cgnv6_log=dict(type='bool',),forward_log=dict(type='bool',),cgnv6_lsn_log=dict(type='bool',),listen_on_port=dict(type='bool',),move_rule=dict(type='dict',location=dict(type='str',choices=['top','before','after','bottom']),target_rule=dict(type='str',)),src_ipv6_any=dict(type='str',choices=['any']),idle_timeout=dict(type='int',),fwlog=dict(type='bool',),src_zone_any=dict(type='str',choices=['any']),ip_version=dict(type='str',choices=['v4','v6']),action=dict(type='str',choices=['permit','deny','reset']),policy=dict(type='str',choices=['cgnv6','forward']),source_list=dict(type='list',src_ipv6_subnet=dict(type='str',),src_obj_network=dict(type='str',),src_slb_server=dict(type='str',),src_obj_grp_network=dict(type='str',),src_ip_subnet=dict(type='str',)),dst_zone_any=dict(type='str',choices=['any']),status=dict(type='str',choices=['enable','disable']),dst_ipv4_any=dict(type='str',choices=['any']),src_zone=dict(type='str',),src_ipv4_any=dict(type='str',choices=['any']),log=dict(type='bool',),dst_zone=dict(type='str',),service_any=dict(type='str',choices=['any']),remark=dict(type='str',),name=dict(type='str',required=True,),cgnv6_lsn_lid=dict(type='int',),uuid=dict(type='str',),user_tag=dict(type='str',),dst_ipv6_any=dict(type='str',choices=['any']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hit-count','permit-bytes','deny-bytes','reset-bytes','active-session-tcp','active-session-udp','active-session-icmp','active-session-other','session-tcp','session-udp','session-icmp','session-other'])),service_list=dict(type='list',icmp_type=dict(type='int',),range_dst_port=dict(type='int',),icmpv6_code=dict(type='int',),gt_src_port=dict(type='int',),lt_src_port=dict(type='int',),proto_id=dict(type='int',),lt_dst_port=dict(type='int',),alg=dict(type='str',choices=['FTP','TFTP','SIP','DNS','PPTP','RTSP']),obj_grp_service=dict(type='str',),icmpv6_type=dict(type='int',),icmp_code=dict(type='int',),range_src_port=dict(type='int',),eq_dst_port=dict(type='int',),icmp=dict(type='bool',),protocols=dict(type='str',choices=['tcp','udp']),gt_dst_port=dict(type='int',),port_num_end_src=dict(type='int',),special_v6_type=dict(type='str',choices=['any-type','dest-unreachable','echo-reply','echo-request','packet-too-big','param-prob','time-exceeded']),eq_src_port=dict(type='int',),special_v6_code=dict(type='str',choices=['any-code','addr-unreachable','admin-prohibited','no-route','not-neighbour','port-unreachable']),icmpv6=dict(type='bool',),port_num_end_dst=dict(type='int',),special_code=dict(type='str',choices=['any-code','frag-required','host-unreachable','network-unreachable','port-unreachable','proto-unreachable','route-failed']),special_type=dict(type='str',choices=['any-type','echo-reply','echo-request','info-reply','info-request','mask-reply','mask-request','parameter-problem','redirect','source-quench','time-exceeded','timestamp','timestamp-reply','dest-unreachable'])),dest_list=dict(type='list',dst_obj_network=dict(type='str',),dst_obj_grp_network=dict(type='str',),dst_slb_vserver=dict(type='str',),dst_ip_subnet=dict(type='str',),dst_ipv6_subnet=dict(type='str',),dst_slb_server=dict(type='str',)),fw_log=dict(type='bool',)),
        session_statistic=dict(type='str',choices=['enable','disable']),
        rules_by_zone=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dummy'])),uuid=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["rule-set"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rule-set"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rule-set"][k] = v
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
    payload = build_json("rule-set", module)
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
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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