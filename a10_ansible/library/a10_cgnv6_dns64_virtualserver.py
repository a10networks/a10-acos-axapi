#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_dns64_virtualserver
description:
    - Create a DNS64 Virtual Server
short_description: Configures A10 cgnv6.dns64-virtualserver
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
            peak_conn:
                description:
                - "Field peak_conn"
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
            port_list:
                description:
                - "Field port_list"
            curr_conn_overflow:
                description:
                - "Field curr_conn_overflow"
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
            name:
                description:
                - "CGNV6 Virtual Server Name"
            icmpv6_rate_over_limit_drop:
                description:
                - "Field icmpv6_rate_over_limit_drop"
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
            mac:
                description:
                - "Field mac"
            curr_icmp_rate:
                description:
                - "Field curr_icmp_rate"
            icmpv6_lockup_time_left:
                description:
                - "Field icmpv6_lockup_time_left"
            state:
                description:
                - "Field state"
            curr_icmpv6_rate:
                description:
                - "Field curr_icmpv6_rate"
            ip_address:
                description:
                - "Field ip_address"
            icmp_lockup_time_left:
                description:
                - "Field icmp_lockup_time_left"
            migration_status:
                description:
                - "Field migration_status"
    use_if_ip:
        description:
        - "Use Interface IP"
        required: False
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP; "
            uuid:
                description:
                - "uuid of the object"
            precedence:
                description:
                - "Set auto NAT pool as higher precedence for source NAT"
            auto:
                description:
                - "Configure auto NAT for the vport"
            template_policy:
                description:
                - "Policy Template (Policy template name)"
            service_group:
                description:
                - "Bind a Service Group to this Virtual Server (Service Group Name)"
            port_number:
                description:
                - "Port"
            acl_name_list:
                description:
                - "Field acl_name_list"
            sampling_enable:
                description:
                - "Field sampling_enable"
            user_tag:
                description:
                - "Customized tag"
            template_dns:
                description:
                - "DNS template (DNS template name)"
            acl_id_list:
                description:
                - "Field acl_id_list"
            action:
                description:
                - "'enable'= Enable; 'disable'= Disable; "
            pool:
                description:
                - "Specify NAT pool or pool group"
    name:
        description:
        - "CGNV6 Virtual Server Name"
        required: True
    template_policy:
        description:
        - "Policy template name"
        required: False
    vrid:
        description:
        - "Join a vrrp group (Specify ha VRRP-A vrid)"
        required: False
    enable_disable_action:
        description:
        - "'enable'= Enable Virtual Server (default); 'disable'= Disable Virtual Server; "
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    ipv6_address:
        description:
        - "IPV6 address"
        required: False
    netmask:
        description:
        - "IP subnet mask"
        required: False
    ip_address:
        description:
        - "IP Address"
        required: False
    policy:
        description:
        - "Policy template"
        required: False
    ethernet:
        description:
        - "Ethernet interface"
        required: False
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
AVAILABLE_PROPERTIES = ["enable_disable_action","ethernet","ip_address","ipv6_address","name","netmask","oper","policy","port_list","template_policy","use_if_ip","user_tag","uuid","vrid",]

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
        oper=dict(type='dict',peak_conn=dict(type='int',),conn_rate_unit=dict(type='str',choices=['100ms','second']),port_list=dict(type='list',oper=dict(type='dict',http_host_hits=dict(type='bool',),cpu_count=dict(type='int',),loc_list=dict(type='str',),http_hits_list=dict(type='list',name=dict(type='str',),hits_count=dict(type='int',)),http_vport=dict(type='bool',),state=dict(type='str',choices=['All Up','Functional Up','Down','Disb','Unkn']),loc_max_depth=dict(type='int',),level_str=dict(type='str',),loc_last=dict(type='str',),http_url_hits=dict(type='bool',),geo_location=dict(type='str',),http_vport_cpu_list=dict(type='list',REQ_50u=dict(type='int',),http2_control_bytes=dict(type='int',),ws_server_switch=dict(type='int',),REQ_50m=dict(type='int',),status_450=dict(type='int',),http2_reset_received=dict(type='int',),status_510=dict(type='int',),ws_handshake_request=dict(type='int',),http2_header_bytes=dict(type='int',),status_207=dict(type='int',),status_206=dict(type='int',),status_205=dict(type='int',),status_204=dict(type='int',),status_203=dict(type='int',),status_202=dict(type='int',),status_201=dict(type='int',),status_200=dict(type='int',),ws_client_switch=dict(type='int',),status_2xx=dict(type='int',),http2_goaway_received=dict(type='int',),REQ_500u=dict(type='int',),status_4xx=dict(type='int',),status_3xx=dict(type='int',),REQ_200u=dict(type='int',),stream_closed=dict(type='int',),REQ_100m=dict(type='int',),REQ_5m=dict(type='int',),REQ_100u=dict(type='int',),REQ_5s=dict(type='int',),REQ_20m=dict(type='int',),header_length_long=dict(type='int',),REQ_20u=dict(type='int',),REQ_2s=dict(type='int',),total_http2_bytes=dict(type='int',),status_411=dict(type='int',),status_306=dict(type='int',),status_307=dict(type='int',),status_304=dict(type='int',),status_305=dict(type='int',),status_302=dict(type='int',),status_303=dict(type='int',),REQ_2m=dict(type='int',),status_301=dict(type='int',),REQ_10u=dict(type='int',),total_http2_conn=dict(type='int',),REQ_10m=dict(type='int',),REQ_200m=dict(type='int',),peak_http2_conn=dict(type='int',),status_412=dict(type='int',),status_413=dict(type='int',),status_410=dict(type='int',),http2_reset_sent=dict(type='int',),status_416=dict(type='int',),status_417=dict(type='int',),status_414=dict(type='int',),status_415=dict(type='int',),status_418=dict(type='int',),status_unknown=dict(type='int',),status_100=dict(type='int',),status_101=dict(type='int',),status_102=dict(type='int',),status_300=dict(type='int',),status_424=dict(type='int',),curr_http2_conn=dict(type='int',),ws_handshake_success=dict(type='int',),status_504_ax=dict(type='int',),status_6xx=dict(type='int',),status_5xx=dict(type='int',),status_401=dict(type='int',),status_400=dict(type='int',),status_403=dict(type='int',),status_402=dict(type='int',),status_405=dict(type='int',),status_404=dict(type='int',),status_407=dict(type='int',),status_406=dict(type='int',),status_409=dict(type='int',),status_408=dict(type='int',),http2_goaway_sent=dict(type='int',),REQ_1m=dict(type='int',),REQ_1s=dict(type='int',),status_1xx=dict(type='int',),http2_data_bytes=dict(type='int',),status_423=dict(type='int',),status_422=dict(type='int',),status_426=dict(type='int',),status_425=dict(type='int',),REQ_500m=dict(type='int',),status_508=dict(type='int',),status_509=dict(type='int',),REQ_OVER_5s=dict(type='int',),status_500=dict(type='int',),status_501=dict(type='int',),status_502=dict(type='int',),status_503=dict(type='int',),status_504=dict(type='int',),status_505=dict(type='int',),status_506=dict(type='int',),status_507=dict(type='int',),status_449=dict(type='int',)),real_curr_conn=dict(type='int',),loc_success=dict(type='int',),loc_error=dict(type='int',),group_id=dict(type='int',),loc_override=dict(type='int',)),protocol=dict(type='str',required=True,choices=['dns-udp']),port_number=dict(type='int',required=True,)),curr_conn_overflow=dict(type='int',),icmp_rate_over_limit_drop=dict(type='int',),name=dict(type='str',required=True,),icmpv6_rate_over_limit_drop=dict(type='int',),curr_conn_rate=dict(type='int',),mac=dict(type='str',),curr_icmp_rate=dict(type='int',),icmpv6_lockup_time_left=dict(type='int',),state=dict(type='str',choices=['All Up','Functional Up','Partial Up','Down','Disb','Unkn']),curr_icmpv6_rate=dict(type='int',),ip_address=dict(type='str',),icmp_lockup_time_left=dict(type='int',),migration_status=dict(type='str',)),
        use_if_ip=dict(type='bool',),
        port_list=dict(type='list',protocol=dict(type='str',required=True,choices=['dns-udp']),uuid=dict(type='str',),precedence=dict(type='bool',),auto=dict(type='bool',),template_policy=dict(type='str',),service_group=dict(type='str',),port_number=dict(type='int',required=True,),acl_name_list=dict(type='list',acl_name=dict(type='str',),acl_name_src_nat_pool=dict(type='str',),acl_name_seq_num=dict(type='int',)),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_conn','total_l4_conn','total_l7_conn','toatal_tcp_conn','total_conn','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_dns_pkts','total_mf_dns_pkts','es_total_failure_actions','compression_bytes_before','compression_bytes_after','compression_hit','compression_miss','compression_miss_no_client','compression_miss_template_exclusion','curr_req','total_req','total_req_succ','peak_conn','curr_conn_rate','last_rsp_time','fastest_rsp_time','slowest_rsp_time'])),user_tag=dict(type='str',),template_dns=dict(type='str',),acl_id_list=dict(type='list',acl_id_seq_num=dict(type='int',),acl_id=dict(type='int',),acl_id_src_nat_pool=dict(type='str',)),action=dict(type='str',choices=['enable','disable']),pool=dict(type='str',)),
        name=dict(type='str',required=True,),
        template_policy=dict(type='str',),
        vrid=dict(type='int',),
        enable_disable_action=dict(type='str',choices=['enable','disable']),
        user_tag=dict(type='str',),
        ipv6_address=dict(type='str',),
        netmask=dict(type='str',),
        ip_address=dict(type='str',),
        policy=dict(type='bool',),
        ethernet=dict(type='str',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["dns64-virtualserver"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["dns64-virtualserver"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["dns64-virtualserver"][k] = v
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
    payload = build_json("dns64-virtualserver", module)
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