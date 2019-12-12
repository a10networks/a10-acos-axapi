#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_common
description:
    - SLB related commands
short_description: Configures A10 slb.common
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
    low_latency:
        description:
        - "Enable low latency mode"
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            server_auto_reselect:
                description:
                - "Field server_auto_reselect"
    use_mss_tab:
        description:
        - "Use MSS based on internal table for SLB processing"
        required: False
    stats_data_disable:
        description:
        - "Disable global slb data statistics"
        required: False
    compress_block_size:
        description:
        - "Set compression block size (Compression block size in bytes)"
        required: False
    player_id_check_enable:
        description:
        - "Enable the Player id check"
        required: False
    after_disable:
        description:
        - "Graceful shutdown after disable server/port and/or virtual server/port"
        required: False
    msl_time:
        description:
        - "Configure maximum session life, default is 2 seconds (1-40 seconds, default is 2 seconds)"
        required: False
    graceful_shutdown_enable:
        description:
        - "Enable graceful shutdown"
        required: False
    buff_thresh_hw_buff:
        description:
        - "Set hardware buffer threshold"
        required: False
    hw_syn_rr:
        description:
        - "Configure hardware SYN round robin (range 1-500000)"
        required: False
    entity:
        description:
        - "'server'= Graceful shutdown server/port only; 'virtual-server'= Graceful shutdown virtual server/port only; "
        required: False
    reset_stale_session:
        description:
        - "Send reset if session in delete queue receives a SYN packet"
        required: False
    gateway_health_check:
        description:
        - "Enable gateway health check"
        required: False
    scale_out:
        description:
        - "Enable SLB scale out"
        required: False
    graceful_shutdown:
        description:
        - "1-65535, in unit of seconds"
        required: False
    rate_limit_logging:
        description:
        - "Configure rate limit logging"
        required: False
    fast_path_disable:
        description:
        - "Disable fast path in SLB processing"
        required: False
    drop_icmp_to_vip_when_vip_down:
        description:
        - "Drop ICMP to VIP when VIP down"
        required: False
    ssli_sni_hash_enable:
        description:
        - "Enable SSLi SNI hash table"
        required: False
    hw_compression:
        description:
        - "Use hardware compression"
        required: False
    dns_vip_stateless:
        description:
        - "Enable DNS VIP stateless mode"
        required: False
    buff_thresh_sys_buff_low:
        description:
        - "Set low water mark of system buffer"
        required: False
    range_end:
        description:
        - "port range end"
        required: False
    dns_response_rate_limiting:
        description:
        - "Field dns_response_rate_limiting"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            max_table_entries:
                description:
                - "Maximum number of entries allowed"
    dns_cache_enable:
        description:
        - "Enable DNS cache"
        required: False
    max_local_rate:
        description:
        - "Set maximum local rate"
        required: False
    exclude_destination:
        description:
        - "'local'= Maximum local rate; 'remote'= Maximum remote rate;  (Maximum rates)"
        required: False
    dns_cache_age:
        description:
        - "Set DNS cache entry age, default is 300 seconds (1-1000000 seconds, default is 300 seconds)"
        required: False
    max_http_header_count:
        description:
        - "Set maximum number of HTTP headers allowed"
        required: False
    l2l3_trunk_lb_disable:
        description:
        - "Disable L2/L3 trunk LB"
        required: False
    resolve_port_conflict:
        description:
        - "Enable client port service port conflicts"
        required: False
    sort_res:
        description:
        - "Enable SLB sorting of resource names"
        required: False
    snat_gwy_for_l3:
        description:
        - "Use source NAT gateway for L3 traffic"
        required: False
    buff_thresh_relieve_thresh:
        description:
        - "Relieve threshold"
        required: False
    dsr_health_check_enable:
        description:
        - "Enable dsr-health-check (direct server return health check)"
        required: False
    buff_thresh:
        description:
        - "Set buffer threshold"
        required: False
    dns_cache_entry_size:
        description:
        - "Set DNS cache entry size, default is 256 bytes (1-4096 bytes, default is 256 bytes)"
        required: False
    log_for_reset_unknown_conn:
        description:
        - "Log when rate exceed"
        required: False
    auto_nat_no_ip_refresh:
        description:
        - "'enable'= enable; 'disable'= disable; "
        required: False
    pkt_rate_for_reset_unknown_conn:
        description:
        - "Field pkt_rate_for_reset_unknown_conn"
        required: False
    buff_thresh_sys_buff_high:
        description:
        - "Set high water mark of system buffer"
        required: False
    max_buff_queued_per_conn:
        description:
        - "Set per connection buffer threshold (Buffer value range 128-4096)"
        required: False
    max_remote_rate:
        description:
        - "Set maximum remote rate"
        required: False
    ttl_threshold:
        description:
        - "Only cache DNS response with longer TTL"
        required: False
    extended_stats:
        description:
        - "Enable global slb extended statistics"
        required: False
    enable_l7_req_acct:
        description:
        - "Enable L7 request accounting"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    snat_on_vip:
        description:
        - "Enable source NAT traffic against VIP"
        required: False
    range_start:
        description:
        - "port range start"
        required: False
    honor_server_response_ttl:
        description:
        - "Honor the server reponse TTL"
        required: False
    interval:
        description:
        - "Specify the healthcheck interval, default is 5 seconds (Interval Value, in seconds (default 5))"
        required: False
    stateless_sg_multi_binding:
        description:
        - "Enable stateless service groups to be assigned to multiple L2/L3 DSR VIPs"
        required: False
    disable_adaptive_resource_check:
        description:
        - "Disable adaptive resource check based on buffer usage"
        required: False
    range:
        description:
        - "auto translate port range"
        required: False
    conn_rate_limit:
        description:
        - "Field conn_rate_limit"
        required: False
        suboptions:
            src_ip_list:
                description:
                - "Field src_ip_list"
    mss_table:
        description:
        - "Set MSS table (128-750, default is 536)"
        required: False
    timeout:
        description:
        - "Specify the healthcheck timeout value, default is 15 seconds (Timeout Value, in seconds (default 15))"
        required: False
    response_type:
        description:
        - "'single-answer'= Only cache DNS response with single answer; 'round-robin'= Round robin; "
        required: False
    ddos_protection:
        description:
        - "Field ddos_protection"
        required: False
        suboptions:
            packets_per_second:
                description:
                - "Field packets_per_second"
            logging:
                description:
                - "Field logging"
            ipd_enable_toggle:
                description:
                - "'enable'= Enable SLB DDoS protection; 'disable'= Disable SLB DDoS protection (default); "
    override_port:
        description:
        - "Enable override port in DSR health check mode"
        required: False
    no_auto_up_on_aflex:
        description:
        - "Don't automatically mark vport up when aFleX is bound"
        required: False
    disable_server_auto_reselect:
        description:
        - "Disable auto reselection of server"
        required: False
    software:
        description:
        - "Software"
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
AVAILABLE_PROPERTIES = ["after_disable","auto_nat_no_ip_refresh","buff_thresh","buff_thresh_hw_buff","buff_thresh_relieve_thresh","buff_thresh_sys_buff_high","buff_thresh_sys_buff_low","compress_block_size","conn_rate_limit","ddos_protection","disable_adaptive_resource_check","disable_server_auto_reselect","dns_cache_age","dns_cache_enable","dns_cache_entry_size","dns_response_rate_limiting","dns_vip_stateless","drop_icmp_to_vip_when_vip_down","dsr_health_check_enable","enable_l7_req_acct","entity","exclude_destination","extended_stats","fast_path_disable","gateway_health_check","graceful_shutdown","graceful_shutdown_enable","honor_server_response_ttl","hw_compression","hw_syn_rr","interval","l2l3_trunk_lb_disable","log_for_reset_unknown_conn","low_latency","max_buff_queued_per_conn","max_http_header_count","max_local_rate","max_remote_rate","msl_time","mss_table","no_auto_up_on_aflex","oper","override_port","pkt_rate_for_reset_unknown_conn","player_id_check_enable","range","range_end","range_start","rate_limit_logging","reset_stale_session","resolve_port_conflict","response_type","scale_out","snat_gwy_for_l3","snat_on_vip","software","sort_res","ssli_sni_hash_enable","stateless_sg_multi_binding","stats_data_disable","timeout","ttl_threshold","use_mss_tab","uuid",]

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
        low_latency=dict(type='bool',),
        oper=dict(type='dict',server_auto_reselect=dict(type='int',)),
        use_mss_tab=dict(type='bool',),
        stats_data_disable=dict(type='bool',),
        compress_block_size=dict(type='int',),
        player_id_check_enable=dict(type='bool',),
        after_disable=dict(type='bool',),
        msl_time=dict(type='int',),
        graceful_shutdown_enable=dict(type='bool',),
        buff_thresh_hw_buff=dict(type='int',),
        hw_syn_rr=dict(type='int',),
        entity=dict(type='str',choices=['server','virtual-server']),
        reset_stale_session=dict(type='bool',),
        gateway_health_check=dict(type='bool',),
        scale_out=dict(type='bool',),
        graceful_shutdown=dict(type='int',),
        rate_limit_logging=dict(type='bool',),
        fast_path_disable=dict(type='bool',),
        drop_icmp_to_vip_when_vip_down=dict(type='bool',),
        ssli_sni_hash_enable=dict(type='bool',),
        hw_compression=dict(type='bool',),
        dns_vip_stateless=dict(type='bool',),
        buff_thresh_sys_buff_low=dict(type='int',),
        range_end=dict(type='int',),
        dns_response_rate_limiting=dict(type='dict',uuid=dict(type='str',),max_table_entries=dict(type='int',)),
        dns_cache_enable=dict(type='bool',),
        max_local_rate=dict(type='int',),
        exclude_destination=dict(type='str',choices=['local','remote']),
        dns_cache_age=dict(type='int',),
        max_http_header_count=dict(type='int',),
        l2l3_trunk_lb_disable=dict(type='bool',),
        resolve_port_conflict=dict(type='bool',),
        sort_res=dict(type='bool',),
        snat_gwy_for_l3=dict(type='bool',),
        buff_thresh_relieve_thresh=dict(type='int',),
        dsr_health_check_enable=dict(type='bool',),
        buff_thresh=dict(type='bool',),
        dns_cache_entry_size=dict(type='int',),
        log_for_reset_unknown_conn=dict(type='bool',),
        auto_nat_no_ip_refresh=dict(type='str',choices=['enable','disable']),
        pkt_rate_for_reset_unknown_conn=dict(type='int',),
        buff_thresh_sys_buff_high=dict(type='int',),
        max_buff_queued_per_conn=dict(type='int',),
        max_remote_rate=dict(type='int',),
        ttl_threshold=dict(type='int',),
        extended_stats=dict(type='bool',),
        enable_l7_req_acct=dict(type='bool',),
        uuid=dict(type='str',),
        snat_on_vip=dict(type='bool',),
        range_start=dict(type='int',),
        honor_server_response_ttl=dict(type='bool',),
        interval=dict(type='int',),
        stateless_sg_multi_binding=dict(type='bool',),
        disable_adaptive_resource_check=dict(type='bool',),
        range=dict(type='int',),
        conn_rate_limit=dict(type='dict',src_ip_list=dict(type='list',protocol=dict(type='str',required=True,choices=['tcp','udp']),log=dict(type='bool',),lock_out=dict(type='int',),limit_period=dict(type='str',choices=['100','1000']),limit=dict(type='int',),exceed_action=dict(type='bool',),shared=dict(type='bool',),uuid=dict(type='str',))),
        mss_table=dict(type='int',),
        timeout=dict(type='int',),
        response_type=dict(type='str',choices=['single-answer','round-robin']),
        ddos_protection=dict(type='dict',packets_per_second=dict(type='dict',ipd_tcp=dict(type='int',),ipd_udp=dict(type='int',)),logging=dict(type='dict',ipd_logging_toggle=dict(type='str',choices=['enable','disable'])),ipd_enable_toggle=dict(type='str',choices=['enable','disable'])),
        override_port=dict(type='bool',),
        no_auto_up_on_aflex=dict(type='bool',),
        disable_server_auto_reselect=dict(type='bool',),
        software=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/common"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/common"

    f_dict = {}

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
        for k, v in payload["common"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["common"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["common"][k] = v
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
    payload = build_json("common", module)
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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