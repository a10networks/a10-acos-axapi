#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_common
description:
    - None
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
    low_latency:
        description:
        - "None"
        required: False
    use_mss_tab:
        description:
        - "None"
        required: False
    stats_data_disable:
        description:
        - "None"
        required: False
    compress_block_size:
        description:
        - "None"
        required: False
    player_id_check_enable:
        description:
        - "None"
        required: False
    dns_cache_enable:
        description:
        - "None"
        required: False
    msl_time:
        description:
        - "None"
        required: False
    graceful_shutdown_enable:
        description:
        - "None"
        required: False
    buff_thresh_hw_buff:
        description:
        - "None"
        required: False
    hw_syn_rr:
        description:
        - "None"
        required: False
    entity:
        description:
        - "None"
        required: False
    reset_stale_session:
        description:
        - "None"
        required: False
    gateway_health_check:
        description:
        - "None"
        required: False
    scale_out:
        description:
        - "None"
        required: False
    graceful_shutdown:
        description:
        - "None"
        required: False
    rate_limit_logging:
        description:
        - "None"
        required: False
    fast_path_disable:
        description:
        - "None"
        required: False
    drop_icmp_to_vip_when_vip_down:
        description:
        - "None"
        required: False
    ssli_sni_hash_enable:
        description:
        - "None"
        required: False
    hw_compression:
        description:
        - "None"
        required: False
    dns_vip_stateless:
        description:
        - "None"
        required: False
    buff_thresh_sys_buff_low:
        description:
        - "None"
        required: False
    range_end:
        description:
        - "None"
        required: False
    after_disable:
        description:
        - "None"
        required: False
    max_local_rate:
        description:
        - "None"
        required: False
    exclude_destination:
        description:
        - "None"
        required: False
    dns_cache_age:
        description:
        - "None"
        required: False
    max_http_header_count:
        description:
        - "None"
        required: False
    l2l3_trunk_lb_disable:
        description:
        - "None"
        required: False
    sort_res:
        description:
        - "None"
        required: False
    snat_gwy_for_l3:
        description:
        - "None"
        required: False
    buff_thresh_relieve_thresh:
        description:
        - "None"
        required: False
    dsr_health_check_enable:
        description:
        - "None"
        required: False
    buff_thresh:
        description:
        - "None"
        required: False
    dns_cache_entry_size:
        description:
        - "None"
        required: False
    log_for_reset_unknown_conn:
        description:
        - "None"
        required: False
    auto_nat_no_ip_refresh:
        description:
        - "None"
        required: False
    pkt_rate_for_reset_unknown_conn:
        description:
        - "Field pkt_rate_for_reset_unknown_conn"
        required: False
    buff_thresh_sys_buff_high:
        description:
        - "None"
        required: False
    max_buff_queued_per_conn:
        description:
        - "None"
        required: False
    max_remote_rate:
        description:
        - "None"
        required: False
    ttl_threshold:
        description:
        - "None"
        required: False
    extended_stats:
        description:
        - "None"
        required: False
    enable_l7_req_acct:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    snat_on_vip:
        description:
        - "None"
        required: False
    range_start:
        description:
        - "None"
        required: False
    honor_server_response_ttl:
        description:
        - "None"
        required: False
    interval:
        description:
        - "None"
        required: False
    stateless_sg_multi_binding:
        description:
        - "None"
        required: False
    disable_adaptive_resource_check:
        description:
        - "None"
        required: False
    range:
        description:
        - "None"
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
        - "None"
        required: False
    timeout:
        description:
        - "None"
        required: False
    response_type:
        description:
        - "None"
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
                - "None"
    override_port:
        description:
        - "None"
        required: False
    no_auto_up_on_aflex:
        description:
        - "None"
        required: False
    disable_server_auto_reselect:
        description:
        - "None"
        required: False
    software:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["after_disable","auto_nat_no_ip_refresh","buff_thresh","buff_thresh_hw_buff","buff_thresh_relieve_thresh","buff_thresh_sys_buff_high","buff_thresh_sys_buff_low","compress_block_size","conn_rate_limit","ddos_protection","disable_adaptive_resource_check","disable_server_auto_reselect","dns_cache_age","dns_cache_enable","dns_cache_entry_size","dns_vip_stateless","drop_icmp_to_vip_when_vip_down","dsr_health_check_enable","enable_l7_req_acct","entity","exclude_destination","extended_stats","fast_path_disable","gateway_health_check","graceful_shutdown","graceful_shutdown_enable","honor_server_response_ttl","hw_compression","hw_syn_rr","interval","l2l3_trunk_lb_disable","log_for_reset_unknown_conn","low_latency","max_buff_queued_per_conn","max_http_header_count","max_local_rate","max_remote_rate","msl_time","mss_table","no_auto_up_on_aflex","override_port","pkt_rate_for_reset_unknown_conn","player_id_check_enable","range","range_end","range_start","rate_limit_logging","reset_stale_session","response_type","scale_out","snat_gwy_for_l3","snat_on_vip","software","sort_res","ssli_sni_hash_enable","stateless_sg_multi_binding","stats_data_disable","timeout","ttl_threshold","use_mss_tab","uuid",]

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
        low_latency=dict(type='bool',),
        use_mss_tab=dict(type='bool',),
        stats_data_disable=dict(type='bool',),
        compress_block_size=dict(type='int',),
        player_id_check_enable=dict(type='bool',),
        dns_cache_enable=dict(type='bool',),
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
        after_disable=dict(type='bool',),
        max_local_rate=dict(type='int',),
        exclude_destination=dict(type='str',choices=['local','remote']),
        dns_cache_age=dict(type='int',),
        max_http_header_count=dict(type='int',),
        l2l3_trunk_lb_disable=dict(type='bool',),
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
    payload = build_json("common", module)
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
    payload = build_json("common", module)
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