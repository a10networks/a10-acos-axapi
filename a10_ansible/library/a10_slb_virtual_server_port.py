#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_virtual_server_port
description:
    - None
short_description: Configures A10 slb.virtual-server.port
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
    ha_conn_mirror:
        description:
        - "None"
        required: False
    protocol:
        description:
        - "None"
        required: True
    precedence:
        description:
        - "None"
        required: False
    port_translation:
        description:
        - "None"
        required: False
    template_reqmod_icap:
        description:
        - "None"
        required: False
    acl_name_list:
        description:
        - "Field acl_name_list"
        required: False
        suboptions:
            acl_name:
                description:
                - "None"
            acl_name_src_nat_pool:
                description:
                - "None"
            acl_name_seq_num:
                description:
                - "None"
    stats_data_action:
        description:
        - "None"
        required: False
    template_connection_reuse:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    template_tcp_shared:
        description:
        - "None"
        required: False
    template_tcp:
        description:
        - "None"
        required: False
    template_persist_destination_ip:
        description:
        - "None"
        required: False
    when_down:
        description:
        - "None"
        required: False
    template_client_ssl_shared:
        description:
        - "None"
        required: False
    persist_type:
        description:
        - "None"
        required: False
    use_rcv_hop_for_resp:
        description:
        - "None"
        required: False
    scaleout_bucket_count:
        description:
        - "None"
        required: False
    req_fail:
        description:
        - "None"
        required: False
    no_dest_nat:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: False
    template_policy:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    template_diameter:
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
    template_ssli:
        description:
        - "None"
        required: False
    template_smpp:
        description:
        - "None"
        required: False
    no_logging:
        description:
        - "None"
        required: False
    reset_on_server_selection_fail:
        description:
        - "None"
        required: False
    waf_template:
        description:
        - "None"
        required: False
    ipinip:
        description:
        - "None"
        required: False
    no_auto_up_on_aflex:
        description:
        - "None"
        required: False
    rate:
        description:
        - "None"
        required: False
    gslb_enable:
        description:
        - "None"
        required: False
    template_persist_ssl_sid:
        description:
        - "None"
        required: False
    template_dns:
        description:
        - "None"
        required: False
    template_sip:
        description:
        - "None"
        required: False
    template_dblb:
        description:
        - "None"
        required: False
    shared_partition_server_ssl_template:
        description:
        - "None"
        required: False
    template_client_ssl:
        description:
        - "None"
        required: False
    enable_playerid_check:
        description:
        - "None"
        required: False
    service_group:
        description:
        - "None"
        required: False
    template_fix:
        description:
        - "None"
        required: False
    shared_partition_udp:
        description:
        - "None"
        required: False
    syn_cookie:
        description:
        - "None"
        required: False
    alternate_port:
        description:
        - "None"
        required: False
    template_cache:
        description:
        - "None"
        required: False
    rtp_sip_call_id_match:
        description:
        - "None"
        required: False
    template_scaleout:
        description:
        - "None"
        required: False
    template_ftp:
        description:
        - "None"
        required: False
    serv_sel_fail:
        description:
        - "None"
        required: False
    range:
        description:
        - "None"
        required: False
    action:
        description:
        - "None"
        required: False
    shared_partition_client_ssl_template:
        description:
        - "None"
        required: False
    view:
        description:
        - "None"
        required: False
    template_persist_source_ip:
        description:
        - "None"
        required: False
    template_dynamic_service:
        description:
        - "None"
        required: False
    use_cgnv6:
        description:
        - "None"
        required: False
    template_persist_cookie:
        description:
        - "None"
        required: False
    template_virtual_port:
        description:
        - "None"
        required: False
    conn_limit:
        description:
        - "None"
        required: False
    trunk_fwd:
        description:
        - "None"
        required: False
    template_udp_shared:
        description:
        - "None"
        required: False
    pool:
        description:
        - "None"
        required: False
    snat_on_vip:
        description:
        - "None"
        required: False
    shared_partition_tcp:
        description:
        - "None"
        required: False
    template_tcp_proxy_server:
        description:
        - "None"
        required: False
    shared_partition_http_template:
        description:
        - "None"
        required: False
    template_external_service:
        description:
        - "None"
        required: False
    template_udp:
        description:
        - "None"
        required: False
    force_routing_mode:
        description:
        - "None"
        required: False
    template_file_inspection:
        description:
        - "None"
        required: False
    when_down_protocol2:
        description:
        - "None"
        required: False
    def_selection_if_pref_failed:
        description:
        - "None"
        required: False
    template_smtp:
        description:
        - "None"
        required: False
    redirect_to_https:
        description:
        - "None"
        required: False
    alt_protocol2:
        description:
        - "None"
        required: False
    alt_protocol1:
        description:
        - "None"
        required: False
    message_switching:
        description:
        - "None"
        required: False
    template_imap_pop3:
        description:
        - "None"
        required: False
    scaleout_device_group:
        description:
        - "None"
        required: False
    l7_hardware_assist:
        description:
        - "None"
        required: False
    template_http_policy:
        description:
        - "None"
        required: False
    reset:
        description:
        - "None"
        required: False
    use_alternate_port:
        description:
        - "None"
        required: False
    acl_id_list:
        description:
        - "Field acl_id_list"
        required: False
        suboptions:
            acl_id_seq_num:
                description:
                - "None"
            acl_id:
                description:
                - "None"
            acl_id_src_nat_pool:
                description:
                - "None"
    trunk_rev:
        description:
        - "None"
        required: False
    eth_fwd:
        description:
        - "None"
        required: False
    template_respmod_icap:
        description:
        - "None"
        required: False
    template_server_ssl_shared:
        description:
        - "None"
        required: False
    use_default_if_no_server:
        description:
        - "None"
        required: False
    auto:
        description:
        - "None"
        required: False
    aflex_scripts:
        description:
        - "Field aflex_scripts"
        required: False
        suboptions:
            aflex:
                description:
                - "None"
    template_http_shared:
        description:
        - "None"
        required: False
    template_server_ssl:
        description:
        - "None"
        required: False
    alternate_port_number:
        description:
        - "None"
        required: False
    port_number:
        description:
        - "None"
        required: True
    template_tcp_proxy_client:
        description:
        - "None"
        required: False
    template_tcp_proxy:
        description:
        - "None"
        required: False
    extended_stats:
        description:
        - "None"
        required: False
    template_http:
        description:
        - "None"
        required: False
    expand:
        description:
        - "None"
        required: False
    skip_rev_hash:
        description:
        - "None"
        required: False
    on_syn:
        description:
        - "None"
        required: False
    clientip_sticky_nat:
        description:
        - "None"
        required: False
    secs:
        description:
        - "None"
        required: False
    auth_cfg:
        description:
        - "Field auth_cfg"
        required: False
        suboptions:
            aaa_policy:
                description:
                - "None"
    eth_rev:
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
AVAILABLE_PROPERTIES = ["acl_id_list","acl_name_list","action","aflex_scripts","alt_protocol1","alt_protocol2","alternate_port","alternate_port_number","auth_cfg","auto","clientip_sticky_nat","conn_limit","def_selection_if_pref_failed","enable_playerid_check","eth_fwd","eth_rev","expand","extended_stats","force_routing_mode","gslb_enable","ha_conn_mirror","ipinip","l7_hardware_assist","message_switching","name","no_auto_up_on_aflex","no_dest_nat","no_logging","on_syn","persist_type","pool","port_number","port_translation","precedence","protocol","range","rate","redirect_to_https","req_fail","reset","reset_on_server_selection_fail","rtp_sip_call_id_match","sampling_enable","scaleout_bucket_count","scaleout_device_group","secs","serv_sel_fail","service_group","shared_partition_client_ssl_template","shared_partition_http_template","shared_partition_server_ssl_template","shared_partition_tcp","shared_partition_udp","skip_rev_hash","snat_on_vip","stats_data_action","syn_cookie","template_cache","template_client_ssl","template_client_ssl_shared","template_connection_reuse","template_dblb","template_diameter","template_dns","template_dynamic_service","template_external_service","template_file_inspection","template_fix","template_ftp","template_http","template_http_policy","template_http_shared","template_imap_pop3","template_persist_cookie","template_persist_destination_ip","template_persist_source_ip","template_persist_ssl_sid","template_policy","template_reqmod_icap","template_respmod_icap","template_scaleout","template_server_ssl","template_server_ssl_shared","template_sip","template_smpp","template_smtp","template_ssli","template_tcp","template_tcp_proxy","template_tcp_proxy_client","template_tcp_proxy_server","template_tcp_shared","template_udp","template_udp_shared","template_virtual_port","trunk_fwd","trunk_rev","use_alternate_port","use_cgnv6","use_default_if_no_server","use_rcv_hop_for_resp","user_tag","uuid","view","waf_template","when_down","when_down_protocol2",]

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
        ha_conn_mirror=dict(type='bool',),
        protocol=dict(type='str',required=True,choices=['tcp','udp','others','diameter','dns-tcp','dns-udp','fast-http','fix','ftp','ftp-proxy','http','https','http2','http2s','imap','mlb','mms','mysql','mssql','pop3','radius','rtsp','sip','sip-tcp','sips','smpp-tcp','spdy','spdys','smtp','ssl-proxy','ssli','tcp-proxy','tftp','fast-fix']),
        precedence=dict(type='bool',),
        port_translation=dict(type='bool',),
        template_reqmod_icap=dict(type='str',),
        acl_name_list=dict(type='list',acl_name=dict(type='str',),acl_name_src_nat_pool=dict(type='str',),acl_name_seq_num=dict(type='int',)),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        template_connection_reuse=dict(type='str',),
        uuid=dict(type='str',),
        template_tcp_shared=dict(type='str',),
        template_tcp=dict(type='str',),
        template_persist_destination_ip=dict(type='str',),
        when_down=dict(type='bool',),
        template_client_ssl_shared=dict(type='str',),
        persist_type=dict(type='str',choices=['src-dst-ip-swap-persist','use-src-ip-for-dst-persist','use-dst-ip-for-src-persist']),
        use_rcv_hop_for_resp=dict(type='bool',),
        scaleout_bucket_count=dict(type='int',),
        req_fail=dict(type='bool',),
        no_dest_nat=dict(type='bool',),
        name=dict(type='str',),
        template_policy=dict(type='str',),
        user_tag=dict(type='str',),
        template_diameter=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_conn','total_l4_conn','total_l7_conn','total_tcp_conn','total_conn','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_dns_pkts','total_mf_dns_pkts','es_total_failure_actions','compression_bytes_before','compression_bytes_after','compression_hit','compression_miss','compression_miss_no_client','compression_miss_template_exclusion','curr_req','total_req','total_req_succ','peak_conn','curr_conn_rate','last_rsp_time','fastest_rsp_time','slowest_rsp_time','loc_permit','loc_deny','loc_conn','curr_ssl_conn','total_ssl_conn','backend-time-to-first-byte','backend-time-to-last-byte','in-latency','out-latency','total_fwd_bytes_out','total_fwd_pkts_out','total_rev_bytes_out','total_rev_pkts_out'])),
        template_ssli=dict(type='str',),
        template_smpp=dict(type='str',),
        no_logging=dict(type='bool',),
        reset_on_server_selection_fail=dict(type='bool',),
        waf_template=dict(type='str',),
        ipinip=dict(type='bool',),
        no_auto_up_on_aflex=dict(type='bool',),
        rate=dict(type='int',),
        gslb_enable=dict(type='bool',),
        template_persist_ssl_sid=dict(type='str',),
        template_dns=dict(type='str',),
        template_sip=dict(type='str',),
        template_dblb=dict(type='str',),
        shared_partition_server_ssl_template=dict(type='bool',),
        template_client_ssl=dict(type='str',),
        enable_playerid_check=dict(type='bool',),
        service_group=dict(type='str',),
        template_fix=dict(type='str',),
        shared_partition_udp=dict(type='bool',),
        syn_cookie=dict(type='bool',),
        alternate_port=dict(type='bool',),
        template_cache=dict(type='str',),
        rtp_sip_call_id_match=dict(type='bool',),
        template_scaleout=dict(type='str',),
        template_ftp=dict(type='str',),
        serv_sel_fail=dict(type='bool',),
        range=dict(type='int',),
        action=dict(type='str',choices=['enable','disable']),
        shared_partition_client_ssl_template=dict(type='bool',),
        view=dict(type='int',),
        template_persist_source_ip=dict(type='str',),
        template_dynamic_service=dict(type='str',),
        use_cgnv6=dict(type='bool',),
        template_persist_cookie=dict(type='str',),
        template_virtual_port=dict(type='str',),
        conn_limit=dict(type='int',),
        trunk_fwd=dict(type='str',),
        template_udp_shared=dict(type='str',),
        pool=dict(type='str',),
        snat_on_vip=dict(type='bool',),
        shared_partition_tcp=dict(type='bool',),
        template_tcp_proxy_server=dict(type='str',),
        shared_partition_http_template=dict(type='bool',),
        template_external_service=dict(type='str',),
        template_udp=dict(type='str',),
        force_routing_mode=dict(type='bool',),
        template_file_inspection=dict(type='str',),
        when_down_protocol2=dict(type='bool',),
        def_selection_if_pref_failed=dict(type='str',choices=['def-selection-if-pref-failed','def-selection-if-pref-failed-disable']),
        template_smtp=dict(type='str',),
        redirect_to_https=dict(type='bool',),
        alt_protocol2=dict(type='str',choices=['tcp']),
        alt_protocol1=dict(type='str',choices=['http']),
        message_switching=dict(type='bool',),
        template_imap_pop3=dict(type='str',),
        scaleout_device_group=dict(type='int',),
        l7_hardware_assist=dict(type='bool',),
        template_http_policy=dict(type='str',),
        reset=dict(type='bool',),
        use_alternate_port=dict(type='bool',),
        acl_id_list=dict(type='list',acl_id_seq_num=dict(type='int',),acl_id=dict(type='int',),acl_id_src_nat_pool=dict(type='str',)),
        trunk_rev=dict(type='str',),
        eth_fwd=dict(type='str',),
        template_respmod_icap=dict(type='str',),
        template_server_ssl_shared=dict(type='str',),
        use_default_if_no_server=dict(type='bool',),
        auto=dict(type='bool',),
        aflex_scripts=dict(type='list',aflex=dict(type='str',)),
        template_http_shared=dict(type='str',),
        template_server_ssl=dict(type='str',),
        alternate_port_number=dict(type='int',),
        port_number=dict(type='int',required=True,),
        template_tcp_proxy_client=dict(type='str',),
        template_tcp_proxy=dict(type='str',),
        extended_stats=dict(type='bool',),
        template_http=dict(type='str',),
        expand=dict(type='bool',),
        skip_rev_hash=dict(type='bool',),
        on_syn=dict(type='bool',),
        clientip_sticky_nat=dict(type='bool',),
        secs=dict(type='int',),
        auth_cfg=dict(type='dict',aaa_policy=dict(type='str',)),
        eth_rev=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    f_dict["port-number"] = module.params["port-number"]
    f_dict["protocol"] = module.params["protocol"]

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
    payload = build_json("port", module)
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
    payload = build_json("port", module)
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