#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_virtual_server
description:
    - None
short_description: Configures A10 slb.virtual-server
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
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            ha_conn_mirror:
                description:
                - "None"
            protocol:
                description:
                - "None"
            precedence:
                description:
                - "None"
            port_translation:
                description:
                - "None"
            template_reqmod_icap:
                description:
                - "None"
            acl_name_list:
                description:
                - "Field acl_name_list"
            stats_data_action:
                description:
                - "None"
            template_connection_reuse:
                description:
                - "None"
            uuid:
                description:
                - "None"
            template_tcp_shared:
                description:
                - "None"
            template_tcp:
                description:
                - "None"
            template_persist_destination_ip:
                description:
                - "None"
            when_down:
                description:
                - "None"
            template_client_ssl_shared:
                description:
                - "None"
            persist_type:
                description:
                - "None"
            use_rcv_hop_for_resp:
                description:
                - "None"
            scaleout_bucket_count:
                description:
                - "None"
            req_fail:
                description:
                - "None"
            no_dest_nat:
                description:
                - "None"
            name:
                description:
                - "None"
            template_policy:
                description:
                - "None"
            user_tag:
                description:
                - "None"
            template_diameter:
                description:
                - "None"
            sampling_enable:
                description:
                - "Field sampling_enable"
            template_ssli:
                description:
                - "None"
            template_smpp:
                description:
                - "None"
            no_logging:
                description:
                - "None"
            reset_on_server_selection_fail:
                description:
                - "None"
            waf_template:
                description:
                - "None"
            ipinip:
                description:
                - "None"
            no_auto_up_on_aflex:
                description:
                - "None"
            rate:
                description:
                - "None"
            gslb_enable:
                description:
                - "None"
            template_persist_ssl_sid:
                description:
                - "None"
            template_dns:
                description:
                - "None"
            template_sip:
                description:
                - "None"
            template_dblb:
                description:
                - "None"
            shared_partition_server_ssl_template:
                description:
                - "None"
            template_client_ssl:
                description:
                - "None"
            enable_playerid_check:
                description:
                - "None"
            service_group:
                description:
                - "None"
            template_fix:
                description:
                - "None"
            shared_partition_udp:
                description:
                - "None"
            syn_cookie:
                description:
                - "None"
            alternate_port:
                description:
                - "None"
            template_cache:
                description:
                - "None"
            rtp_sip_call_id_match:
                description:
                - "None"
            template_scaleout:
                description:
                - "None"
            template_ftp:
                description:
                - "None"
            serv_sel_fail:
                description:
                - "None"
            range:
                description:
                - "None"
            action:
                description:
                - "None"
            shared_partition_client_ssl_template:
                description:
                - "None"
            view:
                description:
                - "None"
            template_persist_source_ip:
                description:
                - "None"
            template_dynamic_service:
                description:
                - "None"
            use_cgnv6:
                description:
                - "None"
            template_persist_cookie:
                description:
                - "None"
            template_virtual_port:
                description:
                - "None"
            conn_limit:
                description:
                - "None"
            trunk_fwd:
                description:
                - "None"
            template_udp_shared:
                description:
                - "None"
            pool:
                description:
                - "None"
            snat_on_vip:
                description:
                - "None"
            shared_partition_tcp:
                description:
                - "None"
            template_tcp_proxy_server:
                description:
                - "None"
            shared_partition_http_template:
                description:
                - "None"
            template_external_service:
                description:
                - "None"
            template_udp:
                description:
                - "None"
            force_routing_mode:
                description:
                - "None"
            template_file_inspection:
                description:
                - "None"
            when_down_protocol2:
                description:
                - "None"
            def_selection_if_pref_failed:
                description:
                - "None"
            template_smtp:
                description:
                - "None"
            redirect_to_https:
                description:
                - "None"
            alt_protocol2:
                description:
                - "None"
            alt_protocol1:
                description:
                - "None"
            message_switching:
                description:
                - "None"
            template_imap_pop3:
                description:
                - "None"
            scaleout_device_group:
                description:
                - "None"
            l7_hardware_assist:
                description:
                - "None"
            template_http_policy:
                description:
                - "None"
            reset:
                description:
                - "None"
            use_alternate_port:
                description:
                - "None"
            acl_id_list:
                description:
                - "Field acl_id_list"
            trunk_rev:
                description:
                - "None"
            eth_fwd:
                description:
                - "None"
            template_respmod_icap:
                description:
                - "None"
            template_server_ssl_shared:
                description:
                - "None"
            use_default_if_no_server:
                description:
                - "None"
            auto:
                description:
                - "None"
            aflex_scripts:
                description:
                - "Field aflex_scripts"
            template_http_shared:
                description:
                - "None"
            template_server_ssl:
                description:
                - "None"
            alternate_port_number:
                description:
                - "None"
            port_number:
                description:
                - "None"
            template_tcp_proxy_client:
                description:
                - "None"
            template_tcp_proxy:
                description:
                - "None"
            extended_stats:
                description:
                - "None"
            template_http:
                description:
                - "None"
            expand:
                description:
                - "None"
            skip_rev_hash:
                description:
                - "None"
            on_syn:
                description:
                - "None"
            clientip_sticky_nat:
                description:
                - "None"
            secs:
                description:
                - "None"
            auth_cfg:
                description:
                - "Field auth_cfg"
            eth_rev:
                description:
                - "None"
    stats_data_action:
        description:
        - "None"
        required: False
    acl_name:
        description:
        - "None"
        required: False
    enable_disable_action:
        description:
        - "None"
        required: False
    ha_dynamic:
        description:
        - "None"
        required: False
    redistribute_route_map:
        description:
        - "None"
        required: False
    ip_address:
        description:
        - "None"
        required: False
    template_logging:
        description:
        - "None"
        required: False
    use_if_ip:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    vrid:
        description:
        - "None"
        required: False
    disable_vip_adv:
        description:
        - "None"
        required: False
    template_virtual_server:
        description:
        - "None"
        required: False
    arp_disable:
        description:
        - "None"
        required: False
    description:
        description:
        - "None"
        required: False
    redistribution_flagged:
        description:
        - "None"
        required: False
    netmask:
        description:
        - "None"
        required: False
    acl_id:
        description:
        - "None"
        required: False
    ipv6_acl:
        description:
        - "None"
        required: False
    migrate_vip:
        description:
        - "Field migrate_vip"
        required: False
        suboptions:
            target_data_cpu:
                description:
                - "None"
            uuid:
                description:
                - "None"
            finish_migration:
                description:
                - "None"
            target_floating_ipv6:
                description:
                - "None"
            target_floating_ipv4:
                description:
                - "None"
            cancel_migration:
                description:
                - "None"
    extended_stats:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    template_scaleout:
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
    ipv6_address:
        description:
        - "None"
        required: False
    ethernet:
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
AVAILABLE_PROPERTIES = ["acl_id","acl_name","arp_disable","description","disable_vip_adv","enable_disable_action","ethernet","extended_stats","ha_dynamic","ip_address","ipv6_acl","ipv6_address","migrate_vip","name","netmask","port_list","redistribute_route_map","redistribution_flagged","stats_data_action","template_logging","template_policy","template_scaleout","template_virtual_server","use_if_ip","user_tag","uuid","vrid",]

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
        port_list=dict(type='list',ha_conn_mirror=dict(type='bool',),protocol=dict(type='str',required=True,choices=['tcp','udp','others','diameter','dns-tcp','dns-udp','fast-http','fix','ftp','ftp-proxy','http','https','http2','http2s','imap','mlb','mms','mysql','mssql','pop3','radius','rtsp','sip','sip-tcp','sips','smpp-tcp','spdy','spdys','smtp','ssl-proxy','ssli','tcp-proxy','tftp','fast-fix']),precedence=dict(type='bool',),port_translation=dict(type='bool',),template_reqmod_icap=dict(type='str',),acl_name_list=dict(type='list',acl_name=dict(type='str',),acl_name_src_nat_pool=dict(type='str',),acl_name_seq_num=dict(type='int',)),stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),template_connection_reuse=dict(type='str',),uuid=dict(type='str',),template_tcp_shared=dict(type='str',),template_tcp=dict(type='str',),template_persist_destination_ip=dict(type='str',),when_down=dict(type='bool',),template_client_ssl_shared=dict(type='str',),persist_type=dict(type='str',choices=['src-dst-ip-swap-persist','use-src-ip-for-dst-persist','use-dst-ip-for-src-persist']),use_rcv_hop_for_resp=dict(type='bool',),scaleout_bucket_count=dict(type='int',),req_fail=dict(type='bool',),no_dest_nat=dict(type='bool',),name=dict(type='str',),template_policy=dict(type='str',),user_tag=dict(type='str',),template_diameter=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_conn','total_l4_conn','total_l7_conn','total_tcp_conn','total_conn','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_dns_pkts','total_mf_dns_pkts','es_total_failure_actions','compression_bytes_before','compression_bytes_after','compression_hit','compression_miss','compression_miss_no_client','compression_miss_template_exclusion','curr_req','total_req','total_req_succ','peak_conn','curr_conn_rate','last_rsp_time','fastest_rsp_time','slowest_rsp_time','loc_permit','loc_deny','loc_conn','curr_ssl_conn','total_ssl_conn','backend-time-to-first-byte','backend-time-to-last-byte','in-latency','out-latency','total_fwd_bytes_out','total_fwd_pkts_out','total_rev_bytes_out','total_rev_pkts_out'])),template_ssli=dict(type='str',),template_smpp=dict(type='str',),no_logging=dict(type='bool',),reset_on_server_selection_fail=dict(type='bool',),waf_template=dict(type='str',),ipinip=dict(type='bool',),no_auto_up_on_aflex=dict(type='bool',),rate=dict(type='int',),gslb_enable=dict(type='bool',),template_persist_ssl_sid=dict(type='str',),template_dns=dict(type='str',),template_sip=dict(type='str',),template_dblb=dict(type='str',),shared_partition_server_ssl_template=dict(type='bool',),template_client_ssl=dict(type='str',),enable_playerid_check=dict(type='bool',),service_group=dict(type='str',),template_fix=dict(type='str',),shared_partition_udp=dict(type='bool',),syn_cookie=dict(type='bool',),alternate_port=dict(type='bool',),template_cache=dict(type='str',),rtp_sip_call_id_match=dict(type='bool',),template_scaleout=dict(type='str',),template_ftp=dict(type='str',),serv_sel_fail=dict(type='bool',),range=dict(type='int',),action=dict(type='str',choices=['enable','disable']),shared_partition_client_ssl_template=dict(type='bool',),view=dict(type='int',),template_persist_source_ip=dict(type='str',),template_dynamic_service=dict(type='str',),use_cgnv6=dict(type='bool',),template_persist_cookie=dict(type='str',),template_virtual_port=dict(type='str',),conn_limit=dict(type='int',),trunk_fwd=dict(type='str',),template_udp_shared=dict(type='str',),pool=dict(type='str',),snat_on_vip=dict(type='bool',),shared_partition_tcp=dict(type='bool',),template_tcp_proxy_server=dict(type='str',),shared_partition_http_template=dict(type='bool',),template_external_service=dict(type='str',),template_udp=dict(type='str',),force_routing_mode=dict(type='bool',),template_file_inspection=dict(type='str',),when_down_protocol2=dict(type='bool',),def_selection_if_pref_failed=dict(type='str',choices=['def-selection-if-pref-failed','def-selection-if-pref-failed-disable']),template_smtp=dict(type='str',),redirect_to_https=dict(type='bool',),alt_protocol2=dict(type='str',choices=['tcp']),alt_protocol1=dict(type='str',choices=['http']),message_switching=dict(type='bool',),template_imap_pop3=dict(type='str',),scaleout_device_group=dict(type='int',),l7_hardware_assist=dict(type='bool',),template_http_policy=dict(type='str',),reset=dict(type='bool',),use_alternate_port=dict(type='bool',),acl_id_list=dict(type='list',acl_id_seq_num=dict(type='int',),acl_id=dict(type='int',),acl_id_src_nat_pool=dict(type='str',)),trunk_rev=dict(type='str',),eth_fwd=dict(type='str',),template_respmod_icap=dict(type='str',),template_server_ssl_shared=dict(type='str',),use_default_if_no_server=dict(type='bool',),auto=dict(type='bool',),aflex_scripts=dict(type='list',aflex=dict(type='str',)),template_http_shared=dict(type='str',),template_server_ssl=dict(type='str',),alternate_port_number=dict(type='int',),port_number=dict(type='int',required=True,),template_tcp_proxy_client=dict(type='str',),template_tcp_proxy=dict(type='str',),extended_stats=dict(type='bool',),template_http=dict(type='str',),expand=dict(type='bool',),skip_rev_hash=dict(type='bool',),on_syn=dict(type='bool',),clientip_sticky_nat=dict(type='bool',),secs=dict(type='int',),auth_cfg=dict(type='dict',aaa_policy=dict(type='str',)),eth_rev=dict(type='str',)),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        acl_name=dict(type='str',),
        enable_disable_action=dict(type='str',choices=['enable','disable','disable-when-all-ports-down','disable-when-any-port-down']),
        ha_dynamic=dict(type='int',),
        redistribute_route_map=dict(type='str',),
        ip_address=dict(type='str',),
        template_logging=dict(type='str',),
        use_if_ip=dict(type='bool',),
        uuid=dict(type='str',),
        vrid=dict(type='int',),
        disable_vip_adv=dict(type='bool',),
        template_virtual_server=dict(type='str',),
        arp_disable=dict(type='bool',),
        description=dict(type='str',),
        redistribution_flagged=dict(type='bool',),
        netmask=dict(type='str',),
        acl_id=dict(type='int',),
        ipv6_acl=dict(type='str',),
        migrate_vip=dict(type='dict',target_data_cpu=dict(type='int',),uuid=dict(type='str',),finish_migration=dict(type='bool',),target_floating_ipv6=dict(type='str',),target_floating_ipv4=dict(type='str',),cancel_migration=dict(type='bool',)),
        extended_stats=dict(type='bool',),
        name=dict(type='str',required=True,),
        template_scaleout=dict(type='str',),
        template_policy=dict(type='str',),
        user_tag=dict(type='str',),
        ipv6_address=dict(type='str',),
        ethernet=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    requires_one_of = sorted(['ip_address','ipv6_address'])
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
    payload = build_json("virtual-server", module)
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
    payload = build_json("virtual-server", module)
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