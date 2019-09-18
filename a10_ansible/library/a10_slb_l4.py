#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_l4
description:
    - Configure L4
short_description: Configures A10 slb.l4
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'intcp'= TCP received; 'synreceived'= TCP SYN received; 'tcp_fwd_last_ack'= L4 rcv fwd last ACK; 'tcp_rev_last_ack'= L4 rcv rev last ACK; 'tcp_rev_fin'= L4 rcv rev FIN; 'tcp_fwd_fin'= L4 rcv fwd FIN; 'tcp_fwd_ackfin'= L4 rcv fwd FIN|ACK; 'inudp'= UDP received; 'syncookiessent'= TCP SYN cookie snt; 'syncookiessent_ts'= TCP SYN cookie snt ts; 'syncookiessentfailed'= TCP SYN cookie snt fail; 'outrst'= TCP out RST; 'outrst_nosyn'= TCP out RST no SYN; 'outrst_broker'= TCP out RST L4 proxy; 'outrst_ack_attack'= TCP out RST ACK attack; 'outrst_aflex'= TCP out RST aFleX; 'outrst_stale_sess'= TCP out RST stale sess; 'syn_stale_sess'= SYN stale sess drop; 'outrst_tcpproxy'= TCP out RST TCP proxy; 'svrselfail'= Server sel failure; 'noroute'= IP out noroute; 'snat_fail'= Source NAT failure; 'snat_no_fwd_route'= Source NAT no fwd route; 'snat_no_rev_route'= Source NAT no rev route; 'snat_icmp_error_process'= Source NAT ICMP Process; 'snat_icmp_no_match'= Source NAT ICMP No Match; 'smart_nat_id_mismatch'= Auto NAT id mismatch; 'syncookiescheckfailed'= TCP SYN cookie failed; 'novport_drop'= NAT no session drops; 'no_vport_drop'= vport not matching drops; 'nosyn_drop'= No SYN pkt drops; 'nosyn_drop_fin'= No SYN pkt drops - FIN; 'nosyn_drop_rst'= No SYN pkt drops - RST; 'nosyn_drop_ack'= No SYN pkt drops - ACK; 'connlimit_drop'= Conn Limit drops; 'connlimit_reset'= Conn Limit resets; 'conn_rate_limit_drop'= Conn rate limit drops; 'conn_rate_limit_reset'= Conn rate limit resets; 'proxy_nosock_drop'= Proxy no sock drops; 'drop_aflex'= aFleX drops; 'sess_aged_out'= Session aged out; 'tcp_sess_aged_out'= TCP Session aged out; 'udp_sess_aged_out'= UDP Session aged out; 'other_sess_aged_out'= Other Session aged out; 'tcp_no_slb'= TCP no SLB; 'udp_no_slb'= UDP no SLB; 'throttle_syn'= SYN Throttle; 'drop_gslb'= Drop GSLB; 'inband_hm_retry'= Inband HM retry; 'inband_hm_reassign'= Inband HM reassign; 'auto_reassign'= Auto-reselect server; 'fast_aging_set'= Fast aging set; 'fast_aging_reset'= Fast aging reset; 'dns_policy_drop'= DNS Policy Drop; 'tcp_invalid_drop'= TCP invalid drop; 'anomaly_out_seq'= Anomaly out of sequence; 'anomaly_zero_win'= Anomaly zero window; 'anomaly_bad_content'= Anomaly bad content; 'anomaly_pbslb_drop'= Anomaly pbslb drop; 'no_resourse_drop'= No resource drop; 'reset_unknown_conn'= Reset unknown conn; 'reset_l7_on_failover'= RST L7 on failover; 'ignore_msl'= ignore msl; 'l2_dsr'= L2 DSR received; 'l3_dsr'= L3 DSR received; 'port_preserve_attempt'= NAT Port Preserve Try; 'port_preserve_succ'= NAT Port Preserve Succ; 'tcpsyndata_drop'= TCP SYN With Data Drop; 'tcpotherflags_drop'= TCP SYN Other Flags Drop; 'bw_rate_limit_exceed'= BW-Limit Exceed drop; 'bw_watermark_drop'= BW-Watermark drop; 'l4_cps_exceed'= L4 CPS exceed drop; 'nat_cps_exceed'= NAT CPS exceed drop; 'l7_cps_exceed'= L7 CPS exceed drop; 'ssl_cps_exceed'= SSL CPS exceed drop; 'ssl_tpt_exceed'= SSL TPT exceed drop; 'ssl_watermark_drop'= SSL TPT-Watermark drop; 'concurrent_conn_exceed'= L3V Conn Limit Drop; 'svr_syn_handshake_fail'= L4 server handshake fail; 'stateless_conn_timeout'= L4 stateless Conn TO; 'tcp_ax_rexmit_syn'= L4 AX re-xmit SYN; 'tcp_syn_rcv_ack'= L4 rcv ACK on SYN; 'tcp_syn_rcv_rst'= L4 rcv RST on SYN; 'tcp_sess_noest_aged_out'= TCP no-Est Sess aged out; 'tcp_sess_noest_csyn_rcv_aged_out'= no-Est CSYN rcv aged out; 'tcp_sess_noest_ssyn_xmit_aged_out'= no-Est SSYN snt aged out; 'tcp_rexmit_syn'= L4 rcv rexmit SYN; 'tcp_rexmit_syn_delq'= L4 rcv rexmit SYN (delq); 'tcp_rexmit_synack'= L4 rcv rexmit SYN|ACK; 'tcp_rexmit_synack_delq'= L4 rcv rexmit SYN|ACK DQ; 'tcp_fwd_fin_dup'= L4 rcv fwd FIN dup; 'tcp_rev_fin_dup'= L4 rcv rev FIN dup; 'tcp_rev_ackfin'= L4 rcv rev FIN|ACK; 'tcp_fwd_rst'= L4 rcv fwd RST; 'tcp_rev_rst'= L4 rcv rev RST; 'udp_req_oneplus_no_resp'= L4 UDP reqs no rsp; 'udp_req_one_oneplus_resp'= L4 UDP req rsps; 'udp_req_resp_notmatch'= L4 UDP req/rsp not match; 'udp_req_more_resp'= L4 UDP req greater than rsps; 'udp_resp_more_req'= L4 UDP rsps greater than reqs; 'udp_req_oneplus'= L4 UDP reqs; 'udp_resp_oneplus'= L4 UDP rsps; 'out_seq_ack_drop'= Out of sequence ACK drop; 'tcp_est'= L4 TCP Established; 'synattack'= L4 SYN attack; 'syn_rate'= TCP SYN rate per sec; 'syncookie_buff_drop'= TCP SYN cookie buff drop; 'syncookie_buff_queue'= TCP SYN cookie buff queue; 'skip_insert_client_ip'= Skip Insert-client-ip; 'synreceived_hw'= TCP SYN (HW SYN cookie); 'dns_id_switch'= DNS query id switch; 'server_down_del'= Server Down Del switch; 'dnssec_switch'= DNSSEC SG switch; 'rate_drop_reset_unkn'= Rate Drop reset; 'tcp_connections_closed'= TCP Connections Closed; "
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','intcp','synreceived','tcp_fwd_last_ack','tcp_rev_last_ack','tcp_rev_fin','tcp_fwd_fin','tcp_fwd_ackfin','inudp','syncookiessent','syncookiessent_ts','syncookiessentfailed','outrst','outrst_nosyn','outrst_broker','outrst_ack_attack','outrst_aflex','outrst_stale_sess','syn_stale_sess','outrst_tcpproxy','svrselfail','noroute','snat_fail','snat_no_fwd_route','snat_no_rev_route','snat_icmp_error_process','snat_icmp_no_match','smart_nat_id_mismatch','syncookiescheckfailed','novport_drop','no_vport_drop','nosyn_drop','nosyn_drop_fin','nosyn_drop_rst','nosyn_drop_ack','connlimit_drop','connlimit_reset','conn_rate_limit_drop','conn_rate_limit_reset','proxy_nosock_drop','drop_aflex','sess_aged_out','tcp_sess_aged_out','udp_sess_aged_out','other_sess_aged_out','tcp_no_slb','udp_no_slb','throttle_syn','drop_gslb','inband_hm_retry','inband_hm_reassign','auto_reassign','fast_aging_set','fast_aging_reset','dns_policy_drop','tcp_invalid_drop','anomaly_out_seq','anomaly_zero_win','anomaly_bad_content','anomaly_pbslb_drop','no_resourse_drop','reset_unknown_conn','reset_l7_on_failover','ignore_msl','l2_dsr','l3_dsr','port_preserve_attempt','port_preserve_succ','tcpsyndata_drop','tcpotherflags_drop','bw_rate_limit_exceed','bw_watermark_drop','l4_cps_exceed','nat_cps_exceed','l7_cps_exceed','ssl_cps_exceed','ssl_tpt_exceed','ssl_watermark_drop','concurrent_conn_exceed','svr_syn_handshake_fail','stateless_conn_timeout','tcp_ax_rexmit_syn','tcp_syn_rcv_ack','tcp_syn_rcv_rst','tcp_sess_noest_aged_out','tcp_sess_noest_csyn_rcv_aged_out','tcp_sess_noest_ssyn_xmit_aged_out','tcp_rexmit_syn','tcp_rexmit_syn_delq','tcp_rexmit_synack','tcp_rexmit_synack_delq','tcp_fwd_fin_dup','tcp_rev_fin_dup','tcp_rev_ackfin','tcp_fwd_rst','tcp_rev_rst','udp_req_oneplus_no_resp','udp_req_one_oneplus_resp','udp_req_resp_notmatch','udp_req_more_resp','udp_resp_more_req','udp_req_oneplus','udp_resp_oneplus','out_seq_ack_drop','tcp_est','synattack','syn_rate','syncookie_buff_drop','syncookie_buff_queue','skip_insert_client_ip','synreceived_hw','dns_id_switch','server_down_del','dnssec_switch','rate_drop_reset_unkn','tcp_connections_closed'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/l4"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/l4"

    f_dict = {}

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

def get_oper(module)
    return module.client.get(oper_url(module))

def get_stats(module)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["l4"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["l4"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["l4"][k] = v
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
    payload = build_json("l4", module)
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
    payload = build_json("l4", module)
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