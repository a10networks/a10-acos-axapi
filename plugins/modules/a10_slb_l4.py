#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
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
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    ansible_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
            cpu_count:
                description:
                - "Field cpu_count"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'intcp'= TCP received; 'synreceived'= TCP SYN received; 'tcp_fwd_last_ack'= L4 rcv fwd last ACK; 'tcp_rev_last_ack'= L4 rcv rev last ACK; 'tcp_rev_fin'= L4 rcv rev FIN; 'tcp_fwd_fin'= L4 rcv fwd FIN; 'tcp_fwd_ackfin'= L4 rcv fwd FIN|ACK; 'inudp'= UDP received; 'syncookiessent'= TCP SYN cookie snt; 'syncookiessent_ts'= TCP SYN cookie snt ts; 'syncookiessentfailed'= TCP SYN cookie snt fail; 'outrst'= TCP out RST; 'outrst_nosyn'= TCP out RST no SYN; 'outrst_broker'= TCP out RST L4 proxy; 'outrst_ack_attack'= TCP out RST ACK attack; 'outrst_aflex'= TCP out RST aFleX; 'outrst_stale_sess'= TCP out RST stale sess; 'syn_stale_sess'= SYN stale sess drop; 'outrst_tcpproxy'= TCP out RST TCP proxy; 'svrselfail'= Server sel failure; 'noroute'= IP out noroute; 'snat_fail'= Source NAT failure; 'snat_no_fwd_route'= Source NAT no fwd route; 'snat_no_rev_route'= Source NAT no rev route; 'snat_icmp_error_process'= Source NAT ICMP Process; 'snat_icmp_no_match'= Source NAT ICMP No Match; 'smart_nat_id_mismatch'= Auto NAT id mismatch; 'syncookiescheckfailed'= TCP SYN cookie failed; 'novport_drop'= NAT no session drops; 'no_vport_drop'= vport not matching drops; 'nosyn_drop'= No SYN pkt drops; 'nosyn_drop_fin'= No SYN pkt drops - FIN; 'nosyn_drop_rst'= No SYN pkt drops - RST; 'nosyn_drop_ack'= No SYN pkt drops - ACK; 'connlimit_drop'= Conn Limit drops; 'connlimit_reset'= Conn Limit resets; 'conn_rate_limit_drop'= Conn rate limit drops; 'conn_rate_limit_reset'= Conn rate limit resets; 'proxy_nosock_drop'= Proxy no sock drops; 'drop_aflex'= aFleX drops; 'sess_aged_out'= Session aged out; 'tcp_sess_aged_out'= TCP Session aged out; 'udp_sess_aged_out'= UDP Session aged out; 'other_sess_aged_out'= Other Session aged out; 'tcp_no_slb'= TCP no SLB; 'udp_no_slb'= UDP no SLB; 'throttle_syn'= SYN Throttle; 'drop_gslb'= Drop GSLB; 'inband_hm_retry'= Inband HM retry; 'inband_hm_reassign'= Inband HM reassign; 'auto_reassign'= Auto-reselect server; 'fast_aging_set'= Fast aging set; 'fast_aging_reset'= Fast aging reset; 'dns_policy_drop'= DNS Policy Drop; 'tcp_invalid_drop'= TCP invalid drop; 'anomaly_out_seq'= Anomaly out of sequence; 'anomaly_zero_win'= Anomaly zero window; 'anomaly_bad_content'= Anomaly bad content; 'anomaly_pbslb_drop'= Anomaly pbslb drop; 'no_resourse_drop'= No resource drop; 'reset_unknown_conn'= Reset unknown conn; 'reset_l7_on_failover'= RST L7 on failover; 'ignore_msl'= ignore msl; 'l2_dsr'= L2 DSR received; 'l3_dsr'= L3 DSR received; 'port_preserve_attempt'= NAT Port Preserve Try; 'port_preserve_succ'= NAT Port Preserve Succ; 'tcpsyndata_drop'= TCP SYN With Data Drop; 'tcpotherflags_drop'= TCP SYN Other Flags Drop; 'bw_rate_limit_exceed'= BW-Limit Exceed drop; 'bw_watermark_drop'= BW-Watermark drop; 'l4_cps_exceed'= L4 CPS exceed drop; 'nat_cps_exceed'= NAT CPS exceed drop; 'l7_cps_exceed'= L7 CPS exceed drop; 'ssl_cps_exceed'= SSL CPS exceed drop; 'ssl_tpt_exceed'= SSL TPT exceed drop; 'ssl_watermark_drop'= SSL TPT-Watermark drop; 'concurrent_conn_exceed'= L3V Conn Limit Drop; 'svr_syn_handshake_fail'= L4 server handshake fail; 'stateless_conn_timeout'= L4 stateless Conn TO; 'tcp_ax_rexmit_syn'= L4 AX re-xmit SYN; 'tcp_syn_rcv_ack'= L4 rcv ACK on SYN; 'tcp_syn_rcv_rst'= L4 rcv RST on SYN; 'tcp_sess_noest_aged_out'= TCP no-Est Sess aged out; 'tcp_sess_noest_csyn_rcv_aged_out'= no-Est CSYN rcv aged out; 'tcp_sess_noest_ssyn_xmit_aged_out'= no-Est SSYN snt aged out; 'tcp_rexmit_syn'= L4 rcv rexmit SYN; 'tcp_rexmit_syn_delq'= L4 rcv rexmit SYN (delq); 'tcp_rexmit_synack'= L4 rcv rexmit SYN|ACK; 'tcp_rexmit_synack_delq'= L4 rcv rexmit SYN|ACK DQ; 'tcp_fwd_fin_dup'= L4 rcv fwd FIN dup; 'tcp_rev_fin_dup'= L4 rcv rev FIN dup; 'tcp_rev_ackfin'= L4 rcv rev FIN|ACK; 'tcp_fwd_rst'= L4 rcv fwd RST; 'tcp_rev_rst'= L4 rcv rev RST; 'udp_req_oneplus_no_resp'= L4 UDP reqs no rsp; 'udp_req_one_oneplus_resp'= L4 UDP req rsps; 'udp_req_resp_notmatch'= L4 UDP req/rsp not match; 'udp_req_more_resp'= L4 UDP req greater than rsps; 'udp_resp_more_req'= L4 UDP rsps greater than reqs; 'udp_req_oneplus'= L4 UDP reqs; 'udp_resp_oneplus'= L4 UDP rsps; 'out_seq_ack_drop'= Out of sequence ACK drop; 'tcp_est'= L4 TCP Established; 'synattack'= L4 SYN attack; 'syn_rate'= TCP SYN rate per sec; 'syncookie_buff_drop'= TCP SYN cookie buff drop; 'syncookie_buff_queue'= TCP SYN cookie buff queue; 'skip_insert_client_ip'= Skip Insert-client-ip; 'synreceived_hw'= TCP SYN (HW SYN cookie); 'dns_id_switch'= DNS query id switch; 'server_down_del'= Server Down Del switch; 'dnssec_switch'= DNSSEC SG switch; 'rate_drop_reset_unkn'= Rate Drop reset; 'tcp_connections_closed'= TCP Connections Closed; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            conn_rate_limit_drop:
                description:
                - "Conn rate limit drops"
            outrst_stale_sess:
                description:
                - "TCP out RST stale sess"
            concurrent_conn_exceed:
                description:
                - "L3V Conn Limit Drop"
            tcp_sess_aged_out:
                description:
                - "TCP Session aged out"
            ignore_msl:
                description:
                - "ignore msl"
            no_vport_drop:
                description:
                - "vport not matching drops"
            snat_icmp_error_process:
                description:
                - "Source NAT ICMP Process"
            port_preserve_attempt:
                description:
                - "NAT Port Preserve Try"
            anomaly_pbslb_drop:
                description:
                - "Anomaly pbslb drop"
            proxy_nosock_drop:
                description:
                - "Proxy no sock drops"
            svr_syn_handshake_fail:
                description:
                - "L4 server handshake fail"
            snat_icmp_no_match:
                description:
                - "Source NAT ICMP No Match"
            drop_gslb:
                description:
                - "Drop GSLB"
            outrst_aflex:
                description:
                - "TCP out RST aFleX"
            anomaly_zero_win:
                description:
                - "Anomaly zero window"
            nosyn_drop_rst:
                description:
                - "No SYN pkt drops - RST"
            anomaly_bad_content:
                description:
                - "Anomaly bad content"
            bw_rate_limit_exceed:
                description:
                - "BW-Limit Exceed drop"
            tcp_fwd_last_ack:
                description:
                - "L4 rcv fwd last ACK"
            nosyn_drop_fin:
                description:
                - "No SYN pkt drops - FIN"
            anomaly_out_seq:
                description:
                - "Anomaly out of sequence"
            tcp_rev_ackfin:
                description:
                - "L4 rcv rev FIN|ACK"
            tcp_rev_fin:
                description:
                - "L4 rcv rev FIN"
            tcp_fwd_fin:
                description:
                - "L4 rcv fwd FIN"
            l2_dsr:
                description:
                - "L2 DSR received"
            bw_watermark_drop:
                description:
                - "BW-Watermark drop"
            reset_l7_on_failover:
                description:
                - "RST L7 on failover"
            tcp_invalid_drop:
                description:
                - "TCP invalid drop"
            syn_stale_sess:
                description:
                - "SYN stale sess drop"
            syncookie_buff_drop:
                description:
                - "TCP SYN cookie buff drop"
            inudp:
                description:
                - "UDP received"
            tcpotherflags_drop:
                description:
                - "TCP SYN Other Flags Drop"
            udp_sess_aged_out:
                description:
                - "UDP Session aged out"
            auto_reassign:
                description:
                - "Auto-reselect server"
            stateless_conn_timeout:
                description:
                - "L4 stateless Conn TO"
            fast_aging_set:
                description:
                - "Fast aging set"
            udp_req_oneplus_no_resp:
                description:
                - "L4 UDP reqs no rsp"
            connlimit_drop:
                description:
                - "Conn Limit drops"
            tcp_connections_closed:
                description:
                - "TCP Connections Closed"
            udp_req_one_oneplus_resp:
                description:
                - "L4 UDP req rsps"
            connlimit_reset:
                description:
                - "Conn Limit resets"
            ssl_cps_exceed:
                description:
                - "SSL CPS exceed drop"
            syncookiessentfailed:
                description:
                - "TCP SYN cookie snt fail"
            ssl_tpt_exceed:
                description:
                - "SSL TPT exceed drop"
            smart_nat_id_mismatch:
                description:
                - "Auto NAT id mismatch"
            tcp_fwd_ackfin:
                description:
                - "L4 rcv fwd FIN|ACK"
            ssl_watermark_drop:
                description:
                - "SSL TPT-Watermark drop"
            tcp_rexmit_synack_delq:
                description:
                - "L4 rcv rexmit SYN|ACK DQ"
            conn_rate_limit_reset:
                description:
                - "Conn rate limit resets"
            tcp_fwd_fin_dup:
                description:
                - "L4 rcv fwd FIN dup"
            other_sess_aged_out:
                description:
                - "Other Session aged out"
            tcp_rexmit_synack:
                description:
                - "L4 rcv rexmit SYN|ACK"
            skip_insert_client_ip:
                description:
                - "Skip Insert-client-ip"
            server_down_del:
                description:
                - "Server Down Del switch"
            l3_dsr:
                description:
                - "L3 DSR received"
            tcp_sess_noest_aged_out:
                description:
                - "TCP no-Est Sess aged out"
            syn_rate:
                description:
                - "TCP SYN rate per sec"
            l7_cps_exceed:
                description:
                - "L7 CPS exceed drop"
            outrst_ack_attack:
                description:
                - "TCP out RST ACK attack"
            synattack:
                description:
                - "L4 SYN attack"
            drop_aflex:
                description:
                - "aFleX drops"
            tcp_est:
                description:
                - "L4 TCP Established"
            svrselfail:
                description:
                - "Server sel failure"
            outrst_broker:
                description:
                - "TCP out RST L4 proxy"
            tcp_sess_noest_csyn_rcv_aged_out:
                description:
                - "no-Est CSYN rcv aged out"
            novport_drop:
                description:
                - "NAT no session drops"
            fast_aging_reset:
                description:
                - "Fast aging reset"
            syncookiessent:
                description:
                - "TCP SYN cookie snt"
            tcp_rexmit_syn:
                description:
                - "L4 rcv rexmit SYN"
            outrst:
                description:
                - "TCP out RST"
            tcp_ax_rexmit_syn:
                description:
                - "L4 AX re-xmit SYN"
            tcp_sess_noest_ssyn_xmit_aged_out:
                description:
                - "no-Est SSYN snt aged out"
            syncookie_buff_queue:
                description:
                - "TCP SYN cookie buff queue"
            sess_aged_out:
                description:
                - "Session aged out"
            throttle_syn:
                description:
                - "SYN Throttle"
            nosyn_drop:
                description:
                - "No SYN pkt drops"
            l4_cps_exceed:
                description:
                - "L4 CPS exceed drop"
            udp_req_resp_notmatch:
                description:
                - "L4 UDP req/rsp not match"
            snat_fail:
                description:
                - "Source NAT failure"
            no_resourse_drop:
                description:
                - "No resource drop"
            inband_hm_retry:
                description:
                - "Inband HM retry"
            synreceived:
                description:
                - "TCP SYN received"
            nat_cps_exceed:
                description:
                - "NAT CPS exceed drop"
            out_seq_ack_drop:
                description:
                - "Out of sequence ACK drop"
            outrst_nosyn:
                description:
                - "TCP out RST no SYN"
            udp_req_more_resp:
                description:
                - "L4 UDP req greater than rsps"
            dns_policy_drop:
                description:
                - "DNS Policy Drop"
            rate_drop_reset_unkn:
                description:
                - "Rate Drop reset"
            nosyn_drop_ack:
                description:
                - "No SYN pkt drops - ACK"
            snat_no_rev_route:
                description:
                - "Source NAT no rev route"
            tcp_fwd_rst:
                description:
                - "L4 rcv fwd RST"
            tcp_no_slb:
                description:
                - "TCP no SLB"
            reset_unknown_conn:
                description:
                - "Reset unknown conn"
            udp_resp_oneplus:
                description:
                - "L4 UDP rsps"
            outrst_tcpproxy:
                description:
                - "TCP out RST TCP proxy"
            snat_no_fwd_route:
                description:
                - "Source NAT no fwd route"
            tcp_rev_fin_dup:
                description:
                - "L4 rcv rev FIN dup"
            udp_no_slb:
                description:
                - "UDP no SLB"
            port_preserve_succ:
                description:
                - "NAT Port Preserve Succ"
            udp_resp_more_req:
                description:
                - "L4 UDP rsps greater than reqs"
            inband_hm_reassign:
                description:
                - "Inband HM reassign"
            tcpsyndata_drop:
                description:
                - "TCP SYN With Data Drop"
            syncookiescheckfailed:
                description:
                - "TCP SYN cookie failed"
            tcp_rexmit_syn_delq:
                description:
                - "L4 rcv rexmit SYN (delq)"
            tcp_syn_rcv_rst:
                description:
                - "L4 rcv RST on SYN"
            dns_id_switch:
                description:
                - "DNS query id switch"
            tcp_rev_last_ack:
                description:
                - "L4 rcv rev last ACK"
            tcp_rev_rst:
                description:
                - "L4 rcv rev RST"
            noroute:
                description:
                - "IP out noroute"
            udp_req_oneplus:
                description:
                - "L4 UDP reqs"
            dnssec_switch:
                description:
                - "DNSSEC SG switch"
            syncookiessent_ts:
                description:
                - "TCP SYN cookie snt ts"
            tcp_syn_rcv_ack:
                description:
                - "L4 rcv ACK on SYN"
            synreceived_hw:
                description:
                - "TCP SYN (HW SYN cookie)"
            intcp:
                description:
                - "TCP received"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["oper","sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', l4_cpu_list=dict(type='list', conn_rate_limit_drop=dict(type='int', ), connlimit_reset=dict(type='int', ), syncookies_buff_drop=dict(type='int', ), tcp_outrst_ack_attack=dict(type='int', ), tcp_sess_aged_out=dict(type='int', ), tcp_outrst_stale_sess=dict(type='int', ), ignore_msl=dict(type='int', ), no_vport_drop=dict(type='int', ), snat_icmp_error_process=dict(type='int', ), port_preserve_attempt=dict(type='int', ), rcv_fwd_last_ack=dict(type='int', ), anomaly_pbslb_drop=dict(type='int', ), tcp_synreceived_hw=dict(type='int', ), rcv_rexmit_synack_delq=dict(type='int', ), tcp_outrst_broker=dict(type='int', ), snat_icmp_no_match=dict(type='int', ), rcv_fwd_rst=dict(type='int', ), anomaly_zero_win=dict(type='int', ), tcp_syn_stale_sess=dict(type='int', ), other_sess_aged_out=dict(type='int', ), reset_l7_on_failover=dict(type='int', ), tcp_outrst_nosyn=dict(type='int', ), nosyn_drop_rst=dict(type='int', ), anomaly_bad_content=dict(type='int', ), ip_outnoroute=dict(type='int', ), no_resource_drop=dict(type='int', ), l4_cps_exceed_drop=dict(type='int', ), nosyn_drop_fin=dict(type='int', ), anomaly_out_seq=dict(type='int', ), conn_rate_limit_reset=dict(type='int', ), tcp_syn_otherflags=dict(type='int', ), out_seq_ack_drop=dict(type='int', ), rcv_rev_rst=dict(type='int', ), ssl_tpt_exceed_drop=dict(type='int', ), bw_watermark_drop=dict(type='int', ), rcv_rexmit_synack=dict(type='int', ), sess_aged_out=dict(type='int', ), tcp_invalid_drop=dict(type='int', ), rcv_rev_fin=dict(type='int', ), inudp=dict(type='int', ), udp_sess_aged_out=dict(type='int', ), rcv_rsps_morethan_reqs=dict(type='int', ), auto_reassign=dict(type='int', ), ax_rexmit_syn=dict(type='int', ), stateless_conn_timeout=dict(type='int', ), fast_aging_set=dict(type='int', ), rcv_rev_finack=dict(type='int', ), connlimit_drop=dict(type='int', ), tcp_connections_closed=dict(type='int', ), tcp_outrst_aflex=dict(type='int', ), conn_limit_exceed_drop=dict(type='int', ), tcp_synreceived=dict(type='int', ), tcp_syncookiessent_ts=dict(type='int', ), smart_nat_id_mismatch=dict(type='int', ), proxy_nosock_drop=dict(type='int', ), ssl_watermark_drop=dict(type='int', ), nat_cps_exceed_drop=dict(type='int', ), rcv_req_morethan_rsps=dict(type='int', ), rcv_rev_last_ack=dict(type='int', ), rcv_rexmit_syn_delq=dict(type='int', ), skip_insert_client_ip=dict(type='int', ), server_down_del=dict(type='int', ), l3_dsr=dict(type='int', ), rcv_fwd_fin=dict(type='int', ), noest_client_syn_aged_out=dict(type='int', ), tcp_syncookiescheckfailed=dict(type='int', ), rcv_rev_fin_dup=dict(type='int', ), synattack=dict(type='int', ), tcp_est=dict(type='int', ), rcv_rexmit_syn=dict(type='int', ), novport_drop=dict(type='int', ), l7_cps_exceed_drop=dict(type='int', ), fast_aging_reset=dict(type='int', ), aflex_drop=dict(type='int', ), syncookies_buff_queue=dict(type='int', ), rcv_ack_on_syn=dict(type='int', ), tcp_outrst=dict(type='int', ), tcp_noest_aged_out=dict(type='int', ), throttle_syn=dict(type='int', ), tcp_outrst_tcpproxy=dict(type='int', ), nosyn_drop=dict(type='int', ), snat_fail=dict(type='int', ), rcv_udp_rsps=dict(type='int', ), inband_hm_retry=dict(type='int', ), rcv_reqs_no_rsp=dict(type='int', ), bw_rate_limit_exceed_drop=dict(type='int', ), l2_dsr=dict(type='int', ), nosyn_drop_ack=dict(type='int', ), tcp_syn_rate=dict(type='int', ), l4_svr_handshake_fail=dict(type='int', ), rcv_udp_reqs=dict(type='int', ), snat_no_rev_route=dict(type='int', ), tcp_no_slb=dict(type='int', ), reset_unknown_conn=dict(type='int', ), rcv_fwd_finack=dict(type='int', ), udp_no_slb=dict(type='int', ), tcp_syn_withdata=dict(type='int', ), port_preserve_succ=dict(type='int', ), inband_hm_reassign=dict(type='int', ), ssl_cps_exceed_drop=dict(type='int', ), svr_sel_failed=dict(type='int', ), dns_id_switch=dict(type='int', ), noest_server_syn_xmit_aged_out=dict(type='int', ), tcp_syncookiessentfailed=dict(type='int', ), tcp_syncookiessent=dict(type='int', ), dnssec_switch=dict(type='int', ), snat_no_fwd_route=dict(type='int', ), rcv_req_rsps=dict(type='int', ), rcv_rst_on_syn=dict(type='int', ), intcp=dict(type='int', ), rcv_fwd_fin_dup=dict(type='int', ), rcv_req_not_match=dict(type='int', )), cpu_count=dict(type='int', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'intcp', 'synreceived', 'tcp_fwd_last_ack', 'tcp_rev_last_ack', 'tcp_rev_fin', 'tcp_fwd_fin', 'tcp_fwd_ackfin', 'inudp', 'syncookiessent', 'syncookiessent_ts', 'syncookiessentfailed', 'outrst', 'outrst_nosyn', 'outrst_broker', 'outrst_ack_attack', 'outrst_aflex', 'outrst_stale_sess', 'syn_stale_sess', 'outrst_tcpproxy', 'svrselfail', 'noroute', 'snat_fail', 'snat_no_fwd_route', 'snat_no_rev_route', 'snat_icmp_error_process', 'snat_icmp_no_match', 'smart_nat_id_mismatch', 'syncookiescheckfailed', 'novport_drop', 'no_vport_drop', 'nosyn_drop', 'nosyn_drop_fin', 'nosyn_drop_rst', 'nosyn_drop_ack', 'connlimit_drop', 'connlimit_reset', 'conn_rate_limit_drop', 'conn_rate_limit_reset', 'proxy_nosock_drop', 'drop_aflex', 'sess_aged_out', 'tcp_sess_aged_out', 'udp_sess_aged_out', 'other_sess_aged_out', 'tcp_no_slb', 'udp_no_slb', 'throttle_syn', 'drop_gslb', 'inband_hm_retry', 'inband_hm_reassign', 'auto_reassign', 'fast_aging_set', 'fast_aging_reset', 'dns_policy_drop', 'tcp_invalid_drop', 'anomaly_out_seq', 'anomaly_zero_win', 'anomaly_bad_content', 'anomaly_pbslb_drop', 'no_resourse_drop', 'reset_unknown_conn', 'reset_l7_on_failover', 'ignore_msl', 'l2_dsr', 'l3_dsr', 'port_preserve_attempt', 'port_preserve_succ', 'tcpsyndata_drop', 'tcpotherflags_drop', 'bw_rate_limit_exceed', 'bw_watermark_drop', 'l4_cps_exceed', 'nat_cps_exceed', 'l7_cps_exceed', 'ssl_cps_exceed', 'ssl_tpt_exceed', 'ssl_watermark_drop', 'concurrent_conn_exceed', 'svr_syn_handshake_fail', 'stateless_conn_timeout', 'tcp_ax_rexmit_syn', 'tcp_syn_rcv_ack', 'tcp_syn_rcv_rst', 'tcp_sess_noest_aged_out', 'tcp_sess_noest_csyn_rcv_aged_out', 'tcp_sess_noest_ssyn_xmit_aged_out', 'tcp_rexmit_syn', 'tcp_rexmit_syn_delq', 'tcp_rexmit_synack', 'tcp_rexmit_synack_delq', 'tcp_fwd_fin_dup', 'tcp_rev_fin_dup', 'tcp_rev_ackfin', 'tcp_fwd_rst', 'tcp_rev_rst', 'udp_req_oneplus_no_resp', 'udp_req_one_oneplus_resp', 'udp_req_resp_notmatch', 'udp_req_more_resp', 'udp_resp_more_req', 'udp_req_oneplus', 'udp_resp_oneplus', 'out_seq_ack_drop', 'tcp_est', 'synattack', 'syn_rate', 'syncookie_buff_drop', 'syncookie_buff_queue', 'skip_insert_client_ip', 'synreceived_hw', 'dns_id_switch', 'server_down_del', 'dnssec_switch', 'rate_drop_reset_unkn', 'tcp_connections_closed'])),
        stats=dict(type='dict', conn_rate_limit_drop=dict(type='str', ), outrst_stale_sess=dict(type='str', ), concurrent_conn_exceed=dict(type='str', ), tcp_sess_aged_out=dict(type='str', ), ignore_msl=dict(type='str', ), no_vport_drop=dict(type='str', ), snat_icmp_error_process=dict(type='str', ), port_preserve_attempt=dict(type='str', ), anomaly_pbslb_drop=dict(type='str', ), proxy_nosock_drop=dict(type='str', ), svr_syn_handshake_fail=dict(type='str', ), snat_icmp_no_match=dict(type='str', ), drop_gslb=dict(type='str', ), outrst_aflex=dict(type='str', ), anomaly_zero_win=dict(type='str', ), nosyn_drop_rst=dict(type='str', ), anomaly_bad_content=dict(type='str', ), bw_rate_limit_exceed=dict(type='str', ), tcp_fwd_last_ack=dict(type='str', ), nosyn_drop_fin=dict(type='str', ), anomaly_out_seq=dict(type='str', ), tcp_rev_ackfin=dict(type='str', ), tcp_rev_fin=dict(type='str', ), tcp_fwd_fin=dict(type='str', ), l2_dsr=dict(type='str', ), bw_watermark_drop=dict(type='str', ), reset_l7_on_failover=dict(type='str', ), tcp_invalid_drop=dict(type='str', ), syn_stale_sess=dict(type='str', ), syncookie_buff_drop=dict(type='str', ), inudp=dict(type='str', ), tcpotherflags_drop=dict(type='str', ), udp_sess_aged_out=dict(type='str', ), auto_reassign=dict(type='str', ), stateless_conn_timeout=dict(type='str', ), fast_aging_set=dict(type='str', ), udp_req_oneplus_no_resp=dict(type='str', ), connlimit_drop=dict(type='str', ), tcp_connections_closed=dict(type='str', ), udp_req_one_oneplus_resp=dict(type='str', ), connlimit_reset=dict(type='str', ), ssl_cps_exceed=dict(type='str', ), syncookiessentfailed=dict(type='str', ), ssl_tpt_exceed=dict(type='str', ), smart_nat_id_mismatch=dict(type='str', ), tcp_fwd_ackfin=dict(type='str', ), ssl_watermark_drop=dict(type='str', ), tcp_rexmit_synack_delq=dict(type='str', ), conn_rate_limit_reset=dict(type='str', ), tcp_fwd_fin_dup=dict(type='str', ), other_sess_aged_out=dict(type='str', ), tcp_rexmit_synack=dict(type='str', ), skip_insert_client_ip=dict(type='str', ), server_down_del=dict(type='str', ), l3_dsr=dict(type='str', ), tcp_sess_noest_aged_out=dict(type='str', ), syn_rate=dict(type='str', ), l7_cps_exceed=dict(type='str', ), outrst_ack_attack=dict(type='str', ), synattack=dict(type='str', ), drop_aflex=dict(type='str', ), tcp_est=dict(type='str', ), svrselfail=dict(type='str', ), outrst_broker=dict(type='str', ), tcp_sess_noest_csyn_rcv_aged_out=dict(type='str', ), novport_drop=dict(type='str', ), fast_aging_reset=dict(type='str', ), syncookiessent=dict(type='str', ), tcp_rexmit_syn=dict(type='str', ), outrst=dict(type='str', ), tcp_ax_rexmit_syn=dict(type='str', ), tcp_sess_noest_ssyn_xmit_aged_out=dict(type='str', ), syncookie_buff_queue=dict(type='str', ), sess_aged_out=dict(type='str', ), throttle_syn=dict(type='str', ), nosyn_drop=dict(type='str', ), l4_cps_exceed=dict(type='str', ), udp_req_resp_notmatch=dict(type='str', ), snat_fail=dict(type='str', ), no_resourse_drop=dict(type='str', ), inband_hm_retry=dict(type='str', ), synreceived=dict(type='str', ), nat_cps_exceed=dict(type='str', ), out_seq_ack_drop=dict(type='str', ), outrst_nosyn=dict(type='str', ), udp_req_more_resp=dict(type='str', ), dns_policy_drop=dict(type='str', ), rate_drop_reset_unkn=dict(type='str', ), nosyn_drop_ack=dict(type='str', ), snat_no_rev_route=dict(type='str', ), tcp_fwd_rst=dict(type='str', ), tcp_no_slb=dict(type='str', ), reset_unknown_conn=dict(type='str', ), udp_resp_oneplus=dict(type='str', ), outrst_tcpproxy=dict(type='str', ), snat_no_fwd_route=dict(type='str', ), tcp_rev_fin_dup=dict(type='str', ), udp_no_slb=dict(type='str', ), port_preserve_succ=dict(type='str', ), udp_resp_more_req=dict(type='str', ), inband_hm_reassign=dict(type='str', ), tcpsyndata_drop=dict(type='str', ), syncookiescheckfailed=dict(type='str', ), tcp_rexmit_syn_delq=dict(type='str', ), tcp_syn_rcv_rst=dict(type='str', ), dns_id_switch=dict(type='str', ), tcp_rev_last_ack=dict(type='str', ), tcp_rev_rst=dict(type='str', ), noroute=dict(type='str', ), udp_req_oneplus=dict(type='str', ), dnssec_switch=dict(type='str', ), syncookiessent_ts=dict(type='str', ), tcp_syn_rcv_ack=dict(type='str', ), synreceived_hw=dict(type='str', ), intcp=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/l4"

    f_dict = {}

    return url_base.format(**f_dict)

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["l4"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

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