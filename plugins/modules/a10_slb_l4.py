#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_l4
description:
    - Configure L4
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'intcp'= TCP received; 'synreceived'= TCP SYN received;
          'tcp_fwd_last_ack'= L4 rcv fwd last ACK; 'tcp_rev_last_ack'= L4 rcv rev last
          ACK; 'tcp_rev_fin'= L4 rcv rev FIN; 'tcp_fwd_fin'= L4 rcv fwd FIN;
          'tcp_fwd_ackfin'= L4 rcv fwd FIN|ACK; 'inudp'= UDP received; 'syncookiessent'=
          TCP SYN cookie snt; 'syncookiessent_ts'= TCP SYN cookie snt ts;
          'syncookiessentfailed'= TCP SYN cookie snt fail; 'outrst'= TCP out RST;
          'outrst_nosyn'= TCP out RST no SYN; 'outrst_broker'= TCP out RST L4 proxy;
          'outrst_ack_attack'= TCP out RST ACK attack; 'outrst_aflex'= TCP out RST aFleX;
          'outrst_stale_sess'= TCP out RST stale sess; 'syn_stale_sess'= SYN stale sess
          drop; 'outrst_tcpproxy'= TCP out RST TCP proxy; 'svrselfail'= Server sel
          failure; 'noroute'= IP out noroute; 'snat_fail'= Source NAT failure;
          'snat_no_fwd_route'= Source NAT no fwd route; 'snat_no_rev_route'= Source NAT
          no rev route; 'snat_icmp_error_process'= Source NAT ICMP Process;
          'snat_icmp_no_match'= Source NAT ICMP No Match; 'smart_nat_id_mismatch'= Auto
          NAT id mismatch; 'syncookiescheckfailed'= TCP SYN cookie failed;
          'novport_drop'= NAT no session drops; 'no_vport_drop'= vport not matching
          drops; 'nosyn_drop'= No SYN pkt drops; 'nosyn_drop_fin'= No SYN pkt drops -
          FIN; 'nosyn_drop_rst'= No SYN pkt drops - RST; 'nosyn_drop_ack'= No SYN pkt
          drops - ACK; 'connlimit_drop'= Conn Limit drops; 'connlimit_reset'= Conn Limit
          resets; 'conn_rate_limit_drop'= Conn rate limit drops; 'conn_rate_limit_reset'=
          Conn rate limit resets; 'proxy_nosock_drop'= Proxy no sock drops; 'drop_aflex'=
          aFleX drops; 'sess_aged_out'= Session aged out; 'tcp_sess_aged_out'= TCP
          Session aged out; 'udp_sess_aged_out'= UDP Session aged out;
          'other_sess_aged_out'= Other Session aged out; 'tcp_no_slb'= TCP no SLB;
          'udp_no_slb'= UDP no SLB; 'throttle_syn'= SYN Throttle; 'drop_gslb'= Drop GSLB;
          'inband_hm_retry'= Inband HM retry; 'inband_hm_reassign'= Inband HM reassign;
          'auto_reassign'= Auto-reselect server; 'fast_aging_set'= Fast aging set;
          'fast_aging_reset'= Fast aging reset; 'dns_policy_drop'= DNS Policy Drop;
          'tcp_invalid_drop'= TCP invalid drop; 'anomaly_out_seq'= Anomaly out of
          sequence; 'anomaly_zero_win'= Anomaly zero window; 'anomaly_bad_content'=
          Anomaly bad content; 'anomaly_pbslb_drop'= Anomaly pbslb drop;
          'no_resourse_drop'= No resource drop; 'reset_unknown_conn'= Reset unknown conn;
          'reset_l7_on_failover'= RST L7 on failover; 'ignore_msl'= ignore msl; 'l2_dsr'=
          L2 DSR received; 'l3_dsr'= L3 DSR received; 'port_preserve_attempt'= NAT Port
          Preserve Try; 'port_preserve_succ'= NAT Port Preserve Succ; 'tcpsyndata_drop'=
          TCP SYN With Data Drop; 'tcpotherflags_drop'= TCP SYN Other Flags Drop;
          'bw_rate_limit_exceed'= BW-Limit Exceed drop; 'bw_watermark_drop'= BW-Watermark
          drop; 'l4_cps_exceed'= L4 CPS exceed drop; 'nat_cps_exceed'= NAT CPS exceed
          drop; 'l7_cps_exceed'= L7 CPS exceed drop; 'ssl_cps_exceed'= SSL CPS exceed
          drop; 'ssl_tpt_exceed'= SSL TPT exceed drop; 'ssl_watermark_drop'= SSL TPT-
          Watermark drop; 'concurrent_conn_exceed'= L3V Conn Limit Drop;
          'svr_syn_handshake_fail'= L4 server handshake fail; 'stateless_conn_timeout'=
          L4 stateless Conn TO; 'tcp_ax_rexmit_syn'= L4 AX re-xmit SYN;
          'tcp_syn_rcv_ack'= L4 rcv ACK on SYN; 'tcp_syn_rcv_rst'= L4 rcv RST on SYN;
          'tcp_sess_noest_aged_out'= TCP no-Est Sess aged out;
          'tcp_sess_noest_csyn_rcv_aged_out'= no-Est CSYN rcv aged out;
          'tcp_sess_noest_ssyn_xmit_aged_out'= no-Est SSYN snt aged out;
          'tcp_rexmit_syn'= L4 rcv rexmit SYN; 'tcp_rexmit_syn_delq'= L4 rcv rexmit SYN
          (delq); 'tcp_rexmit_synack'= L4 rcv rexmit SYN|ACK; 'tcp_rexmit_synack_delq'=
          L4 rcv rexmit SYN|ACK DQ; 'tcp_fwd_fin_dup'= L4 rcv fwd FIN dup;
          'tcp_rev_fin_dup'= L4 rcv rev FIN dup; 'tcp_rev_ackfin'= L4 rcv rev FIN|ACK;
          'tcp_fwd_rst'= L4 rcv fwd RST; 'tcp_rev_rst'= L4 rcv rev RST;
          'udp_req_oneplus_no_resp'= L4 UDP reqs no rsp; 'udp_req_one_oneplus_resp'= L4
          UDP req rsps; 'udp_req_resp_notmatch'= L4 UDP req/rsp not match;
          'udp_req_more_resp'= L4 UDP req greater than rsps; 'udp_resp_more_req'= L4 UDP
          rsps greater than reqs; 'udp_req_oneplus'= L4 UDP reqs; 'udp_resp_oneplus'= L4
          UDP rsps; 'out_seq_ack_drop'= Out of sequence ACK drop; 'tcp_est'= L4 TCP
          Established; 'synattack'= L4 SYN attack; 'syn_rate'= TCP SYN rate per sec;
          'syncookie_buff_drop'= TCP SYN cookie buff drop; 'syncookie_buff_queue'= TCP
          SYN cookie buff queue; 'skip_insert_client_ip'= Skip Insert-client-ip;
          'synreceived_hw'= TCP SYN (HW SYN cookie); 'dns_id_switch'= DNS query id
          switch; 'server_down_del'= Server Down Del switch; 'dnssec_switch'= DNSSEC SG
          switch; 'rate_drop_reset_unkn'= Rate Drop reset; 'tcp_connections_closed'= TCP
          Connections Closed; 'snat_force_preserve_alloc'= Snat port preserve allocated;
          'snat_force_preserve_free'= Snat port preserve freed;
          'snat_port_overload_fail'= Snat port overload fail;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            intcp:
                description:
                - "TCP received"
                type: str
            synreceived:
                description:
                - "TCP SYN received"
                type: str
            tcp_fwd_last_ack:
                description:
                - "L4 rcv fwd last ACK"
                type: str
            tcp_rev_last_ack:
                description:
                - "L4 rcv rev last ACK"
                type: str
            tcp_rev_fin:
                description:
                - "L4 rcv rev FIN"
                type: str
            tcp_fwd_fin:
                description:
                - "L4 rcv fwd FIN"
                type: str
            tcp_fwd_ackfin:
                description:
                - "L4 rcv fwd FIN|ACK"
                type: str
            inudp:
                description:
                - "UDP received"
                type: str
            syncookiessent:
                description:
                - "TCP SYN cookie snt"
                type: str
            syncookiessent_ts:
                description:
                - "TCP SYN cookie snt ts"
                type: str
            syncookiessentfailed:
                description:
                - "TCP SYN cookie snt fail"
                type: str
            outrst:
                description:
                - "TCP out RST"
                type: str
            outrst_nosyn:
                description:
                - "TCP out RST no SYN"
                type: str
            outrst_broker:
                description:
                - "TCP out RST L4 proxy"
                type: str
            outrst_ack_attack:
                description:
                - "TCP out RST ACK attack"
                type: str
            outrst_aflex:
                description:
                - "TCP out RST aFleX"
                type: str
            outrst_stale_sess:
                description:
                - "TCP out RST stale sess"
                type: str
            syn_stale_sess:
                description:
                - "SYN stale sess drop"
                type: str
            outrst_tcpproxy:
                description:
                - "TCP out RST TCP proxy"
                type: str
            svrselfail:
                description:
                - "Server sel failure"
                type: str
            noroute:
                description:
                - "IP out noroute"
                type: str
            snat_fail:
                description:
                - "Source NAT failure"
                type: str
            snat_no_fwd_route:
                description:
                - "Source NAT no fwd route"
                type: str
            snat_no_rev_route:
                description:
                - "Source NAT no rev route"
                type: str
            snat_icmp_error_process:
                description:
                - "Source NAT ICMP Process"
                type: str
            snat_icmp_no_match:
                description:
                - "Source NAT ICMP No Match"
                type: str
            smart_nat_id_mismatch:
                description:
                - "Auto NAT id mismatch"
                type: str
            syncookiescheckfailed:
                description:
                - "TCP SYN cookie failed"
                type: str
            novport_drop:
                description:
                - "NAT no session drops"
                type: str
            no_vport_drop:
                description:
                - "vport not matching drops"
                type: str
            nosyn_drop:
                description:
                - "No SYN pkt drops"
                type: str
            nosyn_drop_fin:
                description:
                - "No SYN pkt drops - FIN"
                type: str
            nosyn_drop_rst:
                description:
                - "No SYN pkt drops - RST"
                type: str
            nosyn_drop_ack:
                description:
                - "No SYN pkt drops - ACK"
                type: str
            connlimit_drop:
                description:
                - "Conn Limit drops"
                type: str
            connlimit_reset:
                description:
                - "Conn Limit resets"
                type: str
            conn_rate_limit_drop:
                description:
                - "Conn rate limit drops"
                type: str
            conn_rate_limit_reset:
                description:
                - "Conn rate limit resets"
                type: str
            proxy_nosock_drop:
                description:
                - "Proxy no sock drops"
                type: str
            drop_aflex:
                description:
                - "aFleX drops"
                type: str
            sess_aged_out:
                description:
                - "Session aged out"
                type: str
            tcp_sess_aged_out:
                description:
                - "TCP Session aged out"
                type: str
            udp_sess_aged_out:
                description:
                - "UDP Session aged out"
                type: str
            other_sess_aged_out:
                description:
                - "Other Session aged out"
                type: str
            tcp_no_slb:
                description:
                - "TCP no SLB"
                type: str
            udp_no_slb:
                description:
                - "UDP no SLB"
                type: str
            throttle_syn:
                description:
                - "SYN Throttle"
                type: str
            drop_gslb:
                description:
                - "Drop GSLB"
                type: str
            inband_hm_retry:
                description:
                - "Inband HM retry"
                type: str
            inband_hm_reassign:
                description:
                - "Inband HM reassign"
                type: str
            auto_reassign:
                description:
                - "Auto-reselect server"
                type: str
            fast_aging_set:
                description:
                - "Fast aging set"
                type: str
            fast_aging_reset:
                description:
                - "Fast aging reset"
                type: str
            dns_policy_drop:
                description:
                - "DNS Policy Drop"
                type: str
            tcp_invalid_drop:
                description:
                - "TCP invalid drop"
                type: str
            anomaly_out_seq:
                description:
                - "Anomaly out of sequence"
                type: str
            anomaly_zero_win:
                description:
                - "Anomaly zero window"
                type: str
            anomaly_bad_content:
                description:
                - "Anomaly bad content"
                type: str
            anomaly_pbslb_drop:
                description:
                - "Anomaly pbslb drop"
                type: str
            no_resourse_drop:
                description:
                - "No resource drop"
                type: str
            reset_unknown_conn:
                description:
                - "Reset unknown conn"
                type: str
            reset_l7_on_failover:
                description:
                - "RST L7 on failover"
                type: str
            ignore_msl:
                description:
                - "ignore msl"
                type: str
            l2_dsr:
                description:
                - "L2 DSR received"
                type: str
            l3_dsr:
                description:
                - "L3 DSR received"
                type: str
            port_preserve_attempt:
                description:
                - "NAT Port Preserve Try"
                type: str
            port_preserve_succ:
                description:
                - "NAT Port Preserve Succ"
                type: str
            tcpsyndata_drop:
                description:
                - "TCP SYN With Data Drop"
                type: str
            tcpotherflags_drop:
                description:
                - "TCP SYN Other Flags Drop"
                type: str
            bw_rate_limit_exceed:
                description:
                - "BW-Limit Exceed drop"
                type: str
            bw_watermark_drop:
                description:
                - "BW-Watermark drop"
                type: str
            l4_cps_exceed:
                description:
                - "L4 CPS exceed drop"
                type: str
            nat_cps_exceed:
                description:
                - "NAT CPS exceed drop"
                type: str
            l7_cps_exceed:
                description:
                - "L7 CPS exceed drop"
                type: str
            ssl_cps_exceed:
                description:
                - "SSL CPS exceed drop"
                type: str
            ssl_tpt_exceed:
                description:
                - "SSL TPT exceed drop"
                type: str
            ssl_watermark_drop:
                description:
                - "SSL TPT-Watermark drop"
                type: str
            concurrent_conn_exceed:
                description:
                - "L3V Conn Limit Drop"
                type: str
            svr_syn_handshake_fail:
                description:
                - "L4 server handshake fail"
                type: str
            stateless_conn_timeout:
                description:
                - "L4 stateless Conn TO"
                type: str
            tcp_ax_rexmit_syn:
                description:
                - "L4 AX re-xmit SYN"
                type: str
            tcp_syn_rcv_ack:
                description:
                - "L4 rcv ACK on SYN"
                type: str
            tcp_syn_rcv_rst:
                description:
                - "L4 rcv RST on SYN"
                type: str
            tcp_sess_noest_aged_out:
                description:
                - "TCP no-Est Sess aged out"
                type: str
            tcp_sess_noest_csyn_rcv_aged_out:
                description:
                - "no-Est CSYN rcv aged out"
                type: str
            tcp_sess_noest_ssyn_xmit_aged_out:
                description:
                - "no-Est SSYN snt aged out"
                type: str
            tcp_rexmit_syn:
                description:
                - "L4 rcv rexmit SYN"
                type: str
            tcp_rexmit_syn_delq:
                description:
                - "L4 rcv rexmit SYN (delq)"
                type: str
            tcp_rexmit_synack:
                description:
                - "L4 rcv rexmit SYN|ACK"
                type: str
            tcp_rexmit_synack_delq:
                description:
                - "L4 rcv rexmit SYN|ACK DQ"
                type: str
            tcp_fwd_fin_dup:
                description:
                - "L4 rcv fwd FIN dup"
                type: str
            tcp_rev_fin_dup:
                description:
                - "L4 rcv rev FIN dup"
                type: str
            tcp_rev_ackfin:
                description:
                - "L4 rcv rev FIN|ACK"
                type: str
            tcp_fwd_rst:
                description:
                - "L4 rcv fwd RST"
                type: str
            tcp_rev_rst:
                description:
                - "L4 rcv rev RST"
                type: str
            udp_req_oneplus_no_resp:
                description:
                - "L4 UDP reqs no rsp"
                type: str
            udp_req_one_oneplus_resp:
                description:
                - "L4 UDP req rsps"
                type: str
            udp_req_resp_notmatch:
                description:
                - "L4 UDP req/rsp not match"
                type: str
            udp_req_more_resp:
                description:
                - "L4 UDP req greater than rsps"
                type: str
            udp_resp_more_req:
                description:
                - "L4 UDP rsps greater than reqs"
                type: str
            udp_req_oneplus:
                description:
                - "L4 UDP reqs"
                type: str
            udp_resp_oneplus:
                description:
                - "L4 UDP rsps"
                type: str
            out_seq_ack_drop:
                description:
                - "Out of sequence ACK drop"
                type: str
            tcp_est:
                description:
                - "L4 TCP Established"
                type: str
            synattack:
                description:
                - "L4 SYN attack"
                type: str
            syn_rate:
                description:
                - "TCP SYN rate per sec"
                type: str
            syncookie_buff_drop:
                description:
                - "TCP SYN cookie buff drop"
                type: str
            syncookie_buff_queue:
                description:
                - "TCP SYN cookie buff queue"
                type: str
            skip_insert_client_ip:
                description:
                - "Skip Insert-client-ip"
                type: str
            synreceived_hw:
                description:
                - "TCP SYN (HW SYN cookie)"
                type: str
            dns_id_switch:
                description:
                - "DNS query id switch"
                type: str
            server_down_del:
                description:
                - "Server Down Del switch"
                type: str
            dnssec_switch:
                description:
                - "DNSSEC SG switch"
                type: str
            rate_drop_reset_unkn:
                description:
                - "Rate Drop reset"
                type: str
            tcp_connections_closed:
                description:
                - "TCP Connections Closed"
                type: str
            snat_force_preserve_alloc:
                description:
                - "Snat port preserve allocated"
                type: str
            snat_force_preserve_free:
                description:
                - "Snat port preserve freed"
                type: str
            snat_port_overload_fail:
                description:
                - "Snat port overload fail"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "sampling_enable",
    "stats",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'intcp', 'synreceived', 'tcp_fwd_last_ack',
                    'tcp_rev_last_ack', 'tcp_rev_fin', 'tcp_fwd_fin',
                    'tcp_fwd_ackfin', 'inudp', 'syncookiessent',
                    'syncookiessent_ts', 'syncookiessentfailed', 'outrst',
                    'outrst_nosyn', 'outrst_broker', 'outrst_ack_attack',
                    'outrst_aflex', 'outrst_stale_sess', 'syn_stale_sess',
                    'outrst_tcpproxy', 'svrselfail', 'noroute', 'snat_fail',
                    'snat_no_fwd_route', 'snat_no_rev_route',
                    'snat_icmp_error_process', 'snat_icmp_no_match',
                    'smart_nat_id_mismatch', 'syncookiescheckfailed',
                    'novport_drop', 'no_vport_drop', 'nosyn_drop',
                    'nosyn_drop_fin', 'nosyn_drop_rst', 'nosyn_drop_ack',
                    'connlimit_drop', 'connlimit_reset',
                    'conn_rate_limit_drop', 'conn_rate_limit_reset',
                    'proxy_nosock_drop', 'drop_aflex', 'sess_aged_out',
                    'tcp_sess_aged_out', 'udp_sess_aged_out',
                    'other_sess_aged_out', 'tcp_no_slb', 'udp_no_slb',
                    'throttle_syn', 'drop_gslb', 'inband_hm_retry',
                    'inband_hm_reassign', 'auto_reassign', 'fast_aging_set',
                    'fast_aging_reset', 'dns_policy_drop', 'tcp_invalid_drop',
                    'anomaly_out_seq', 'anomaly_zero_win',
                    'anomaly_bad_content', 'anomaly_pbslb_drop',
                    'no_resourse_drop', 'reset_unknown_conn',
                    'reset_l7_on_failover', 'ignore_msl', 'l2_dsr', 'l3_dsr',
                    'port_preserve_attempt', 'port_preserve_succ',
                    'tcpsyndata_drop', 'tcpotherflags_drop',
                    'bw_rate_limit_exceed', 'bw_watermark_drop',
                    'l4_cps_exceed', 'nat_cps_exceed', 'l7_cps_exceed',
                    'ssl_cps_exceed', 'ssl_tpt_exceed', 'ssl_watermark_drop',
                    'concurrent_conn_exceed', 'svr_syn_handshake_fail',
                    'stateless_conn_timeout', 'tcp_ax_rexmit_syn',
                    'tcp_syn_rcv_ack', 'tcp_syn_rcv_rst',
                    'tcp_sess_noest_aged_out',
                    'tcp_sess_noest_csyn_rcv_aged_out',
                    'tcp_sess_noest_ssyn_xmit_aged_out', 'tcp_rexmit_syn',
                    'tcp_rexmit_syn_delq', 'tcp_rexmit_synack',
                    'tcp_rexmit_synack_delq', 'tcp_fwd_fin_dup',
                    'tcp_rev_fin_dup', 'tcp_rev_ackfin', 'tcp_fwd_rst',
                    'tcp_rev_rst', 'udp_req_oneplus_no_resp',
                    'udp_req_one_oneplus_resp', 'udp_req_resp_notmatch',
                    'udp_req_more_resp', 'udp_resp_more_req',
                    'udp_req_oneplus', 'udp_resp_oneplus', 'out_seq_ack_drop',
                    'tcp_est', 'synattack', 'syn_rate', 'syncookie_buff_drop',
                    'syncookie_buff_queue', 'skip_insert_client_ip',
                    'synreceived_hw', 'dns_id_switch', 'server_down_del',
                    'dnssec_switch', 'rate_drop_reset_unkn',
                    'tcp_connections_closed', 'snat_force_preserve_alloc',
                    'snat_force_preserve_free', 'snat_port_overload_fail'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'ip_outnoroute': {
                    'type': 'int',
                },
                'tcp_outrst': {
                    'type': 'int',
                },
                'tcp_outrst_nosyn': {
                    'type': 'int',
                },
                'tcp_outrst_broker': {
                    'type': 'int',
                },
                'tcp_outrst_ack_attack': {
                    'type': 'int',
                },
                'tcp_outrst_aflex': {
                    'type': 'int',
                },
                'tcp_outrst_stale_sess': {
                    'type': 'int',
                },
                'tcp_syn_stale_sess': {
                    'type': 'int',
                },
                'tcp_outrst_tcpproxy': {
                    'type': 'int',
                },
                'tcp_synreceived': {
                    'type': 'int',
                },
                'tcp_synreceived_hw': {
                    'type': 'int',
                },
                'tcp_syn_rate': {
                    'type': 'int',
                },
                'tcp_syncookiessent': {
                    'type': 'int',
                },
                'tcp_syncookiessent_ts': {
                    'type': 'int',
                },
                'tcp_syncookiessentfailed': {
                    'type': 'int',
                },
                'intcp': {
                    'type': 'int',
                },
                'inudp': {
                    'type': 'int',
                },
                'svr_sel_failed': {
                    'type': 'int',
                },
                'snat_fail': {
                    'type': 'int',
                },
                'snat_no_fwd_route': {
                    'type': 'int',
                },
                'snat_no_rev_route': {
                    'type': 'int',
                },
                'snat_icmp_error_process': {
                    'type': 'int',
                },
                'snat_icmp_no_match': {
                    'type': 'int',
                },
                'smart_nat_id_mismatch': {
                    'type': 'int',
                },
                'tcp_syncookiescheckfailed': {
                    'type': 'int',
                },
                'novport_drop': {
                    'type': 'int',
                },
                'no_vport_drop': {
                    'type': 'int',
                },
                'nosyn_drop': {
                    'type': 'int',
                },
                'nosyn_drop_fin': {
                    'type': 'int',
                },
                'nosyn_drop_rst': {
                    'type': 'int',
                },
                'nosyn_drop_ack': {
                    'type': 'int',
                },
                'connlimit_drop': {
                    'type': 'int',
                },
                'connlimit_reset': {
                    'type': 'int',
                },
                'conn_rate_limit_drop': {
                    'type': 'int',
                },
                'conn_rate_limit_reset': {
                    'type': 'int',
                },
                'proxy_nosock_drop': {
                    'type': 'int',
                },
                'aflex_drop': {
                    'type': 'int',
                },
                'sess_aged_out': {
                    'type': 'int',
                },
                'tcp_sess_aged_out': {
                    'type': 'int',
                },
                'udp_sess_aged_out': {
                    'type': 'int',
                },
                'other_sess_aged_out': {
                    'type': 'int',
                },
                'tcp_no_slb': {
                    'type': 'int',
                },
                'udp_no_slb': {
                    'type': 'int',
                },
                'throttle_syn': {
                    'type': 'int',
                },
                'inband_hm_retry': {
                    'type': 'int',
                },
                'inband_hm_reassign': {
                    'type': 'int',
                },
                'auto_reassign': {
                    'type': 'int',
                },
                'fast_aging_set': {
                    'type': 'int',
                },
                'fast_aging_reset': {
                    'type': 'int',
                },
                'tcp_invalid_drop': {
                    'type': 'int',
                },
                'out_seq_ack_drop': {
                    'type': 'int',
                },
                'anomaly_out_seq': {
                    'type': 'int',
                },
                'anomaly_zero_win': {
                    'type': 'int',
                },
                'anomaly_bad_content': {
                    'type': 'int',
                },
                'anomaly_pbslb_drop': {
                    'type': 'int',
                },
                'no_resource_drop': {
                    'type': 'int',
                },
                'reset_unknown_conn': {
                    'type': 'int',
                },
                'reset_l7_on_failover': {
                    'type': 'int',
                },
                'tcp_syn_otherflags': {
                    'type': 'int',
                },
                'tcp_syn_withdata': {
                    'type': 'int',
                },
                'ignore_msl': {
                    'type': 'int',
                },
                'l2_dsr': {
                    'type': 'int',
                },
                'l3_dsr': {
                    'type': 'int',
                },
                'port_preserve_attempt': {
                    'type': 'int',
                },
                'port_preserve_succ': {
                    'type': 'int',
                },
                'bw_rate_limit_exceed_drop': {
                    'type': 'int',
                },
                'bw_watermark_drop': {
                    'type': 'int',
                },
                'l4_cps_exceed_drop': {
                    'type': 'int',
                },
                'nat_cps_exceed_drop': {
                    'type': 'int',
                },
                'l7_cps_exceed_drop': {
                    'type': 'int',
                },
                'ssl_cps_exceed_drop': {
                    'type': 'int',
                },
                'ssl_tpt_exceed_drop': {
                    'type': 'int',
                },
                'ssl_watermark_drop': {
                    'type': 'int',
                },
                'conn_limit_exceed_drop': {
                    'type': 'int',
                },
                'l4_svr_handshake_fail': {
                    'type': 'int',
                },
                'stateless_conn_timeout': {
                    'type': 'int',
                },
                'ax_rexmit_syn': {
                    'type': 'int',
                },
                'rcv_ack_on_syn': {
                    'type': 'int',
                },
                'rcv_rst_on_syn': {
                    'type': 'int',
                },
                'tcp_noest_aged_out': {
                    'type': 'int',
                },
                'noest_client_syn_aged_out': {
                    'type': 'int',
                },
                'noest_server_syn_xmit_aged_out': {
                    'type': 'int',
                },
                'rcv_rexmit_syn': {
                    'type': 'int',
                },
                'rcv_rexmit_syn_delq': {
                    'type': 'int',
                },
                'rcv_rexmit_synack': {
                    'type': 'int',
                },
                'rcv_rexmit_synack_delq': {
                    'type': 'int',
                },
                'rcv_fwd_last_ack': {
                    'type': 'int',
                },
                'rcv_rev_last_ack': {
                    'type': 'int',
                },
                'rcv_fwd_fin': {
                    'type': 'int',
                },
                'rcv_fwd_fin_dup': {
                    'type': 'int',
                },
                'rcv_fwd_finack': {
                    'type': 'int',
                },
                'rcv_rev_fin': {
                    'type': 'int',
                },
                'rcv_rev_fin_dup': {
                    'type': 'int',
                },
                'rcv_rev_finack': {
                    'type': 'int',
                },
                'rcv_fwd_rst': {
                    'type': 'int',
                },
                'rcv_rev_rst': {
                    'type': 'int',
                },
                'rcv_reqs_no_rsp': {
                    'type': 'int',
                },
                'rcv_req_rsps': {
                    'type': 'int',
                },
                'rcv_req_not_match': {
                    'type': 'int',
                },
                'rcv_req_morethan_rsps': {
                    'type': 'int',
                },
                'rcv_rsps_morethan_reqs': {
                    'type': 'int',
                },
                'rcv_udp_reqs': {
                    'type': 'int',
                },
                'rcv_udp_rsps': {
                    'type': 'int',
                },
                'tcp_est': {
                    'type': 'int',
                },
                'synattack': {
                    'type': 'int',
                },
                'skip_insert_client_ip': {
                    'type': 'int',
                },
                'dns_id_switch': {
                    'type': 'int',
                },
                'dnssec_switch': {
                    'type': 'int',
                },
                'syncookies_buff_queue': {
                    'type': 'int',
                },
                'syncookies_buff_drop': {
                    'type': 'int',
                },
                'server_down_del': {
                    'type': 'int',
                },
                'tcp_connections_closed': {
                    'type': 'int',
                },
                'snat_force_preserve_alloc': {
                    'type': 'int',
                },
                'snat_force_preserve_free': {
                    'type': 'int',
                },
                'snat_port_overload_fail': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'intcp': {
                'type': 'str',
            },
            'synreceived': {
                'type': 'str',
            },
            'tcp_fwd_last_ack': {
                'type': 'str',
            },
            'tcp_rev_last_ack': {
                'type': 'str',
            },
            'tcp_rev_fin': {
                'type': 'str',
            },
            'tcp_fwd_fin': {
                'type': 'str',
            },
            'tcp_fwd_ackfin': {
                'type': 'str',
            },
            'inudp': {
                'type': 'str',
            },
            'syncookiessent': {
                'type': 'str',
            },
            'syncookiessent_ts': {
                'type': 'str',
            },
            'syncookiessentfailed': {
                'type': 'str',
            },
            'outrst': {
                'type': 'str',
            },
            'outrst_nosyn': {
                'type': 'str',
            },
            'outrst_broker': {
                'type': 'str',
            },
            'outrst_ack_attack': {
                'type': 'str',
            },
            'outrst_aflex': {
                'type': 'str',
            },
            'outrst_stale_sess': {
                'type': 'str',
            },
            'syn_stale_sess': {
                'type': 'str',
            },
            'outrst_tcpproxy': {
                'type': 'str',
            },
            'svrselfail': {
                'type': 'str',
            },
            'noroute': {
                'type': 'str',
            },
            'snat_fail': {
                'type': 'str',
            },
            'snat_no_fwd_route': {
                'type': 'str',
            },
            'snat_no_rev_route': {
                'type': 'str',
            },
            'snat_icmp_error_process': {
                'type': 'str',
            },
            'snat_icmp_no_match': {
                'type': 'str',
            },
            'smart_nat_id_mismatch': {
                'type': 'str',
            },
            'syncookiescheckfailed': {
                'type': 'str',
            },
            'novport_drop': {
                'type': 'str',
            },
            'no_vport_drop': {
                'type': 'str',
            },
            'nosyn_drop': {
                'type': 'str',
            },
            'nosyn_drop_fin': {
                'type': 'str',
            },
            'nosyn_drop_rst': {
                'type': 'str',
            },
            'nosyn_drop_ack': {
                'type': 'str',
            },
            'connlimit_drop': {
                'type': 'str',
            },
            'connlimit_reset': {
                'type': 'str',
            },
            'conn_rate_limit_drop': {
                'type': 'str',
            },
            'conn_rate_limit_reset': {
                'type': 'str',
            },
            'proxy_nosock_drop': {
                'type': 'str',
            },
            'drop_aflex': {
                'type': 'str',
            },
            'sess_aged_out': {
                'type': 'str',
            },
            'tcp_sess_aged_out': {
                'type': 'str',
            },
            'udp_sess_aged_out': {
                'type': 'str',
            },
            'other_sess_aged_out': {
                'type': 'str',
            },
            'tcp_no_slb': {
                'type': 'str',
            },
            'udp_no_slb': {
                'type': 'str',
            },
            'throttle_syn': {
                'type': 'str',
            },
            'drop_gslb': {
                'type': 'str',
            },
            'inband_hm_retry': {
                'type': 'str',
            },
            'inband_hm_reassign': {
                'type': 'str',
            },
            'auto_reassign': {
                'type': 'str',
            },
            'fast_aging_set': {
                'type': 'str',
            },
            'fast_aging_reset': {
                'type': 'str',
            },
            'dns_policy_drop': {
                'type': 'str',
            },
            'tcp_invalid_drop': {
                'type': 'str',
            },
            'anomaly_out_seq': {
                'type': 'str',
            },
            'anomaly_zero_win': {
                'type': 'str',
            },
            'anomaly_bad_content': {
                'type': 'str',
            },
            'anomaly_pbslb_drop': {
                'type': 'str',
            },
            'no_resourse_drop': {
                'type': 'str',
            },
            'reset_unknown_conn': {
                'type': 'str',
            },
            'reset_l7_on_failover': {
                'type': 'str',
            },
            'ignore_msl': {
                'type': 'str',
            },
            'l2_dsr': {
                'type': 'str',
            },
            'l3_dsr': {
                'type': 'str',
            },
            'port_preserve_attempt': {
                'type': 'str',
            },
            'port_preserve_succ': {
                'type': 'str',
            },
            'tcpsyndata_drop': {
                'type': 'str',
            },
            'tcpotherflags_drop': {
                'type': 'str',
            },
            'bw_rate_limit_exceed': {
                'type': 'str',
            },
            'bw_watermark_drop': {
                'type': 'str',
            },
            'l4_cps_exceed': {
                'type': 'str',
            },
            'nat_cps_exceed': {
                'type': 'str',
            },
            'l7_cps_exceed': {
                'type': 'str',
            },
            'ssl_cps_exceed': {
                'type': 'str',
            },
            'ssl_tpt_exceed': {
                'type': 'str',
            },
            'ssl_watermark_drop': {
                'type': 'str',
            },
            'concurrent_conn_exceed': {
                'type': 'str',
            },
            'svr_syn_handshake_fail': {
                'type': 'str',
            },
            'stateless_conn_timeout': {
                'type': 'str',
            },
            'tcp_ax_rexmit_syn': {
                'type': 'str',
            },
            'tcp_syn_rcv_ack': {
                'type': 'str',
            },
            'tcp_syn_rcv_rst': {
                'type': 'str',
            },
            'tcp_sess_noest_aged_out': {
                'type': 'str',
            },
            'tcp_sess_noest_csyn_rcv_aged_out': {
                'type': 'str',
            },
            'tcp_sess_noest_ssyn_xmit_aged_out': {
                'type': 'str',
            },
            'tcp_rexmit_syn': {
                'type': 'str',
            },
            'tcp_rexmit_syn_delq': {
                'type': 'str',
            },
            'tcp_rexmit_synack': {
                'type': 'str',
            },
            'tcp_rexmit_synack_delq': {
                'type': 'str',
            },
            'tcp_fwd_fin_dup': {
                'type': 'str',
            },
            'tcp_rev_fin_dup': {
                'type': 'str',
            },
            'tcp_rev_ackfin': {
                'type': 'str',
            },
            'tcp_fwd_rst': {
                'type': 'str',
            },
            'tcp_rev_rst': {
                'type': 'str',
            },
            'udp_req_oneplus_no_resp': {
                'type': 'str',
            },
            'udp_req_one_oneplus_resp': {
                'type': 'str',
            },
            'udp_req_resp_notmatch': {
                'type': 'str',
            },
            'udp_req_more_resp': {
                'type': 'str',
            },
            'udp_resp_more_req': {
                'type': 'str',
            },
            'udp_req_oneplus': {
                'type': 'str',
            },
            'udp_resp_oneplus': {
                'type': 'str',
            },
            'out_seq_ack_drop': {
                'type': 'str',
            },
            'tcp_est': {
                'type': 'str',
            },
            'synattack': {
                'type': 'str',
            },
            'syn_rate': {
                'type': 'str',
            },
            'syncookie_buff_drop': {
                'type': 'str',
            },
            'syncookie_buff_queue': {
                'type': 'str',
            },
            'skip_insert_client_ip': {
                'type': 'str',
            },
            'synreceived_hw': {
                'type': 'str',
            },
            'dns_id_switch': {
                'type': 'str',
            },
            'server_down_del': {
                'type': 'str',
            },
            'dnssec_switch': {
                'type': 'str',
            },
            'rate_drop_reset_unkn': {
                'type': 'str',
            },
            'tcp_connections_closed': {
                'type': 'str',
            },
            'snat_force_preserve_alloc': {
                'type': 'str',
            },
            'snat_force_preserve_free': {
                'type': 'str',
            },
            'snat_port_overload_fail': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/l4"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/l4"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["l4"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["l4"].get(k) != v:
            change_results["changed"] = True
            config_changes["l4"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("l4", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
