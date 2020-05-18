#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_service_group
description:
    - Service Group
short_description: Configures A10 slb.service-group
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
    conn_rate:
        description:
        - "Dynamically enable stateless method by conn-rate (Rate to trigger stateless method(conn/sec))"
        required: False
    reset_on_server_selection_fail:
        description:
        - "Send reset to client if server selection fails"
        required: False
    health_check_disable:
        description:
        - "Disable health check"
        required: False
    protocol:
        description:
        - "'tcp'= TCP LB service; 'udp'= UDP LB service; "
        required: False
    traffic_replication_mirror_ip_repl:
        description:
        - "Replaces IP with server-IP"
        required: False
    reset_priority_affinity:
        description:
        - "Reset"
        required: False
    priorities:
        description:
        - "Field priorities"
        required: False
        suboptions:
            priority:
                description:
                - "Priority option. Define different action for each priority node. (Priority in the Group)"
            priority_action:
                description:
                - "'drop'= Drop request when all priority nodes fail; 'drop-if-exceed-limit'= Drop request when connection over limit; 'proceed'= Proceed to next priority when all priority nodes fail(default); 'reset'= Send client reset when all priority nodes fail; 'reset-if-exceed-limit'= Send client reset when connection over limit; "
    min_active_member:
        description:
        - "Minimum Active Member Per Priority (Minimum Active Member before Action)"
        required: False
    member_list:
        description:
        - "Field member_list"
        required: False
        suboptions:
            member_priority:
                description:
                - "Priority of Port in the Group (Priority of Port in the Group, default is 1)"
            uuid:
                description:
                - "uuid of the object"
            fqdn_name:
                description:
                - "Server hostname - Not applicable if real server is already defined"
            resolve_as:
                description:
                - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as AAAA Query to resolve FQDN; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            member_template:
                description:
                - "Real server port template (Real server port template name)"
            name:
                description:
                - "Member name"
            host:
                description:
                - "IP Address - Not applicable if real server is already defined"
            user_tag:
                description:
                - "Customized tag"
            member_state:
                description:
                - "'enable'= Enable member service port; 'disable'= Disable member service port; 'disable-with-health-check'= disable member service port, but health check work; "
            server_ipv6_addr:
                description:
                - "IPV6 Address - Not applicable if real server is already defined"
            port:
                description:
                - "Port number"
            member_stats_data_disable:
                description:
                - "Disable statistical data collection"
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for service group; 'stats-data-disable'= Disable statistical data collection for service group; "
        required: False
    traffic_replication_mirror_da_repl:
        description:
        - "Replace Destination MAC"
        required: False
    template_policy_shared:
        description:
        - "Policy template"
        required: False
    rpt_ext_server:
        description:
        - "Report top 10 fastest/slowest servers"
        required: False
    template_port:
        description:
        - "Port template (Port template name)"
        required: False
    conn_rate_grace_period:
        description:
        - "Define the grace period during transition (Define the grace period during transition(seconds))"
        required: False
    l4_session_usage_duration:
        description:
        - "Period that trigger condition consistently happens(seconds)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            service_resp_2xx:
                description:
                - "Service Group response 2xx count"
            member_list:
                description:
                - "Field member_list"
            service_unhealthy_host:
                description:
                - "Service Group unhealthy host count"
            service_curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
            name:
                description:
                - "SLB Service Name"
            server_selection_fail_drop:
                description:
                - "Drops due to Service selection failure"
            service_healthy_host:
                description:
                - "Service Group healthy host count"
            service_resp_count:
                description:
                - "Service Group response count"
            service_req_count:
                description:
                - "Service Group request count"
            service_resp_4xx:
                description:
                - "Service Group response 4xx count"
            service_peak_conn:
                description:
                - "Peak connection count for the Service Group"
            server_selection_fail_reset:
                description:
                - "Resets sent out for Service selection failure"
            service_resp_3xx:
                description:
                - "Service Group response 3xx count"
            service_resp_5xx:
                description:
                - "Service Group response 5xx count"
    uuid:
        description:
        - "uuid of the object"
        required: False
    backup_server_event_log:
        description:
        - "Send log info on back up server events"
        required: False
    lc_method:
        description:
        - "'least-connection'= Least connection on server level; 'service-least-connection'= Least connection on service port level; 'weighted-least-connection'= Weighted least connection on server level; 'service-weighted-least-connection'= Weighted least connection on service port level; "
        required: False
    pseudo_round_robin:
        description:
        - "PRR, select the oldest node for sub-select"
        required: False
    shared_partition_policy_template:
        description:
        - "Reference a policy template from shared partition"
        required: False
    l4_session_usage_revert_rate:
        description:
        - "Usage to revert to statelful method"
        required: False
    shared_partition_svcgrp_health_check:
        description:
        - "Reference a health-check from shared partition"
        required: False
    template_server:
        description:
        - "Server template (Server template name)"
        required: False
    svcgrp_health_check_shared:
        description:
        - "Health Check (Monitor Name)"
        required: False
    traffic_replication_mirror:
        description:
        - "Mirror Bi-directional Packet"
        required: False
    l4_session_revert_duration:
        description:
        - "Period that revert condition consistently happens(seconds)"
        required: False
    traffic_replication_mirror_sa_da_repl:
        description:
        - "Replace Source MAC and Destination MAC"
        required: False
    lb_method:
        description:
        - "'dst-ip-hash'= Load-balancing based on only Dst IP and Port hash; 'dst-ip-only-hash'= Load-balancing based on only Dst IP hash; 'fastest-response'= Fastest response time on service port level; 'least-request'= Least request on service port level; 'src-ip-hash'= Load-balancing based on only Src IP and Port hash; 'src-ip-only-hash'= Load-balancing based on only Src IP hash; 'weighted-rr'= Weighted round robin on server level; 'service-weighted-rr'= Weighted round robin on service port level; 'round-robin'= Round robin on server level; 'round-robin-strict'= Strict mode round robin on server level; 'odd-even-hash'= odd/even hash based of client src-ip; "
        required: False
    stateless_auto_switch:
        description:
        - "Enable auto stateless method"
        required: False
    min_active_member_action:
        description:
        - "'dynamic-priority'= dynamic change member priority to met the min-active-member requirement; 'skip-pri-set'= Skip Current Priority Set If Min not met; "
        required: False
    l4_session_usage:
        description:
        - "Dynamically enable stateless method by session usage (Usage to trigger stateless method)"
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on service group"
        required: False
    conn_rate_revert_duration:
        description:
        - "Period that revert condition consistently happens(seconds)"
        required: False
    strict_select:
        description:
        - "strict selection"
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            pri_affinity_priority:
                description:
                - "Field pri_affinity_priority"
            name:
                description:
                - "SLB Service Name"
            stateless_current_rate:
                description:
                - "Field stateless_current_rate"
            servers_down:
                description:
                - "Field servers_down"
            stateless_state:
                description:
                - "Field stateless_state"
            servers_disable:
                description:
                - "Field servers_disable"
            stateless_type:
                description:
                - "Field stateless_type"
            servers_total:
                description:
                - "Field servers_total"
            state:
                description:
                - "Field state"
            member_list:
                description:
                - "Field member_list"
            servers_up:
                description:
                - "Field servers_up"
            stateless_current_usage:
                description:
                - "Field stateless_current_usage"
            hm_dsr_enable_all_vip:
                description:
                - "Field hm_dsr_enable_all_vip"
    name:
        description:
        - "SLB Service Name"
        required: True
    reset:
        description:
        - "Field reset"
        required: False
        suboptions:
            auto_switch:
                description:
                - "Reset auto stateless state"
    traffic_replication_mirror_sa_repl:
        description:
        - "Replace Source MAC"
        required: False
    report_delay:
        description:
        - "Reporting frequency (in minutes)"
        required: False
    conn_rate_log:
        description:
        - "Send log if transition happens"
        required: False
    l4_session_usage_log:
        description:
        - "Send log if transition happens"
        required: False
    conn_rate_duration:
        description:
        - "Period that trigger condition consistently happens(seconds)"
        required: False
    stateless_lb_method:
        description:
        - "'stateless-dst-ip-hash'= Stateless load-balancing based on Dst IP and Dst port hash; 'stateless-per-pkt-round-robin'= Stateless load-balancing using per-packet round-robin; 'stateless-src-dst-ip-hash'= Stateless load-balancing based on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash'= Stateless load-balancing based on only IP hash for both Src and Dst; 'stateless-src-ip-hash'= Stateless load-balancing based on Src IP and Src port hash; 'stateless-src-ip-only-hash'= Stateless load-balancing based on only Src IP hash; "
        required: False
    template_policy:
        description:
        - "Policy template (Policy template name)"
        required: False
    stateless_lb_method2:
        description:
        - "'stateless-dst-ip-hash'= Stateless load-balancing based on Dst IP and Dst port hash; 'stateless-per-pkt-round-robin'= Stateless load-balancing using per-packet round-robin; 'stateless-src-dst-ip-hash'= Stateless load-balancing based on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash'= Stateless load-balancing based on only IP hash for both Src and Dst; 'stateless-src-ip-hash'= Stateless load-balancing based on Src IP and Src port hash; 'stateless-src-ip-only-hash'= Stateless load-balancing based on only Src IP hash; "
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    sample_rsp_time:
        description:
        - "sample server response time"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'server_selection_fail_drop'= Drops due to Service selection failure; 'server_selection_fail_reset'= Resets sent out for Service selection failure; 'service_peak_conn'= Peak connection count for the Service Group; 'service_healthy_host'= Service Group healthy host count; 'service_unhealthy_host'= Service Group unhealthy host count; 'service_req_count'= Service Group request count; 'service_resp_count'= Service Group response count; 'service_resp_2xx'= Service Group response 2xx count; 'service_resp_3xx'= Service Group response 3xx count; 'service_resp_4xx'= Service Group response 4xx count; 'service_resp_5xx'= Service Group response 5xx count; 'service_curr_conn_overflow'= Current connection counter overflow count; "
    top_fastest:
        description:
        - "Report top 10 fastest servers"
        required: False
    conn_revert_rate:
        description:
        - "Rate to revert to statelful method (conn/sec)"
        required: False
    l4_session_usage_grace_period:
        description:
        - "Define the grace period during transition (Define the grace period during transition(seconds))"
        required: False
    priority_affinity:
        description:
        - "Priority affinity. Persist to the same priority if possible."
        required: False
    top_slowest:
        description:
        - "Report top 10 slowest servers"
        required: False
    health_check:
        description:
        - "Health Check (Monitor Name)"
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
AVAILABLE_PROPERTIES = ["backup_server_event_log","conn_rate","conn_rate_duration","conn_rate_grace_period","conn_rate_log","conn_rate_revert_duration","conn_revert_rate","extended_stats","health_check","health_check_disable","l4_session_revert_duration","l4_session_usage","l4_session_usage_duration","l4_session_usage_grace_period","l4_session_usage_log","l4_session_usage_revert_rate","lb_method","lc_method","member_list","min_active_member","min_active_member_action","name","oper","priorities","priority_affinity","protocol","pseudo_round_robin","report_delay","reset","reset_on_server_selection_fail","reset_priority_affinity","rpt_ext_server","sample_rsp_time","sampling_enable","shared_partition_policy_template","shared_partition_svcgrp_health_check","stateless_auto_switch","stateless_lb_method","stateless_lb_method2","stats","stats_data_action","strict_select","svcgrp_health_check_shared","template_policy","template_policy_shared","template_port","template_server","top_fastest","top_slowest","traffic_replication_mirror","traffic_replication_mirror_da_repl","traffic_replication_mirror_ip_repl","traffic_replication_mirror_sa_da_repl","traffic_replication_mirror_sa_repl","user_tag","uuid",]

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
        conn_rate=dict(type='int', ),
        reset_on_server_selection_fail=dict(type='bool', ),
        health_check_disable=dict(type='bool', ),
        protocol=dict(type='str', choices=['tcp', 'udp']),
        traffic_replication_mirror_ip_repl=dict(type='bool', ),
        reset_priority_affinity=dict(type='bool', ),
        priorities=dict(type='list', priority=dict(type='int', ), priority_action=dict(type='str', choices=['drop', 'drop-if-exceed-limit', 'proceed', 'reset', 'reset-if-exceed-limit'])),
        min_active_member=dict(type='int', ),
        member_list=dict(type='list', member_priority=dict(type='int', ), uuid=dict(type='str', ), fqdn_name=dict(type='str', ), resolve_as=dict(type='str', choices=['resolve-to-ipv4', 'resolve-to-ipv6', 'resolve-to-ipv4-and-ipv6']), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts', 'total_conn', 'total_rev_pkts_inspected', 'total_rev_pkts_inspected_status_code_2xx', 'total_rev_pkts_inspected_status_code_non_5xx', 'curr_req', 'total_req', 'total_req_succ', 'peak_conn', 'response_time', 'fastest_rsp_time', 'slowest_rsp_time', 'curr_ssl_conn', 'total_ssl_conn', 'curr_conn_overflow', 'state_flaps'])), member_template=dict(type='str', ), name=dict(type='str', required=True, ), host=dict(type='str', ), user_tag=dict(type='str', ), member_state=dict(type='str', choices=['enable', 'disable', 'disable-with-health-check']), server_ipv6_addr=dict(type='str', ), port=dict(type='int', required=True, ), member_stats_data_disable=dict(type='bool', )),
        stats_data_action=dict(type='str', choices=['stats-data-enable', 'stats-data-disable']),
        traffic_replication_mirror_da_repl=dict(type='bool', ),
        template_policy_shared=dict(type='str', ),
        rpt_ext_server=dict(type='bool', ),
        template_port=dict(type='str', ),
        conn_rate_grace_period=dict(type='int', ),
        l4_session_usage_duration=dict(type='int', ),
        stats=dict(type='dict', service_resp_2xx=dict(type='str', ), member_list=dict(type='list', stats=dict(type='dict', curr_req=dict(type='str', ), total_rev_bytes=dict(type='str', ), peak_conn=dict(type='str', ), total_ssl_conn=dict(type='str', ), total_conn=dict(type='str', ), fastest_rsp_time=dict(type='str', ), total_fwd_pkts=dict(type='str', ), total_req=dict(type='str', ), total_rev_pkts=dict(type='str', ), curr_ssl_conn=dict(type='str', ), total_req_succ=dict(type='str', ), state_flaps=dict(type='str', ), curr_conn=dict(type='str', ), total_rev_pkts_inspected_status_code_non_5xx=dict(type='str', ), total_rev_pkts_inspected_status_code_2xx=dict(type='str', ), curr_conn_overflow=dict(type='str', ), total_fwd_bytes=dict(type='str', ), slowest_rsp_time=dict(type='str', ), response_time=dict(type='str', ), total_rev_pkts_inspected=dict(type='str', )), name=dict(type='str', required=True, ), port=dict(type='int', required=True, )), service_unhealthy_host=dict(type='str', ), service_curr_conn_overflow=dict(type='str', ), name=dict(type='str', required=True, ), server_selection_fail_drop=dict(type='str', ), service_healthy_host=dict(type='str', ), service_resp_count=dict(type='str', ), service_req_count=dict(type='str', ), service_resp_4xx=dict(type='str', ), service_peak_conn=dict(type='str', ), server_selection_fail_reset=dict(type='str', ), service_resp_3xx=dict(type='str', ), service_resp_5xx=dict(type='str', )),
        uuid=dict(type='str', ),
        backup_server_event_log=dict(type='bool', ),
        lc_method=dict(type='str', choices=['least-connection', 'service-least-connection', 'weighted-least-connection', 'service-weighted-least-connection']),
        pseudo_round_robin=dict(type='bool', ),
        shared_partition_policy_template=dict(type='bool', ),
        l4_session_usage_revert_rate=dict(type='int', ),
        shared_partition_svcgrp_health_check=dict(type='bool', ),
        template_server=dict(type='str', ),
        svcgrp_health_check_shared=dict(type='str', ),
        traffic_replication_mirror=dict(type='bool', ),
        l4_session_revert_duration=dict(type='int', ),
        traffic_replication_mirror_sa_da_repl=dict(type='bool', ),
        lb_method=dict(type='str', choices=['dst-ip-hash', 'dst-ip-only-hash', 'fastest-response', 'least-request', 'src-ip-hash', 'src-ip-only-hash', 'weighted-rr', 'service-weighted-rr', 'round-robin', 'round-robin-strict', 'odd-even-hash']),
        stateless_auto_switch=dict(type='bool', ),
        min_active_member_action=dict(type='str', choices=['dynamic-priority', 'skip-pri-set']),
        l4_session_usage=dict(type='int', ),
        extended_stats=dict(type='bool', ),
        conn_rate_revert_duration=dict(type='int', ),
        strict_select=dict(type='bool', ),
        oper=dict(type='dict', pri_affinity_priority=dict(type='int', ), name=dict(type='str', required=True, ), stateless_current_rate=dict(type='int', ), servers_down=dict(type='int', ), stateless_state=dict(type='int', ), servers_disable=dict(type='int', ), stateless_type=dict(type='int', ), servers_total=dict(type='int', ), state=dict(type='str', choices=['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']), member_list=dict(type='list', oper=dict(type='dict', hm_key=dict(type='int', ), alt_list=dict(type='list', alt_state=dict(type='str', ), alt_rev_pkts=dict(type='int', ), alt_port=dict(type='int', ), alt_peak_conn=dict(type='int', ), alt_curr_conn=dict(type='int', ), alt_fwd_pkts=dict(type='int', ), alt_total_conn=dict(type='int', ), alt_name=dict(type='str', )), hm_index=dict(type='int', ), state=dict(type='str', choices=['UP', 'DOWN', 'MAINTENANCE', 'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE', 'DIS-DAMP']), drs_list=dict(type='list', drs_fwd_bts=dict(type='int', ), drs_fwd_pkts=dict(type='int', ), drs_rev_bts=dict(type='int', ), drs_port=dict(type='int', ), drs_curr_req=dict(type='int', ), drs_name=dict(type='str', ), drs_pers_conn=dict(type='int', ), drs_priority=dict(type='int', ), drs_total_req_succ=dict(type='int', ), drs_hm_key=dict(type='int', ), drs_hm_index=dict(type='int', ), drs_rev_pkts=dict(type='int', ), drs_total_conn=dict(type='int', ), drs_state=dict(type='str', ), drs_frsp_time=dict(type='int', ), drs_peak_conn=dict(type='int', ), drs_curr_conn=dict(type='int', ), drs_rsp_time=dict(type='int', ), drs_total_req=dict(type='int', ), drs_srsp_time=dict(type='int', ))), name=dict(type='str', required=True, ), port=dict(type='int', required=True, )), servers_up=dict(type='int', ), stateless_current_usage=dict(type='int', ), hm_dsr_enable_all_vip=dict(type='int', )),
        name=dict(type='str', required=True, ),
        reset=dict(type='dict', auto_switch=dict(type='bool', )),
        traffic_replication_mirror_sa_repl=dict(type='bool', ),
        report_delay=dict(type='int', ),
        conn_rate_log=dict(type='bool', ),
        l4_session_usage_log=dict(type='bool', ),
        conn_rate_duration=dict(type='int', ),
        stateless_lb_method=dict(type='str', choices=['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']),
        template_policy=dict(type='str', ),
        stateless_lb_method2=dict(type='str', choices=['stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash']),
        user_tag=dict(type='str', ),
        sample_rsp_time=dict(type='bool', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'server_selection_fail_drop', 'server_selection_fail_reset', 'service_peak_conn', 'service_healthy_host', 'service_unhealthy_host', 'service_req_count', 'service_resp_count', 'service_resp_2xx', 'service_resp_3xx', 'service_resp_4xx', 'service_resp_5xx', 'service_curr_conn_overflow'])),
        top_fastest=dict(type='bool', ),
        conn_revert_rate=dict(type='int', ),
        l4_session_usage_grace_period=dict(type='int', ),
        priority_affinity=dict(type='bool', ),
        top_slowest=dict(type='bool', ),
        health_check=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/service-group/{name}"

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
    url_base = "/axapi/v3/slb/service-group/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted(['lb_method','stateless-lb-method','lc_method'])
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
        for k, v in payload["service-group"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["service-group"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["service-group"][k] = v
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
    payload = build_json("service-group", module)
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