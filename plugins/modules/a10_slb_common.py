#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_common
description:
    - SLB related commands
author: A10 Networks
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
    port_scan_detection:
        description:
        - "'enable'= Enable port scan detection; 'disable'= Disable port scan
          detection(default);"
        type: str
        required: False
    ping_sweep_detection:
        description:
        - "'enable'= Enable ping sweep detection; 'disable'= Disable ping sweep
          detection(default);"
        type: str
        required: False
    extended_stats:
        description:
        - "Enable global slb extended statistics"
        type: bool
        required: False
    stats_data_disable:
        description:
        - "Disable global slb data statistics"
        type: bool
        required: False
    graceful_shutdown_enable:
        description:
        - "Enable graceful shutdown"
        type: bool
        required: False
    graceful_shutdown:
        description:
        - "1-65535, in unit of seconds"
        type: int
        required: False
    entity:
        description:
        - "'server'= Graceful shutdown server/port only; 'virtual-server'= Graceful
          shutdown virtual server/port only;"
        type: str
        required: False
    after_disable:
        description:
        - "Graceful shutdown after disable server/port and/or virtual server/port"
        type: bool
        required: False
    rate_limit_logging:
        description:
        - "Configure rate limit logging"
        type: bool
        required: False
    max_local_rate:
        description:
        - "Set maximum local rate"
        type: int
        required: False
    max_remote_rate:
        description:
        - "Set maximum remote rate"
        type: int
        required: False
    exclude_destination:
        description:
        - "'local'= Maximum local rate; 'remote'= Maximum remote rate;  (Maximum rates)"
        type: str
        required: False
    auto_translate_port:
        description:
        - "Auto Translate Port range"
        type: bool
        required: False
    range:
        description:
        - "auto translate port range"
        type: int
        required: False
    range_start:
        description:
        - "port range start"
        type: int
        required: False
    range_end:
        description:
        - "port range end"
        type: int
        required: False
    use_default_sess_count:
        description:
        - "Use default session count"
        type: bool
        required: False
    per_thr_percent:
        description:
        - "Percentage of default session count to use for per thread session table size"
        type: int
        required: False
    dsr_health_check_enable:
        description:
        - "Enable dsr-health-check (direct server return health check)"
        type: bool
        required: False
    one_server_conn_hm_rate:
        description:
        - "One Server Conn Health Check Rate"
        type: int
        required: False
    aflex_table_entry_aging_interval:
        description:
        - "aFleX table entry aging interval in second"
        type: int
        required: False
    aflex_persist_uie_chassis_sync_enable:
        description:
        - "Enable aflex persist uie cross PU sync"
        type: bool
        required: False
    override_port:
        description:
        - "Enable override port in DSR health check mode"
        type: bool
        required: False
    health_check_to_all_vip:
        description:
        - "Field health_check_to_all_vip"
        type: bool
        required: False
    reset_stale_session:
        description:
        - "Send reset if session in delete queue receives a SYN packet"
        type: bool
        required: False
    dns_negative_cache_enable:
        description:
        - "Enable DNS negative cache"
        type: bool
        required: False
    dns_negative_cache_caching_non_valid:
        description:
        - "Enable caching non-valid negative response, otherwise will only cache valid
          negative response"
        type: bool
        required: False
    dns_cookie_cache_policy:
        description:
        - "'served-by-cache'= Answer from cache for requests with cookie; 'served-by-
          backend'= Answer from server for requests with cookie;"
        type: str
        required: False
    dns_cache_enable:
        description:
        - "Enable DNS cache"
        type: bool
        required: False
    dns_persistent_cache_enable:
        description:
        - "Enable persistent DNS cache"
        type: bool
        required: False
    max_persistent_cache:
        description:
        - "Define maximum persistent cache (Maximum persistent cache entry)"
        type: int
        required: False
    dns_persistent_cache_ttl_threshold:
        description:
        - "Only save DNS cache with longer TTL (0-10000000 seconds, default is 0 second)"
        type: int
        required: False
    dns_persistent_cache_hit_threshold:
        description:
        - "Only save DNS cache with larger hit count (0-10000000, default is 0)"
        type: int
        required: False
    dns_cache_ttl_adjustment_enable:
        description:
        - "Enable DNS cache response ttl adjustment"
        type: bool
        required: False
    response_type:
        description:
        - "'single-answer'= Only cache DNS response with single answer; 'round-robin'=
          Round robin;"
        type: str
        required: False
    ttl_threshold:
        description:
        - "Only cache DNS response with longer TTL"
        type: int
        required: False
    dns_cache_aging_weight:
        description:
        - "Set DNS cache entry weight, default is 1"
        type: int
        required: False
    dns_cache_age:
        description:
        - "Set DNS cache entry age, default is 300 seconds (1-1000000 seconds, default is
          300 seconds)"
        type: int
        required: False
    dns_cache_age_min_threshold:
        description:
        - "Set DNS cache entry age minimum threshold, default is 0 seconds (1-1000000
          seconds, default is 0 seconds)"
        type: int
        required: False
    compress_block_size:
        description:
        - "Set compression block size (Compression block size in bytes)"
        type: int
        required: False
    dns_cache_entry_size:
        description:
        - "Set DNS cache entry size, default is 256 bytes (1-4096 bytes, default is 256
          bytes)"
        type: int
        required: False
    dns_cache_sync:
        description:
        - "Enable DNS cache HA sync"
        type: bool
        required: False
    dns_cache_sync_ttl_threshold:
        description:
        - "Only sync DNS cache with longer TTL (0-10000000 seconds, default is 0 second)"
        type: int
        required: False
    dns_cache_sync_entry_size:
        description:
        - "Only sync DNS cache with smaller size (1-4096 bytes, default is 256 bytes)"
        type: int
        required: False
    dns_cache_hitcount_enable:
        description:
        - "Enable DNS cache entry hit count"
        type: bool
        required: False
    dns_vip_stateless:
        description:
        - "Enable DNS VIP stateless mode"
        type: bool
        required: False
    honor_server_response_ttl:
        description:
        - "Honor the server reponse TTL"
        type: bool
        required: False
    recursive_ns_cache:
        description:
        - "'honor-packet-ttl'= Honor the lowest TTL among NS records in the server
          response; 'honor-age-config'= Honor the ttl/age settings based on acos dns
          cache configuration;"
        type: str
        required: False
    buff_thresh:
        description:
        - "Set buffer threshold"
        type: bool
        required: False
    buff_thresh_hw_buff:
        description:
        - "Set hardware buffer threshold"
        type: int
        required: False
    buff_thresh_relieve_thresh:
        description:
        - "Relieve threshold"
        type: int
        required: False
    buff_thresh_sys_buff_low:
        description:
        - "Set low water mark of system buffer"
        type: int
        required: False
    buff_thresh_sys_buff_high:
        description:
        - "Set high water mark of system buffer"
        type: int
        required: False
    max_buff_queued_per_conn:
        description:
        - "Set per connection buffer threshold (Buffer value range 128-4096)"
        type: int
        required: False
    pkt_rate_for_reset_unknown_conn:
        description:
        - "Field pkt_rate_for_reset_unknown_conn"
        type: int
        required: False
    log_for_reset_unknown_conn:
        description:
        - "Log when rate exceed"
        type: bool
        required: False
    gateway_health_check:
        description:
        - "Enable gateway health check"
        type: bool
        required: False
    interval:
        description:
        - "Specify the healthcheck interval, default is 5 seconds (Interval Value, in
          seconds (default 5))"
        type: int
        required: False
    timeout:
        description:
        - "Specify the healthcheck timeout value, default is 15 seconds (Timeout Value, in
          seconds (default 15))"
        type: int
        required: False
    msl_time:
        description:
        - "Configure maximum session life, default is 2 seconds (1-39 seconds, default is
          2 seconds)"
        type: int
        required: False
    fast_path_disable:
        description:
        - "Disable fast path in SLB processing"
        type: bool
        required: False
    odd_even_nat_enable:
        description:
        - "Enable odd even nat pool allocation in dual blade systems"
        type: bool
        required: False
    odd_even_nat_one_arm:
        description:
        - "Enable odd even nat pool allocation in one-arm deployment"
        type: bool
        required: False
    http_fast_enable:
        description:
        - "Enable Http Fast in SLB processing"
        type: bool
        required: False
    l2l3_trunk_lb_disable:
        description:
        - "Disable L2/L3 trunk LB"
        type: bool
        required: False
    snat_gwy_for_l3:
        description:
        - "Use source NAT gateway for L3 traffic for transparent mode"
        type: bool
        required: False
    allow_in_gateway_mode:
        description:
        - "Use source NAT gateway for L3 traffic for gateway mode"
        type: bool
        required: False
    disable_server_auto_reselect:
        description:
        - "Disable auto reselection of server"
        type: bool
        required: False
    enable_l7_req_acct:
        description:
        - "Enable L7 request accounting"
        type: bool
        required: False
    enable_ddos:
        description:
        - "Enable DDoS protection"
        type: bool
        required: False
    disable_adaptive_resource_check:
        description:
        - "Disable adaptive resource check based on buffer usage"
        type: bool
        required: False
    ddos_pkt_size_thresh:
        description:
        - "Set data packet size threshold for DDOS, default is 64 bytes"
        type: int
        required: False
    ddos_pkt_count_thresh:
        description:
        - "Set packet count threshold for DDOS, default is 100"
        type: int
        required: False
    snat_on_vip:
        description:
        - "Enable source NAT traffic against VIP"
        type: bool
        required: False
    low_latency:
        description:
        - "Enable low latency mode"
        type: bool
        required: False
    mss_table:
        description:
        - "Set MSS table (128-750, default is 536)"
        type: int
        required: False
    resolve_port_conflict:
        description:
        - "Enable client port service port conflicts"
        type: bool
        required: False
    no_auto_up_on_aflex:
        description:
        - "Don't automatically mark vport up when aFleX is bound"
        type: bool
        required: False
    hw_compression:
        description:
        - "Use hardware compression"
        type: bool
        required: False
    hw_syn_rr:
        description:
        - "Configure hardware SYN round robin (range 1-500000)"
        type: int
        required: False
    max_http_header_count:
        description:
        - "Set maximum number of HTTP headers allowed"
        type: int
        required: False
    scale_out:
        description:
        - "Enable SLB scale out"
        type: bool
        required: False
    scale_out_traffic_map:
        description:
        - "Set SLB scaleout traffic-map"
        type: bool
        required: False
    show_slb_server_legacy_cmd:
        description:
        - "Enable show slb server legacy command"
        type: bool
        required: False
    show_slb_service_group_legacy_cmd:
        description:
        - "Enable show slb service-group legacy command"
        type: bool
        required: False
    show_slb_virtual_server_legacy_cmd:
        description:
        - "Enable show slb virtual-server legacy command"
        type: bool
        required: False
    traffic_map_type:
        description:
        - "'vport'= traffic-map per vport; 'global'= global traffic-map;"
        type: str
        required: False
    sort_res:
        description:
        - "Enable SLB sorting of resource names"
        type: bool
        required: False
    use_mss_tab:
        description:
        - "Use MSS based on internal table for SLB processing"
        type: bool
        required: False
    auto_nat_no_ip_refresh:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    ddos_protection:
        description:
        - "Field ddos_protection"
        type: dict
        required: False
        suboptions:
            ipd_enable_toggle:
                description:
                - "'enable'= Enable SLB DDoS protection; 'disable'= Disable SLB DDoS protection
          (default);"
                type: str
            logging:
                description:
                - "Field logging"
                type: dict
            packets_per_second:
                description:
                - "Field packets_per_second"
                type: dict
    ssli_sni_hash_enable:
        description:
        - "Enable SSLi SNI hash table"
        type: bool
        required: False
    clientside_ip:
        description:
        - "Clientside IP address"
        type: str
        required: False
    clientside_ipv6:
        description:
        - "Clientside IPv6 address"
        type: str
        required: False
    serverside_ip:
        description:
        - "Serverside IP address"
        type: str
        required: False
    serverside_ipv6:
        description:
        - "Serverside IPv6 address"
        type: str
        required: False
    port:
        description:
        - "Serverside port number for SNI transmission"
        type: int
        required: False
    ssli_cert_not_ready_inspect_timeout:
        description:
        - "SSLI asynchronized connection timeout, default is 10 seconds (seconds, set to 0
          for never timeout)"
        type: int
        required: False
    ssli_cert_not_ready_inspect_limit:
        description:
        - "SSLI asynchronized connection max number, default is 2000 (set to 0 for
          unlimited size)"
        type: int
        required: False
    ssli_silent_termination_enable:
        description:
        - "Terminate the SSLi sessions silently without sending RST/FIN packet"
        type: bool
        required: False
    software:
        description:
        - "Software"
        type: bool
        required: False
    software_tls13:
        description:
        - "Software TLS1.3"
        type: bool
        required: False
    QAT:
        description:
        - "HW assisted QAT SSL module"
        type: bool
        required: False
    QAT4:
        description:
        - "HW assisted QAT Gen4 SSL module"
        type: bool
        required: False
    N5_new:
        description:
        - "HW assisted N5 SSL module with TLS 1.3 and TLS 1.2 support using OpenSSL 1.1.1"
        type: bool
        required: False
    N5_old:
        description:
        - "HW assisted N5 SSL module with TLS 1.2 support using OpenSSL 0.9.7"
        type: bool
        required: False
    software_tls13_offload:
        description:
        - "Software TLS1.3 with CPU Offload Support"
        type: bool
        required: False
    ssl_n5_delay_tx_enable:
        description:
        - "Enable delay transmission for N5-new"
        type: bool
        required: False
    ssl_ratelimit_cfg:
        description:
        - "Field ssl_ratelimit_cfg"
        type: dict
        required: False
        suboptions:
            disable_rate:
                description:
                - "Disable HW SSL Rate limit for N5-new"
                type: bool
            tls12_rate:
                description:
                - "Enabling Rateliming for TLS1.2 HW requests per chip in 1K - default 120"
                type: int
            tls13_rate:
                description:
                - "Enabling Rateliming for TLS1.3 HW requests per chip in 1K - default 72"
                type: int
    ssl_module_usage_enable:
        description:
        - "Enable SSL module usage calculations for QAT"
        type: bool
        required: False
    substitute_source_mac:
        description:
        - "Substitute Source MAC Address to that of the outgoing interface"
        type: bool
        required: False
    drop_icmp_to_vip_when_vip_down:
        description:
        - "Drop ICMP to VIP when VIP down"
        type: bool
        required: False
    player_id_check_enable:
        description:
        - "Enable the Player id check"
        type: bool
        required: False
    stateless_sg_multi_binding:
        description:
        - "Enable stateless service groups to be assigned to multiple L2/L3 DSR VIPs"
        type: bool
        required: False
    ecmp_hash:
        description:
        - "'system-default'= Use system default ecmp hashing algorithm; 'connection-
          based'= Use connection information for hashing;"
        type: str
        required: False
    vport_global:
        description:
        - "Configure periodic showtech vport paging global limit"
        type: int
        required: False
    vport_l3v:
        description:
        - "Configure periodic showtech vport paging l3v limit"
        type: int
        required: False
    service_group_on_no_dest_nat_vports:
        description:
        - "'allow-same'= Allow the binding service-group on no-dest-nat virtual ports;
          'enforce-different'= Enforce that the same service-group can not be bound on
          different no-dest-nat virtual ports;"
        type: str
        required: False
    disable_port_masking:
        description:
        - "Disable masking of ports for CPU hashing"
        type: bool
        required: False
    snat_preserve:
        description:
        - "Field snat_preserve"
        type: dict
        required: False
        suboptions:
            range:
                description:
                - "Field range"
                type: list
    disable_persist_scoring:
        description:
        - "Disable Persist Scoring"
        type: bool
        required: False
    ipv4_offset:
        description:
        - "IPv4 Octet Offset for Hash"
        type: int
        required: False
    ipv6_subnet:
        description:
        - "IPv6 Octet Valid Subnet Length for Hash"
        type: int
        required: False
    pbslb_entry_age:
        description:
        - "Set global pbslb entry age (minute)"
        type: int
        required: False
    pbslb_overflow_glid:
        description:
        - "Apply global limit id to overflow pbslb entry"
        type: str
        required: False
    pre_process_enable:
        description:
        - "Enable NG-WAF pre-processing"
        type: bool
        required: False
    cache_expire_time:
        description:
        - "Cache expiration time, default is 1 minute"
        type: int
        required: False
    attack_resp_code:
        description:
        - "Custom response code"
        type: int
        required: False
    monitor_mode_enable:
        description:
        - "Enable NG-WAF monitor mode"
        type: bool
        required: False
    custom_signal_clist:
        description:
        - "Provide custom signal names"
        type: str
        required: False
    custom_message:
        description:
        - "Block message"
        type: str
        required: False
    custom_page:
        description:
        - "Specify the custom webpage name"
        type: str
        required: False
    use_https_proxy:
        description:
        - "NG-WAF connects to Cloud through proxy server"
        type: bool
        required: False
    ngwaf_proxy_ipv4:
        description:
        - "IPv4 address"
        type: str
        required: False
    ngwaf_proxy_ipv6:
        description:
        - "IPv6 address"
        type: str
        required: False
    ngwaf_proxy_port:
        description:
        - "Port"
        type: int
        required: False
    use_mgmt_port:
        description:
        - "Use management port to connect"
        type: bool
        required: False
    enable_fast_path_rerouting:
        description:
        - "Enable Fast-Path Rerouting"
        type: bool
        required: False
    cancel_stream_loop_limit:
        description:
        - "Set global cancel stream loop limit (cancel stream loop limit, default is 5)"
        type: int
        required: False
    redirect_dummy_ethernet:
        description:
        - "Ethernet interface (Ethernet interface number)"
        type: str
        required: False
    redirect_dummy_vlan:
        description:
        - "VLAN Id"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    cert_pinning:
        description:
        - "Field cert_pinning"
        type: dict
        required: False
        suboptions:
            ttl:
                description:
                - "The ttl of local cert pinning candidate list, multiple of 10 minutes, default
          is 144 (1440 minutes)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            candidate_list_feedback_opt_in:
                description:
                - "Field candidate_list_feedback_opt_in"
                type: dict
    aflex_table_entry_sync:
        description:
        - "Field aflex_table_entry_sync"
        type: dict
        required: False
        suboptions:
            aflex_table_entry_sync_enable:
                description:
                - "Enable aflex table sync"
                type: bool
            aflex_table_entry_sync_max_key_len:
                description:
                - "aflex table entry max key length to sync"
                type: int
            aflex_table_entry_sync_max_value_len:
                description:
                - "aflex table entry max value length to sync"
                type: int
            aflex_table_entry_sync_min_lifetime:
                description:
                - "aflex table entry minimum lifetime to sync"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    quic:
        description:
        - "Field quic"
        type: dict
        required: False
        suboptions:
            cid_len:
                description:
                - "Length of CID"
                type: int
            signature:
                description:
                - "Set CID Signature"
                type: str
            signature_len:
                description:
                - "Offset for CID Signature"
                type: int
            signature_offset:
                description:
                - "Offset for CID Signature"
                type: int
            cpu_offset:
                description:
                - "Offset for Encoded CPU"
                type: int
            quic_lb_offset:
                description:
                - "Offset for QUIC-LB"
                type: int
            enable_hash:
                description:
                - "Enable CID Hashing"
                type: bool
            enable_signature:
                description:
                - "Enable CID Signature Validation"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    conn_rate_limit:
        description:
        - "Field conn_rate_limit"
        type: dict
        required: False
        suboptions:
            src_ip_list:
                description:
                - "Field src_ip_list"
                type: list
    dns_response_rate_limiting:
        description:
        - "Field dns_response_rate_limiting"
        type: dict
        required: False
        suboptions:
            max_table_entries:
                description:
                - "Maximum number of entries allowed"
                type: int
            source_entry_age:
                description:
                - "Source entry age in minutes (default 2)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    global_dns_cache:
        description:
        - "Field global_dns_cache"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            class_list:
                description:
                - "Field class_list"
                type: dict
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            server_auto_reselect:
                description:
                - "Field server_auto_reselect"
                type: int

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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "aflex_persist_uie_chassis_sync_enable", "aflex_table_entry_aging_interval", "aflex_table_entry_sync", "after_disable", "allow_in_gateway_mode", "attack_resp_code", "auto_nat_no_ip_refresh", "auto_translate_port", "buff_thresh", "buff_thresh_hw_buff", "buff_thresh_relieve_thresh", "buff_thresh_sys_buff_high", "buff_thresh_sys_buff_low",
    "cache_expire_time", "cancel_stream_loop_limit", "cert_pinning", "clientside_ip", "clientside_ipv6", "compress_block_size", "conn_rate_limit", "custom_message", "custom_page", "custom_signal_clist", "ddos_pkt_count_thresh", "ddos_pkt_size_thresh", "ddos_protection", "disable_adaptive_resource_check", "disable_persist_scoring",
    "disable_port_masking", "disable_server_auto_reselect", "dns_cache_age", "dns_cache_age_min_threshold", "dns_cache_aging_weight", "dns_cache_enable", "dns_cache_entry_size", "dns_cache_hitcount_enable", "dns_cache_sync", "dns_cache_sync_entry_size", "dns_cache_sync_ttl_threshold", "dns_cache_ttl_adjustment_enable", "dns_cookie_cache_policy",
    "dns_negative_cache_caching_non_valid", "dns_negative_cache_enable", "dns_persistent_cache_enable", "dns_persistent_cache_hit_threshold", "dns_persistent_cache_ttl_threshold", "dns_response_rate_limiting", "dns_vip_stateless", "drop_icmp_to_vip_when_vip_down", "dsr_health_check_enable", "ecmp_hash", "enable_ddos", "enable_fast_path_rerouting",
    "enable_l7_req_acct", "entity", "exclude_destination", "extended_stats", "fast_path_disable", "gateway_health_check", "global_dns_cache", "graceful_shutdown", "graceful_shutdown_enable", "health_check_to_all_vip", "honor_server_response_ttl", "http_fast_enable", "hw_compression", "hw_syn_rr", "interval", "ipv4_offset", "ipv6_subnet",
    "l2l3_trunk_lb_disable", "log_for_reset_unknown_conn", "low_latency", "max_buff_queued_per_conn", "max_http_header_count", "max_local_rate", "max_persistent_cache", "max_remote_rate", "monitor_mode_enable", "msl_time", "mss_table", "N5_new", "N5_old", "ngwaf_proxy_ipv4", "ngwaf_proxy_ipv6", "ngwaf_proxy_port", "no_auto_up_on_aflex",
    "odd_even_nat_enable", "odd_even_nat_one_arm", "one_server_conn_hm_rate", "oper", "override_port", "pbslb_entry_age", "pbslb_overflow_glid", "per_thr_percent", "ping_sweep_detection", "pkt_rate_for_reset_unknown_conn", "player_id_check_enable", "port", "port_scan_detection", "pre_process_enable", "QAT", "QAT4", "quic", "range", "range_end",
    "range_start", "rate_limit_logging", "recursive_ns_cache", "redirect_dummy_ethernet", "redirect_dummy_vlan", "reset_stale_session", "resolve_port_conflict", "response_type", "scale_out", "scale_out_traffic_map", "serverside_ip", "serverside_ipv6", "service_group_on_no_dest_nat_vports", "show_slb_server_legacy_cmd",
    "show_slb_service_group_legacy_cmd", "show_slb_virtual_server_legacy_cmd", "snat_gwy_for_l3", "snat_on_vip", "snat_preserve", "software", "software_tls13", "software_tls13_offload", "sort_res", "ssl_module_usage_enable", "ssl_n5_delay_tx_enable", "ssl_ratelimit_cfg", "ssli_cert_not_ready_inspect_limit", "ssli_cert_not_ready_inspect_timeout",
    "ssli_silent_termination_enable", "ssli_sni_hash_enable", "stateless_sg_multi_binding", "stats_data_disable", "substitute_source_mac", "timeout", "traffic_map_type", "ttl_threshold", "use_default_sess_count", "use_https_proxy", "use_mgmt_port", "use_mss_tab", "uuid", "vport_global", "vport_l3v",
    ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'port_scan_detection': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'ping_sweep_detection': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'extended_stats': {
            'type': 'bool',
            },
        'stats_data_disable': {
            'type': 'bool',
            },
        'graceful_shutdown_enable': {
            'type': 'bool',
            },
        'graceful_shutdown': {
            'type': 'int',
            },
        'entity': {
            'type': 'str',
            'choices': ['server', 'virtual-server']
            },
        'after_disable': {
            'type': 'bool',
            },
        'rate_limit_logging': {
            'type': 'bool',
            },
        'max_local_rate': {
            'type': 'int',
            },
        'max_remote_rate': {
            'type': 'int',
            },
        'exclude_destination': {
            'type': 'str',
            'choices': ['local', 'remote']
            },
        'auto_translate_port': {
            'type': 'bool',
            },
        'range': {
            'type': 'int',
            },
        'range_start': {
            'type': 'int',
            },
        'range_end': {
            'type': 'int',
            },
        'use_default_sess_count': {
            'type': 'bool',
            },
        'per_thr_percent': {
            'type': 'int',
            },
        'dsr_health_check_enable': {
            'type': 'bool',
            },
        'one_server_conn_hm_rate': {
            'type': 'int',
            },
        'aflex_table_entry_aging_interval': {
            'type': 'int',
            },
        'aflex_persist_uie_chassis_sync_enable': {
            'type': 'bool',
            },
        'override_port': {
            'type': 'bool',
            },
        'health_check_to_all_vip': {
            'type': 'bool',
            },
        'reset_stale_session': {
            'type': 'bool',
            },
        'dns_negative_cache_enable': {
            'type': 'bool',
            },
        'dns_negative_cache_caching_non_valid': {
            'type': 'bool',
            },
        'dns_cookie_cache_policy': {
            'type': 'str',
            'choices': ['served-by-cache', 'served-by-backend']
            },
        'dns_cache_enable': {
            'type': 'bool',
            },
        'dns_persistent_cache_enable': {
            'type': 'bool',
            },
        'max_persistent_cache': {
            'type': 'int',
            },
        'dns_persistent_cache_ttl_threshold': {
            'type': 'int',
            },
        'dns_persistent_cache_hit_threshold': {
            'type': 'int',
            },
        'dns_cache_ttl_adjustment_enable': {
            'type': 'bool',
            },
        'response_type': {
            'type': 'str',
            'choices': ['single-answer', 'round-robin']
            },
        'ttl_threshold': {
            'type': 'int',
            },
        'dns_cache_aging_weight': {
            'type': 'int',
            },
        'dns_cache_age': {
            'type': 'int',
            },
        'dns_cache_age_min_threshold': {
            'type': 'int',
            },
        'compress_block_size': {
            'type': 'int',
            },
        'dns_cache_entry_size': {
            'type': 'int',
            },
        'dns_cache_sync': {
            'type': 'bool',
            },
        'dns_cache_sync_ttl_threshold': {
            'type': 'int',
            },
        'dns_cache_sync_entry_size': {
            'type': 'int',
            },
        'dns_cache_hitcount_enable': {
            'type': 'bool',
            },
        'dns_vip_stateless': {
            'type': 'bool',
            },
        'honor_server_response_ttl': {
            'type': 'bool',
            },
        'recursive_ns_cache': {
            'type': 'str',
            'choices': ['honor-packet-ttl', 'honor-age-config']
            },
        'buff_thresh': {
            'type': 'bool',
            },
        'buff_thresh_hw_buff': {
            'type': 'int',
            },
        'buff_thresh_relieve_thresh': {
            'type': 'int',
            },
        'buff_thresh_sys_buff_low': {
            'type': 'int',
            },
        'buff_thresh_sys_buff_high': {
            'type': 'int',
            },
        'max_buff_queued_per_conn': {
            'type': 'int',
            },
        'pkt_rate_for_reset_unknown_conn': {
            'type': 'int',
            },
        'log_for_reset_unknown_conn': {
            'type': 'bool',
            },
        'gateway_health_check': {
            'type': 'bool',
            },
        'interval': {
            'type': 'int',
            },
        'timeout': {
            'type': 'int',
            },
        'msl_time': {
            'type': 'int',
            },
        'fast_path_disable': {
            'type': 'bool',
            },
        'odd_even_nat_enable': {
            'type': 'bool',
            },
        'odd_even_nat_one_arm': {
            'type': 'bool',
            },
        'http_fast_enable': {
            'type': 'bool',
            },
        'l2l3_trunk_lb_disable': {
            'type': 'bool',
            },
        'snat_gwy_for_l3': {
            'type': 'bool',
            },
        'allow_in_gateway_mode': {
            'type': 'bool',
            },
        'disable_server_auto_reselect': {
            'type': 'bool',
            },
        'enable_l7_req_acct': {
            'type': 'bool',
            },
        'enable_ddos': {
            'type': 'bool',
            },
        'disable_adaptive_resource_check': {
            'type': 'bool',
            },
        'ddos_pkt_size_thresh': {
            'type': 'int',
            },
        'ddos_pkt_count_thresh': {
            'type': 'int',
            },
        'snat_on_vip': {
            'type': 'bool',
            },
        'low_latency': {
            'type': 'bool',
            },
        'mss_table': {
            'type': 'int',
            },
        'resolve_port_conflict': {
            'type': 'bool',
            },
        'no_auto_up_on_aflex': {
            'type': 'bool',
            },
        'hw_compression': {
            'type': 'bool',
            },
        'hw_syn_rr': {
            'type': 'int',
            },
        'max_http_header_count': {
            'type': 'int',
            },
        'scale_out': {
            'type': 'bool',
            },
        'scale_out_traffic_map': {
            'type': 'bool',
            },
        'show_slb_server_legacy_cmd': {
            'type': 'bool',
            },
        'show_slb_service_group_legacy_cmd': {
            'type': 'bool',
            },
        'show_slb_virtual_server_legacy_cmd': {
            'type': 'bool',
            },
        'traffic_map_type': {
            'type': 'str',
            'choices': ['vport', 'global']
            },
        'sort_res': {
            'type': 'bool',
            },
        'use_mss_tab': {
            'type': 'bool',
            },
        'auto_nat_no_ip_refresh': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'ddos_protection': {
            'type': 'dict',
            'ipd_enable_toggle': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'logging': {
                'type': 'dict',
                'ipd_logging_toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    }
                },
            'packets_per_second': {
                'type': 'dict',
                'ipd_tcp': {
                    'type': 'int',
                    },
                'ipd_udp': {
                    'type': 'int',
                    }
                }
            },
        'ssli_sni_hash_enable': {
            'type': 'bool',
            },
        'clientside_ip': {
            'type': 'str',
            },
        'clientside_ipv6': {
            'type': 'str',
            },
        'serverside_ip': {
            'type': 'str',
            },
        'serverside_ipv6': {
            'type': 'str',
            },
        'port': {
            'type': 'int',
            },
        'ssli_cert_not_ready_inspect_timeout': {
            'type': 'int',
            },
        'ssli_cert_not_ready_inspect_limit': {
            'type': 'int',
            },
        'ssli_silent_termination_enable': {
            'type': 'bool',
            },
        'software': {
            'type': 'bool',
            },
        'software_tls13': {
            'type': 'bool',
            },
        'QAT': {
            'type': 'bool',
            },
        'QAT4': {
            'type': 'bool',
            },
        'N5_new': {
            'type': 'bool',
            },
        'N5_old': {
            'type': 'bool',
            },
        'software_tls13_offload': {
            'type': 'bool',
            },
        'ssl_n5_delay_tx_enable': {
            'type': 'bool',
            },
        'ssl_ratelimit_cfg': {
            'type': 'dict',
            'disable_rate': {
                'type': 'bool',
                },
            'tls12_rate': {
                'type': 'int',
                },
            'tls13_rate': {
                'type': 'int',
                }
            },
        'ssl_module_usage_enable': {
            'type': 'bool',
            },
        'substitute_source_mac': {
            'type': 'bool',
            },
        'drop_icmp_to_vip_when_vip_down': {
            'type': 'bool',
            },
        'player_id_check_enable': {
            'type': 'bool',
            },
        'stateless_sg_multi_binding': {
            'type': 'bool',
            },
        'ecmp_hash': {
            'type': 'str',
            'choices': ['system-default', 'connection-based']
            },
        'vport_global': {
            'type': 'int',
            },
        'vport_l3v': {
            'type': 'int',
            },
        'service_group_on_no_dest_nat_vports': {
            'type': 'str',
            'choices': ['allow-same', 'enforce-different']
            },
        'disable_port_masking': {
            'type': 'bool',
            },
        'snat_preserve': {
            'type': 'dict',
            'range': {
                'type': 'list',
                'port1': {
                    'type': 'int',
                    },
                'port2': {
                    'type': 'int',
                    }
                }
            },
        'disable_persist_scoring': {
            'type': 'bool',
            },
        'ipv4_offset': {
            'type': 'int',
            },
        'ipv6_subnet': {
            'type': 'int',
            },
        'pbslb_entry_age': {
            'type': 'int',
            },
        'pbslb_overflow_glid': {
            'type': 'str',
            },
        'pre_process_enable': {
            'type': 'bool',
            },
        'cache_expire_time': {
            'type': 'int',
            },
        'attack_resp_code': {
            'type': 'int',
            },
        'monitor_mode_enable': {
            'type': 'bool',
            },
        'custom_signal_clist': {
            'type': 'str',
            },
        'custom_message': {
            'type': 'str',
            },
        'custom_page': {
            'type': 'str',
            },
        'use_https_proxy': {
            'type': 'bool',
            },
        'ngwaf_proxy_ipv4': {
            'type': 'str',
            },
        'ngwaf_proxy_ipv6': {
            'type': 'str',
            },
        'ngwaf_proxy_port': {
            'type': 'int',
            },
        'use_mgmt_port': {
            'type': 'bool',
            },
        'enable_fast_path_rerouting': {
            'type': 'bool',
            },
        'cancel_stream_loop_limit': {
            'type': 'int',
            },
        'redirect_dummy_ethernet': {
            'type': 'str',
            },
        'redirect_dummy_vlan': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'cert_pinning': {
            'type': 'dict',
            'ttl': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'candidate_list_feedback_opt_in': {
                'type': 'dict',
                'enable': {
                    'type': 'bool',
                    },
                'schedule': {
                    'type': 'bool',
                    },
                'weekly': {
                    'type': 'bool',
                    },
                'week_day': {
                    'type': 'str',
                    'choices': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                    },
                'week_time': {
                    'type': 'str',
                    },
                'daily': {
                    'type': 'bool',
                    },
                'day_time': {
                    'type': 'str',
                    },
                'use_mgmt_port': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aflex_table_entry_sync': {
            'type': 'dict',
            'aflex_table_entry_sync_enable': {
                'type': 'bool',
                },
            'aflex_table_entry_sync_max_key_len': {
                'type': 'int',
                },
            'aflex_table_entry_sync_max_value_len': {
                'type': 'int',
                },
            'aflex_table_entry_sync_min_lifetime': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'quic': {
            'type': 'dict',
            'cid_len': {
                'type': 'int',
                },
            'signature': {
                'type': 'str',
                },
            'signature_len': {
                'type': 'int',
                },
            'signature_offset': {
                'type': 'int',
                },
            'cpu_offset': {
                'type': 'int',
                },
            'quic_lb_offset': {
                'type': 'int',
                },
            'enable_hash': {
                'type': 'bool',
                },
            'enable_signature': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'conn_rate_limit': {
            'type': 'dict',
            'src_ip_list': {
                'type': 'list',
                'disable_ipv6_support': {
                    'type': 'bool',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                    },
                'limit': {
                    'type': 'int',
                    },
                'limit_period': {
                    'type': 'str',
                    'choices': ['100', '1000']
                    },
                'shared': {
                    'type': 'bool',
                    },
                'exceed_action': {
                    'type': 'bool',
                    },
                'log': {
                    'type': 'bool',
                    },
                'lock_out': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'dns_response_rate_limiting': {
            'type': 'dict',
            'max_table_entries': {
                'type': 'int',
                },
            'source_entry_age': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'global_dns_cache': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'class_list': {
                'type': 'dict',
                'name': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'lid_list': {
                    'type': 'list',
                    'lidnum': {
                        'type': 'int',
                        'required': True,
                        },
                    'conn_rate_limit': {
                        'type': 'int',
                        },
                    'per': {
                        'type': 'int',
                        },
                    'over_limit_action': {
                        'type': 'str',
                        'choices': ['ignore', 'drop']
                        },
                    'lockout': {
                        'type': 'int',
                        },
                    'log': {
                        'type': 'bool',
                        },
                    'log_interval': {
                        'type': 'int',
                        },
                    'dns': {
                        'type': 'dict',
                        'cache_action': {
                            'type': 'str',
                            'choices': ['cache-disable', 'cache-enable']
                            },
                        'ttl': {
                            'type': 'int',
                            },
                        'weight': {
                            'type': 'int',
                            },
                        'honor_server_response_ttl': {
                            'type': 'bool',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'server_auto_reselect': {
                'type': 'int',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/common"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/common"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["common"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["common"].get(k) != v:
            change_results["changed"] = True
            config_changes["common"][k] = v

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
    payload = utils.build_json("common", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
            existing_config = api_client.get(module.client, existing_url(module))
            result["axapi_calls"].append(existing_config)
            if existing_config['response_body'] != 'NotFound':
                existing_config = existing_config["response_body"]
            else:
                existing_config = None
        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["common"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["common-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["common"]["oper"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
