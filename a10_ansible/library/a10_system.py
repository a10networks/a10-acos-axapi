#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_system
description:
    - Configure System Parameters
short_description: Configures A10 system
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
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    mgmt_port:
        description:
        - "Field mgmt_port"
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
            pci_address:
                description:
                - "pci-address to be configured as mgmt port"
            mac_address:
                description:
                - "mac-address to be configured as mgmt port"
    resource_accounting:
        description:
        - "Field resource_accounting"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            template_list:
                description:
                - "Field template_list"
    promiscuous_mode:
        description:
        - "Run in promiscous mode settings"
        required: False
    inuse_port_list:
        description:
        - "Field inuse_port_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    control_cpu:
        description:
        - "Field control_cpu"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    tcp:
        description:
        - "Field tcp"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    module_ctrl_cpu:
        description:
        - "'high'= high cpu usage; 'low'= low cpu usage; 'medium'= medium cpu usage; "
        required: False
    bandwidth:
        description:
        - "Field bandwidth"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    session:
        description:
        - "Field session"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    modify_port:
        description:
        - "Field modify_port"
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
            port_number:
                description:
                - "port number to be configured (Specify port number)"
    all_vlan_limit:
        description:
        - "Field all_vlan_limit"
        required: False
        suboptions:
            unknown_ucast:
                description:
                - "unknown unicast packets (per second limit)"
            bcast:
                description:
                - "broadcast packets (per second limit)"
            mcast:
                description:
                - "multicast packets (per second limit)"
            ipmcast:
                description:
                - "IP multicast packets (per second limit)"
            uuid:
                description:
                - "uuid of the object"
    cpu_list:
        description:
        - "Field cpu_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    del_port:
        description:
        - "Field del_port"
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
    resource_usage:
        description:
        - "Field resource_usage"
        required: False
        suboptions:
            nat_pool_addr_count:
                description:
                - "Total configurable NAT Pool addresses in the System"
            max_aflex_authz_collection_number:
                description:
                - "Specify the maximum number of collections supported by aFleX authorization"
            class_list_ipv6_addr_count:
                description:
                - "Total IPv6 addresses for class-list"
            max_aflex_file_size:
                description:
                - "Set maximum aFleX file size (Maximum file size in KBytes, default is 32K)"
            class_list_ac_entry_count:
                description:
                - "Total entries for AC class-list"
            l4_session_count:
                description:
                - "Total Sessions in the System"
            aflex_table_entry_count:
                description:
                - "Total aFleX table entry in the system (Total aFlex entry in the system)"
            ssl_context_memory:
                description:
                - "Total SSL context memory needed in units of MB. Will be rounded to closest multiple of 2MB"
            auth_portal_html_file_size:
                description:
                - "Specify maximum html file size for each html page in auth portal (in KB)"
            auth_portal_image_file_size:
                description:
                - "Specify maximum image file size for default portal (in KB)"
            uuid:
                description:
                - "uuid of the object"
    session_reclaim_limit:
        description:
        - "Field session_reclaim_limit"
        required: False
        suboptions:
            scan_freq:
                description:
                - "smp session scan frequency (scan per second)"
            nscan_limit:
                description:
                - "smp session scan limit (number of smp sessions per scan)"
            uuid:
                description:
                - "uuid of the object"
    inuse_cpu_list:
        description:
        - "Field inuse_cpu_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    add_port:
        description:
        - "Field add_port"
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
    ip6_stats:
        description:
        - "Field ip6_stats"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    attack_log:
        description:
        - "log attack anomalies"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    cots_environment:
        description:
        - "Field cots_environment"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    icmp_rate:
        description:
        - "Field icmp_rate"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    ddos_attack:
        description:
        - "System DDoS Attack"
        required: False
    trunk_xaui_hw_hash:
        description:
        - "Field trunk_xaui_hw_hash"
        required: False
        suboptions:
            mode:
                description:
                - "Set HW hash mode, default is 6 (1=dst-mac 2=src-mac 3=src-dst-mac 4=src-ip 5=dst-ip 6=rtag6 7=rtag7)"
            uuid:
                description:
                - "uuid of the object"
    cpu_load_sharing:
        description:
        - "Field cpu_load_sharing"
        required: False
        suboptions:
            packets_per_second:
                description:
                - "Field packets_per_second"
            cpu_usage:
                description:
                - "Field cpu_usage"
            disable:
                description:
                - "Disable CPU load sharing in overload situations"
            uuid:
                description:
                - "uuid of the object"
    ip_stats:
        description:
        - "Field ip_stats"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    environment:
        description:
        - "Field environment"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    attack:
        description:
        - "System Attack"
        required: False
    cots_environment_power:
        description:
        - "Field cots_environment_power"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            template_policy:
                description:
                - "Apply policy template to the whole system (Policy template name)"
            uuid:
                description:
                - "uuid of the object"
    port_info:
        description:
        - "Field port_info"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    anomaly_log:
        description:
        - "log system anomalies"
        required: False
    queuing_buffer:
        description:
        - "Field queuing_buffer"
        required: False
        suboptions:
            enable:
                description:
                - "Enable/Disable micro-burst traffic support"
            uuid:
                description:
                - "uuid of the object"
    ipmi_service:
        description:
        - "Field ipmi_service"
        required: False
        suboptions:
            disable:
                description:
                - "Disable IPMI on platform"
            uuid:
                description:
                - "uuid of the object"
    cpu_hyper_thread:
        description:
        - "Field cpu_hyper_thread"
        required: False
        suboptions:
            enable:
                description:
                - "Enable CPU Hyperthreading"
            disable:
                description:
                - "Disable CPU Hyperthreading"
    data_cpu:
        description:
        - "Field data_cpu"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    ddos_log:
        description:
        - "log DDoS attack anomalies"
        required: False
    trunk_hw_hash:
        description:
        - "Field trunk_hw_hash"
        required: False
        suboptions:
            mode:
                description:
                - "Set HW hash mode, default is 6 (1=dst-mac 2=src-mac 3=src-dst-mac 4=src-ip 5=dst-ip 6=rtag6 7=rtag7)"
            uuid:
                description:
                - "uuid of the object"
    ve_mac_scheme:
        description:
        - "Field ve_mac_scheme"
        required: False
        suboptions:
            ve_mac_scheme_val:
                description:
                - "'hash-based'= Hash-based using the VE number; 'round-robin'= Round Robin scheme; 'system-mac'= Use system MAC address; "
            uuid:
                description:
                - "uuid of the object"
    glid:
        description:
        - "Apply limits to the whole system"
        required: False
    template_bind:
        description:
        - "Field template_bind"
        required: False
        suboptions:
            monitor_list:
                description:
                - "Field monitor_list"
    ipmi:
        description:
        - "Field ipmi"
        required: False
        suboptions:
            reset:
                description:
                - "Reset IPMI Controller"
            ip:
                description:
                - "Field ip"
            ipsrc:
                description:
                - "Field ipsrc"
            tool:
                description:
                - "Field tool"
            user:
                description:
                - "Field user"
    memory:
        description:
        - "Field memory"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    ndisc_ra:
        description:
        - "Field ndisc_ra"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    add_cpu_core:
        description:
        - "Field add_cpu_core"
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be added (Specify core index)"
    trunk:
        description:
        - "Field trunk"
        required: False
        suboptions:
            load_balance:
                description:
                - "Field load_balance"
    telemetry_log:
        description:
        - "Field telemetry_log"
        required: False
        suboptions:
            device_status:
                description:
                - "Field device_status"
            partition_metrics:
                description:
                - "Field partition_metrics"
    ipsec:
        description:
        - "Field ipsec"
        required: False
        suboptions:
            packet_round_robin:
                description:
                - "Enable packet round robin for IPsec packets"
            crypto_core:
                description:
                - "Crypto cores assigned for IPsec processing"
            uuid:
                description:
                - "uuid of the object"
            fpga_decrypt:
                description:
                - "Field fpga_decrypt"
            crypto_mem:
                description:
                - "Crypto memory percentage assigned for IPsec processing (rounded to increments of 10)"
    icmp:
        description:
        - "Field icmp"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    per_vlan_limit:
        description:
        - "Field per_vlan_limit"
        required: False
        suboptions:
            unknown_ucast:
                description:
                - "unknown unicast packets (per second limit)"
            bcast:
                description:
                - "broadcast packets (per second limit)"
            mcast:
                description:
                - "multicast packets (per second limit)"
            ipmcast:
                description:
                - "IP multicast packets (per second limit)"
            uuid:
                description:
                - "uuid of the object"
    guest_file:
        description:
        - "Field guest_file"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    hardware:
        description:
        - "Field hardware"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    upgrade_status:
        description:
        - "Field upgrade_status"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    cpu_map:
        description:
        - "Field cpu_map"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    bfd:
        description:
        - "Field bfd"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    sockstress_disable:
        description:
        - "Disable sockstress protection"
        required: False
    icmp6:
        description:
        - "Field icmp6"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    delete_cpu_core:
        description:
        - "Field delete_cpu_core"
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be deleted (Specify core index)"
    log_cpu_interval:
        description:
        - "Log high CPU interval (Specify consecutive seconds before logging high CPU)"
        required: False
    throughput:
        description:
        - "Field throughput"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    shell_privileges:
        description:
        - "Field shell_privileges"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    io_cpu:
        description:
        - "Field io_cpu"
        required: False
        suboptions:
            max_cores:
                description:
                - "max number of IO cores (Specify number of cores)"
    tcp_stats:
        description:
        - "Field tcp_stats"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    cm_update_file_name_ref:
        description:
        - "Field cm_update_file_name_ref"
        required: False
        suboptions:
            source_name:
                description:
                - "bind source name"
            id:
                description:
                - "Specify unique Partition id"
            dest_name:
                description:
                - "bind dest name"
    platformtype:
        description:
        - "Field platformtype"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["add_cpu_core","add_port","all_vlan_limit","anomaly_log","attack","attack_log","bandwidth","bfd","cm_update_file_name_ref","control_cpu","cots_environment","cots_environment_power","cpu_hyper_thread","cpu_list","cpu_load_sharing","cpu_map","data_cpu","ddos_attack","ddos_log","del_port","delete_cpu_core","environment","glid","guest_file","hardware","icmp","icmp_rate","icmp6","inuse_cpu_list","inuse_port_list","io_cpu","ip_stats","ip6_stats","ipmi","ipmi_service","ipsec","log_cpu_interval","memory","mgmt_port","modify_port","module_ctrl_cpu","ndisc_ra","per_vlan_limit","platformtype","port_info","port_list","promiscuous_mode","queuing_buffer","resource_accounting","resource_usage","session","session_reclaim_limit","shell_privileges","sockstress_disable","tcp","tcp_stats","telemetry_log","template","template_bind","throughput","trunk","trunk_hw_hash","trunk_xaui_hw_hash","upgrade_status","uuid","ve_mac_scheme",]

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
        port_list=dict(type='dict',uuid=dict(type='str',)),
        mgmt_port=dict(type='dict',port_index=dict(type='int',),pci_address=dict(type='str',),mac_address=dict(type='str',)),
        resource_accounting=dict(type='dict',uuid=dict(type='str',),template_list=dict(type='list',app_resources=dict(type='dict',gslb_site_cfg=dict(type='dict',gslb_site_min_guarantee=dict(type='int',),gslb_site_max=dict(type='int',)),gslb_policy_cfg=dict(type='dict',gslb_policy_min_guarantee=dict(type='int',),gslb_policy_max=dict(type='int',)),gslb_service_cfg=dict(type='dict',gslb_service_min_guarantee=dict(type='int',),gslb_service_max=dict(type='int',)),gslb_geo_location_cfg=dict(type='dict',gslb_geo_location_max=dict(type='int',),gslb_geo_location_min_guarantee=dict(type='int',)),uuid=dict(type='str',),real_server_cfg=dict(type='dict',real_server_max=dict(type='int',),real_server_min_guarantee=dict(type='int',)),gslb_ip_list_cfg=dict(type='dict',gslb_ip_list_max=dict(type='int',),gslb_ip_list_min_guarantee=dict(type='int',)),gslb_template_cfg=dict(type='dict',gslb_template_max=dict(type='int',),gslb_template_min_guarantee=dict(type='int',)),gslb_zone_cfg=dict(type='dict',gslb_zone_min_guarantee=dict(type='int',),gslb_zone_max=dict(type='int',)),gslb_device_cfg=dict(type='dict',gslb_device_min_guarantee=dict(type='int',),gslb_device_max=dict(type='int',)),virtual_server_cfg=dict(type='dict',virtual_server_max=dict(type='int',),virtual_server_min_guarantee=dict(type='int',)),real_port_cfg=dict(type='dict',real_port_min_guarantee=dict(type='int',),real_port_max=dict(type='int',)),health_monitor_cfg=dict(type='dict',health_monitor_max=dict(type='int',),health_monitor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),gslb_svc_group_cfg=dict(type='dict',gslb_svc_group_max=dict(type='int',),gslb_svc_group_min_guarantee=dict(type='int',)),service_group_cfg=dict(type='dict',service_group_max=dict(type='int',),service_group_min_guarantee=dict(type='int',)),gslb_service_port_cfg=dict(type='dict',gslb_service_port_max=dict(type='int',),gslb_service_port_min_guarantee=dict(type='int',)),gslb_service_ip_cfg=dict(type='dict',gslb_service_ip_max=dict(type='int',),gslb_service_ip_min_guarantee=dict(type='int',))),name=dict(type='str',required=True,),system_resources=dict(type='dict',l4_session_limit_cfg=dict(type='dict',l4_session_limit_max=dict(type='str',),l4_session_limit_min_guarantee=dict(type='str',)),l7cps_limit_cfg=dict(type='dict',l7cps_limit_max=dict(type='int',)),l4cps_limit_cfg=dict(type='dict',l4cps_limit_max=dict(type='int',)),uuid=dict(type='str',),natcps_limit_cfg=dict(type='dict',natcps_limit_max=dict(type='int',)),sslcps_limit_cfg=dict(type='dict',sslcps_limit_max=dict(type='int',)),fwcps_limit_cfg=dict(type='dict',fwcps_limit_max=dict(type='int',)),ssl_throughput_limit_cfg=dict(type='dict',ssl_throughput_limit_watermark_disable=dict(type='bool',),ssl_throughput_limit_max=dict(type='int',)),threshold=dict(type='int',),bw_limit_cfg=dict(type='dict',bw_limit_max=dict(type='int',),bw_limit_watermark_disable=dict(type='bool',)),concurrent_session_limit_cfg=dict(type='dict',concurrent_session_limit_max=dict(type='int',))),user_tag=dict(type='str',),network_resources=dict(type='dict',static_ipv6_route_cfg=dict(type='dict',static_ipv6_route_max=dict(type='int',),static_ipv6_route_min_guarantee=dict(type='int',)),uuid=dict(type='str',),ipv4_acl_line_cfg=dict(type='dict',ipv4_acl_line_min_guarantee=dict(type='int',),ipv4_acl_line_max=dict(type='int',)),static_ipv4_route_cfg=dict(type='dict',static_ipv4_route_max=dict(type='int',),static_ipv4_route_min_guarantee=dict(type='int',)),static_arp_cfg=dict(type='dict',static_arp_min_guarantee=dict(type='int',),static_arp_max=dict(type='int',)),object_group_clause_cfg=dict(type='dict',object_group_clause_min_guarantee=dict(type='int',),object_group_clause_max=dict(type='int',)),static_mac_cfg=dict(type='dict',static_mac_min_guarantee=dict(type='int',),static_mac_max=dict(type='int',)),object_group_cfg=dict(type='dict',object_group_min_guarantee=dict(type='int',),object_group_max=dict(type='int',)),static_neighbor_cfg=dict(type='dict',static_neighbor_max=dict(type='int',),static_neighbor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),ipv6_acl_line_cfg=dict(type='dict',ipv6_acl_line_max=dict(type='int',),ipv6_acl_line_min_guarantee=dict(type='int',))),uuid=dict(type='str',))),
        promiscuous_mode=dict(type='bool',),
        inuse_port_list=dict(type='dict',uuid=dict(type='str',)),
        control_cpu=dict(type='dict',uuid=dict(type='str',)),
        tcp=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','activeopens','passiveopens','attemptfails','estabresets','insegs','outsegs','retranssegs','inerrs','outrsts','sock_alloc','orphan_count','mem_alloc','recv_mem','send_mem','currestab','currsyssnt','currsynrcv','currfinw1','currfinw2','currtimew','currclose','currclsw','currlack','currlstn','currclsg','pawsactiverejected','syn_rcv_rstack','syn_rcv_rst','syn_rcv_ack','ax_rexmit_syn','tcpabortontimeout','noroute','exceedmss'])),uuid=dict(type='str',)),
        module_ctrl_cpu=dict(type='str',choices=['high','low','medium']),
        bandwidth=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','input-bytes-per-sec','output-bytes-per-sec'])),uuid=dict(type='str',)),
        session=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_l4_conn','conn_counter','conn_freed_counter','total_l4_packet_count','total_l7_packet_count','total_l4_conn_proxy','total_l7_conn','total_tcp_conn','curr_free_conn','tcp_est_counter','tcp_half_open_counter','tcp_half_close_counter','udp_counter','ip_counter','other_counter','reverse_nat_tcp_counter','reverse_nat_udp_counter','tcp_syn_half_open_counter','conn_smp_alloc_counter','conn_smp_free_counter','conn_smp_aged_counter','ssl_count_curr','ssl_count_total','server_ssl_count_curr','server_ssl_count_total','client_ssl_reuse_total','server_ssl_reuse_total','ssl_failed_total','ssl_failed_ca_verification','ssl_server_cert_error','ssl_client_cert_auth_fail','total_ip_nat_conn','total_l2l3_conn','client_ssl_ctx_malloc_failure','conn_type_0_available','conn_type_1_available','conn_type_2_available','conn_type_3_available','conn_type_4_available','conn_smp_type_0_available','conn_smp_type_1_available','conn_smp_type_2_available','conn_smp_type_3_available','conn_smp_type_4_available','sctp-half-open-counter','sctp-est-counter','nonssl_bypass','ssl_failsafe_total','ssl_forward_proxy_failed_handshake_total','ssl_forward_proxy_failed_tcp_total','ssl_forward_proxy_failed_crypto_total','ssl_forward_proxy_failed_cert_verify_total','ssl_forward_proxy_invalid_ocsp_stapling_total','ssl_forward_proxy_revoked_ocsp_total','ssl_forward_proxy_failed_cert_signing_total','ssl_forward_proxy_failed_ssl_version_total','ssl_forward_proxy_sni_bypass_total','ssl_forward_proxy_client_auth_bypass_total','conn_app_smp_alloc_counter','diameter_conn_counter','diameter_conn_freed_counter','debug_tcp_counter','debug_udp_counter','total_fw_conn','ssl_forward_proxy_failed_aflex_total','ssl_forward_proxy_cert_subject_bypass_total','ssl_forward_proxy_cert_issuer_bypass_total'])),uuid=dict(type='str',)),
        modify_port=dict(type='dict',port_index=dict(type='int',),port_number=dict(type='int',)),
        all_vlan_limit=dict(type='dict',unknown_ucast=dict(type='int',),bcast=dict(type='int',),mcast=dict(type='int',),ipmcast=dict(type='int',),uuid=dict(type='str',)),
        cpu_list=dict(type='dict',uuid=dict(type='str',)),
        del_port=dict(type='dict',port_index=dict(type='int',)),
        resource_usage=dict(type='dict',nat_pool_addr_count=dict(type='int',),max_aflex_authz_collection_number=dict(type='int',),class_list_ipv6_addr_count=dict(type='int',),max_aflex_file_size=dict(type='int',),class_list_ac_entry_count=dict(type='int',),l4_session_count=dict(type='int',),aflex_table_entry_count=dict(type='int',),ssl_context_memory=dict(type='int',),auth_portal_html_file_size=dict(type='int',),auth_portal_image_file_size=dict(type='int',),uuid=dict(type='str',)),
        session_reclaim_limit=dict(type='dict',scan_freq=dict(type='int',),nscan_limit=dict(type='int',),uuid=dict(type='str',)),
        inuse_cpu_list=dict(type='dict',uuid=dict(type='str',)),
        add_port=dict(type='dict',port_index=dict(type='int',)),
        ip6_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inreceives','inhdrerrors','intoobigerrors','innoroutes','inaddrerrors','inunknownprotos','intruncatedpkts','indiscards','indelivers','outforwdatagrams','outrequests','outdiscards','outnoroutes','reasmtimeout','reasmreqds','reasmoks','reasmfails','fragoks','fragfails','fragcreates','inmcastpkts','outmcastpkts'])),uuid=dict(type='str',)),
        attack_log=dict(type='bool',),
        uuid=dict(type='str',),
        cots_environment=dict(type='dict',uuid=dict(type='str',)),
        icmp_rate=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','over_limit_drop','limit_intf_drop','limit_vserver_drop','limit_total_drop','lockup_time_left','curr_rate','v6_over_limit_drop','v6_limit_intf_drop','v6_limit_vserver_drop','v6_limit_total_drop','v6_lockup_time_left','v6_curr_rate'])),uuid=dict(type='str',)),
        ddos_attack=dict(type='bool',),
        trunk_xaui_hw_hash=dict(type='dict',mode=dict(type='int',),uuid=dict(type='str',)),
        cpu_load_sharing=dict(type='dict',packets_per_second=dict(type='dict',min=dict(type='int',)),cpu_usage=dict(type='dict',high=dict(type='int',),low=dict(type='int',)),disable=dict(type='bool',),uuid=dict(type='str',)),
        ip_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inreceives','inhdrerrors','intoobigerrors','innoroutes','inaddrerrors','inunknownprotos','intruncatedpkts','indiscards','indelivers','outforwdatagrams','outrequests','outdiscards','outnoroutes','reasmtimeout','reasmreqds','reasmoks','reasmfails','fragoks','fragfails','fragcreates','inmcastpkts','outmcastpkts'])),uuid=dict(type='str',)),
        environment=dict(type='dict',uuid=dict(type='str',)),
        attack=dict(type='bool',),
        cots_environment_power=dict(type='dict',uuid=dict(type='str',)),
        template=dict(type='dict',template_policy=dict(type='str',),uuid=dict(type='str',)),
        port_info=dict(type='dict',uuid=dict(type='str',)),
        anomaly_log=dict(type='bool',),
        queuing_buffer=dict(type='dict',enable=dict(type='bool',),uuid=dict(type='str',)),
        ipmi_service=dict(type='dict',disable=dict(type='bool',),uuid=dict(type='str',)),
        cpu_hyper_thread=dict(type='dict',enable=dict(type='bool',),disable=dict(type='bool',)),
        data_cpu=dict(type='dict',uuid=dict(type='str',)),
        ddos_log=dict(type='bool',),
        trunk_hw_hash=dict(type='dict',mode=dict(type='int',),uuid=dict(type='str',)),
        ve_mac_scheme=dict(type='dict',ve_mac_scheme_val=dict(type='str',choices=['hash-based','round-robin','system-mac']),uuid=dict(type='str',)),
        glid=dict(type='int',),
        template_bind=dict(type='dict',monitor_list=dict(type='list',template_monitor=dict(type='int',required=True,),uuid=dict(type='str',))),
        ipmi=dict(type='dict',reset=dict(type='bool',),ip=dict(type='dict',ipv4_address=dict(type='str',),default_gateway=dict(type='str',),ipv4_netmask=dict(type='str',)),ipsrc=dict(type='dict',dhcp=dict(type='bool',),static=dict(type='bool',)),tool=dict(type='dict',cmd=dict(type='str',)),user=dict(type='dict',administrator=dict(type='bool',),setname=dict(type='str',),newname=dict(type='str',),newpass=dict(type='str',),callback=dict(type='bool',),add=dict(type='str',),disable=dict(type='str',),setpass=dict(type='str',),user=dict(type='bool',),operator=dict(type='bool',),password=dict(type='str',),privilege=dict(type='str',))),
        memory=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','usage-percentage'])),uuid=dict(type='str',)),
        ndisc_ra=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','good_recv','periodic_sent','rate_limit','bad_hop_limit','truncated','bad_icmpv6_csum','bad_icmpv6_code','bad_icmpv6_option','l2_addr_and_unspec','no_free_buffers'])),uuid=dict(type='str',)),
        add_cpu_core=dict(type='dict',core_index=dict(type='int',)),
        trunk=dict(type='dict',load_balance=dict(type='dict',use_l4=dict(type='bool',),uuid=dict(type='str',),use_l3=dict(type='bool',))),
        telemetry_log=dict(type='dict',device_status=dict(type='dict',uuid=dict(type='str',)),partition_metrics=dict(type='dict',uuid=dict(type='str',))),
        ipsec=dict(type='dict',packet_round_robin=dict(type='bool',),crypto_core=dict(type='int',),uuid=dict(type='str',),fpga_decrypt=dict(type='dict',action=dict(type='str',choices=['enable','disable'])),crypto_mem=dict(type='int',)),
        icmp=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','inmsgs','inerrors','indestunreachs','intimeexcds','inparmprobs','insrcquenchs','inredirects','inechos','inechoreps','intimestamps','intimestampreps','inaddrmasks','inaddrmaskreps','outmsgs','outerrors','outdestunreachs','outtimeexcds','outparmprobs','outsrcquenchs','outredirects','outechos','outechoreps','outtimestamps','outtimestampreps','outaddrmasks','outaddrmaskreps'])),uuid=dict(type='str',)),
        per_vlan_limit=dict(type='dict',unknown_ucast=dict(type='int',),bcast=dict(type='int',),mcast=dict(type='int',),ipmcast=dict(type='int',),uuid=dict(type='str',)),
        guest_file=dict(type='dict',uuid=dict(type='str',)),
        hardware=dict(type='dict',uuid=dict(type='str',)),
        upgrade_status=dict(type='dict',uuid=dict(type='str',)),
        cpu_map=dict(type='dict',uuid=dict(type='str',)),
        bfd=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','ip_checksum_error','udp_checksum_error','session_not_found','multihop_mismatch','version_mismatch','length_too_small','data_is_short','invalid_detect_mult','invalid_multipoint','invalid_my_disc','invalid_ttl','auth_length_invalid','auth_mismatch','auth_type_mismatch','auth_key_id_mismatch','auth_key_mismatch','auth_seqnum_invalid','auth_failed','local_state_admin_down','dest_unreachable','other_error'])),uuid=dict(type='str',)),
        sockstress_disable=dict(type='bool',),
        icmp6=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','in_msgs','in_errors','in_dest_un_reach','in_pkt_too_big','in_time_exceeds','in_param_prob','in_echoes','in_exho_reply','in_grp_mem_query','in_grp_mem_resp','in_grp_mem_reduction','in_router_sol','in_ra','in_ns','in_na','in_redirect','out_msg','out_dst_un_reach','out_pkt_too_big','out_time_exceeds','out_param_prob','out_echo_req','out_echo_replies','out_rs','out_ra','out_ns','out_na','out_redirects','out_mem_resp','out_mem_reductions','err_rs','err_ra','err_ns','err_na','err_redirects','err_echoes','err_echo_replies'])),uuid=dict(type='str',)),
        delete_cpu_core=dict(type='dict',core_index=dict(type='int',)),
        log_cpu_interval=dict(type='int',),
        throughput=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','global-system-throughput-bits-per-sec','per-part-throughput-bits-per-sec'])),uuid=dict(type='str',)),
        shell_privileges=dict(type='dict',uuid=dict(type='str',)),
        io_cpu=dict(type='dict',max_cores=dict(type='int',)),
        tcp_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','connattempt','connects','drops','conndrops','closed','segstimed','rttupdated','delack','timeoutdrop','rexmttimeo','persisttimeo','keeptimeo','keepprobe','keepdrops','sndtotal','sndpack','sndbyte','sndrexmitpack','sndrexmitbyte','sndrexmitbad','sndacks','sndprobe','sndurg','sndwinup','sndctrl','sndrst','sndfin','sndsyn','rcvtotal','rcvpack','rcvbyte','rcvbadoff','rcvmemdrop','rcvshort','rcvduppack','rcvdupbyte','rcvpartduppack','rcvpartdupbyte','rcvoopack','rcvoobyte','rcvpackafterwin','rcvbyteafterwin','rcvwinprobe','rcvdupack','rcvacktoomuch','rcvackpack','rcvackbyte','rcvwinupd','pawsdrop','predack','preddat','persistdrop','mturesent','badrst','finwait2_drops','sack_recovery_episode','sack_rexmits','sack_rexmit_bytes','sack_rcv_blocks','sack_send_blocks','ecn_shs','ecn_rcwnd','sndcack','cacklim','bad_iochan'])),uuid=dict(type='str',)),
        cm_update_file_name_ref=dict(type='dict',source_name=dict(type='str',),id=dict(type='int',),dest_name=dict(type='str',)),
        platformtype=dict(type='dict',uuid=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system"

    f_dict = {}

    return url_base.format(**f_dict)

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["system"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["system"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["system"][k] = v
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
    payload = build_json("system", module)
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