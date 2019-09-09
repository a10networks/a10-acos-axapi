#!/usr/bin/python

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
    partition:
        description:
        - Destination/target partition for object/command
    geo_location:
        description:
        - "Field geo_location"
        required: False
        suboptions:
            geolite2_city_include_ipv6:
                description:
                - "Include IPv6 address"
            geolite2_country_include_ipv6:
                description:
                - "Include IPv6 address"
            geo_location_geolite2_country:
                description:
                - "Load built-in Maxmind GeoLite2-Country database. Database available from http=//www.maxmind.com"
            entry_list:
                description:
                - "Field entry_list"
            geo_location_geolite2_city:
                description:
                - "Load built-in Maxmind GeoLite2-City database. Database available from http=//www.maxmind.com"
            geoloc_load_file_list:
                description:
                - "Field geoloc_load_file_list"
            geo_location_iana:
                description:
                - "Load built-in IANA Database"
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
    geolocation_file:
        description:
        - "Field geolocation_file"
        required: False
        suboptions:
            error_info:
                description:
                - "Field error_info"
            uuid:
                description:
                - "uuid of the object"
    promiscuous_mode:
        description:
        - "Run in promiscous mode settings"
        required: False
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
    uuid:
        description:
        - "uuid of the object"
        required: False
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
    environment:
        description:
        - "Field environment"
        required: False
        suboptions:
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
    telemetry_log:
        description:
        - "Field telemetry_log"
        required: False
        suboptions:
            device_status:
                description:
                - "Field device_status"
            top_k_source_list:
                description:
                - "Field top_k_source_list"
            top_k_app_svc_list:
                description:
                - "Field top_k_app_svc_list"
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
    hrxq_status:
        description:
        - "Field hrxq_status"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    cosq_stats:
        description:
        - "Field cosq_stats"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    sockstress_disable:
        description:
        - "Disable sockstress protection"
        required: False
    io_cpu:
        description:
        - "Field io_cpu"
        required: False
        suboptions:
            max_cores:
                description:
                - "max number of IO cores (Specify number of cores)"
    cpu_map:
        description:
        - "Field cpu_map"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    ports:
        description:
        - "Field ports"
        required: False
        suboptions:
            link_detection_interval:
                description:
                - "Link detection interval in msecs"
            uuid:
                description:
                - "uuid of the object"
    app_performance:
        description:
        - "Field app_performance"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    counter_lib_accounting:
        description:
        - "Field counter_lib_accounting"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
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
    password_policy:
        description:
        - "Field password_policy"
        required: False
        suboptions:
            aging:
                description:
                - "'Strict'= Strict= Max Age-60 Days; 'Medium'= Medium= Max Age- 90 Days; 'Simple'= Simple= Max Age-120 Days; "
            complexity:
                description:
                - "'Strict'= Strict= Min length=8, Min Lower Case=2, Min Upper Case=2, Min Numbers=2, Min Special Character=1; 'Medium'= Medium= Min length=6, Min Lower Case=2, Min Upper Case=2, Min Numbers=1, Min Special Character=1; 'Simple'= Simple= Min length=4, Min Lower Case=1, Min Upper Case=1, Min Numbers=1, Min Special Character=0; "
            history:
                description:
                - "'Strict'= Strict= Does not allow upto 5 old passwords; 'Medium'= Medium= Does not allow upto 4 old passwords; 'Simple'= Simple= Does not allow upto 3 old passwords; "
            uuid:
                description:
                - "uuid of the object"
            min_pswd_len:
                description:
                - "Configure custom password length"
    module_ctrl_cpu:
        description:
        - "'high'= high cpu usage; 'low'= low cpu usage; 'medium'= medium cpu usage; "
        required: False
    radius:
        description:
        - "Field radius"
        required: False
        suboptions:
            server:
                description:
                - "Field server"
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
    del_port:
        description:
        - "Field del_port"
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
    shared_poll_mode:
        description:
        - "Field shared_poll_mode"
        required: False
        suboptions:
            enable:
                description:
                - "Enable shared poll mode"
            disable:
                description:
                - "Disable shared poll mode"
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
    reboot:
        description:
        - "Field reboot"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    domain_list_info:
        description:
        - "Field domain_list_info"
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
    anomaly_log:
        description:
        - "log system anomalies"
        required: False
    core:
        description:
        - "Field core"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    apps_global:
        description:
        - "Field apps_global"
        required: False
        suboptions:
            msl_time:
                description:
                - "Configure maximum session life, default is 2 seconds (1-40 seconds, default is 2 seconds)"
            uuid:
                description:
                - "uuid of the object"
            log_session_on_established:
                description:
                - "Send TCP session creation log on completion of 3-way handshake"
    multi_queue_support:
        description:
        - "Field multi_queue_support"
        required: False
        suboptions:
            enable:
                description:
                - "Enable Multi-Queue-Support"
    trunk:
        description:
        - "Field trunk"
        required: False
        suboptions:
            load_balance:
                description:
                - "Field load_balance"
    attack_log:
        description:
        - "log attack anomalies"
        required: False
    resource_usage:
        description:
        - "Field resource_usage"
        required: False
        suboptions:
            l4_session_count:
                description:
                - "Total Sessions in the System"
            nat_pool_addr_count:
                description:
                - "Total configurable NAT Pool addresses in the System"
            max_aflex_authz_collection_number:
                description:
                - "Specify the maximum number of collections supported by aFleX authorization"
            visibility:
                description:
                - "Field visibility"
            class_list_ipv6_addr_count:
                description:
                - "Total IPv6 addresses for class-list"
            authz_policy_number:
                description:
                - "Specify the maximum number of authorization policies"
            max_aflex_file_size:
                description:
                - "Set maximum aFleX file size (Maximum file size in KBytes, default is 32K)"
            class_list_ac_entry_count:
                description:
                - "Total entries for AC class-list"
            ssl_dma_memory:
                description:
                - "Total SSL DMA memory needed in units of MB. Will be rounded to closest multiple of 2MB"
            radius_table_size:
                description:
                - "Total configurable CGNV6 RADIUS Table entries"
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
    syslog_time_msec:
        description:
        - "Field syslog_time_msec"
        required: False
        suboptions:
            enable_flag:
                description:
                - "Field enable_flag"
    domain_list_hitcount_enable:
        description:
        - "Enable class list hit count"
        required: False
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
    spe_status:
        description:
        - "Field spe_status"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    src_ip_hash_enable:
        description:
        - "Enable source ip hash"
        required: False
    ssl_req_q:
        description:
        - "Field ssl_req_q"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
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
    geoloc_list_list:
        description:
        - "Field geoloc_list_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            user_tag:
                description:
                - "Customized tag"
            name:
                description:
                - "Specify name of Geolocation list"
            sampling_enable:
                description:
                - "Field sampling_enable"
            shared:
                description:
                - "Enable sharing with other partitions"
            exclude_geoloc_name_list:
                description:
                - "Field exclude_geoloc_name_list"
            include_geoloc_name_list:
                description:
                - "Field include_geoloc_name_list"
    shutdown:
        description:
        - "Field shutdown"
        required: False
        suboptions:
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
    attack:
        description:
        - "System Attack"
        required: False
    cpu_list:
        description:
        - "Field cpu_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    dns:
        description:
        - "Field dns"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
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
    dynamic_service_dns_socket_pool:
        description:
        - "Enable socket pool for dynamic-service DNS"
        required: False
    glid:
        description:
        - "Apply limits to the whole system"
        required: False
    ddos_log:
        description:
        - "log DDoS attack anomalies"
        required: False
    spe_profile:
        description:
        - "Field spe_profile"
        required: False
        suboptions:
            action:
                description:
                - "'ipv4-only'= Enable IPv4 HW forward entries only; 'ipv6-only'= Enable IPv6 HW forward entries only; 'ipv4-ipv6'= Enable Both IPv4/IPv6 HW forward entries (shared); "
    add_cpu_core:
        description:
        - "Field add_cpu_core"
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be added (Specify core index)"
    log_cpu_interval:
        description:
        - "Log high CPU interval (Specify consecutive seconds before logging high CPU)"
        required: False
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
    gui_image_list:
        description:
        - "Field gui_image_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    hardware_forward:
        description:
        - "Field hardware_forward"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
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
    delete_cpu_core:
        description:
        - "Field delete_cpu_core"
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be deleted (Specify core index)"
    geoloc_name_helper:
        description:
        - "Field geoloc_name_helper"
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
    class_list_hitcount_enable:
        description:
        - "Enable class list hit count"
        required: False
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
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
    hardware:
        description:
        - "Field hardware"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    link_capability:
        description:
        - "Field link_capability"
        required: False
        suboptions:
            enable:
                description:
                - "Enable/Disable link capabilities"
            uuid:
                description:
                - "uuid of the object"
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
    guest_file:
        description:
        - "Field guest_file"
        required: False
        suboptions:
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
    deep_hrxq:
        description:
        - "Field deep_hrxq"
        required: False
        suboptions:
            enable:
                description:
                - "Field enable"
    cosq_show:
        description:
        - "Field cosq_show"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    geo_db_hitcount_enable:
        description:
        - "Enable Geolocation database hit count"
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
    data_cpu:
        description:
        - "Field data_cpu"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    dns_cache:
        description:
        - "Field dns_cache"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    fw:
        description:
        - "Field fw"
        required: False
        suboptions:
            application_flow:
                description:
                - "Number of flows"
            basic_dpi_enable:
                description:
                - "Enable basic dpi"
            uuid:
                description:
                - "uuid of the object"
            application_mempool:
                description:
                - "Enable application memory pool"
    ip_dns_cache:
        description:
        - "Field ip_dns_cache"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    mon_template:
        description:
        - "Field mon_template"
        required: False
        suboptions:
            monitor_list:
                description:
                - "Field monitor_list"
    geoloc:
        description:
        - "Field geoloc"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
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
AVAILABLE_PROPERTIES = ["add_cpu_core","add_port","all_vlan_limit","anomaly_log","app_performance","apps_global","attack","attack_log","bandwidth","bfd","class_list_hitcount_enable","cm_update_file_name_ref","control_cpu","core","cosq_show","cosq_stats","counter_lib_accounting","cpu_hyper_thread","cpu_list","cpu_load_sharing","cpu_map","data_cpu","ddos_attack","ddos_log","deep_hrxq","del_port","delete_cpu_core","dns","dns_cache","domain_list_hitcount_enable","domain_list_info","dynamic_service_dns_socket_pool","environment","fw","geo_db_hitcount_enable","geo_location","geoloc","geoloc_list_list","geoloc_name_helper","geolocation_file","glid","guest_file","gui_image_list","hardware","hardware_forward","hrxq_status","icmp","icmp_rate","icmp6","inuse_cpu_list","inuse_port_list","io_cpu","ip_dns_cache","ip_stats","ip6_stats","ipmi","ipmi_service","ipsec","link_capability","log_cpu_interval","memory","mgmt_port","modify_port","module_ctrl_cpu","mon_template","multi_queue_support","ndisc_ra","password_policy","per_vlan_limit","platformtype","port_info","port_list","ports","promiscuous_mode","queuing_buffer","radius","reboot","resource_accounting","resource_usage","session","session_reclaim_limit","shared_poll_mode","shell_privileges","shutdown","sockstress_disable","spe_profile","spe_status","src_ip_hash_enable","ssl_req_q","syslog_time_msec","tcp","tcp_stats","telemetry_log","template","template_bind","throughput","trunk","trunk_hw_hash","trunk_xaui_hw_hash","upgrade_status","uuid","ve_mac_scheme",]

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
        geo_location=dict(type='dict',geolite2_city_include_ipv6=dict(type='bool',),geolite2_country_include_ipv6=dict(type='bool',),geo_location_geolite2_country=dict(type='bool',),entry_list=dict(type='list',geo_locn_obj_name=dict(type='str',required=True,),geo_locn_multiple_addresses=dict(type='list',first_ip_address=dict(type='str',),first_ipv6_address=dict(type='str',),geol_ipv4_mask=dict(type='str',),ip_addr2=dict(type='str',),ipv6_addr2=dict(type='str',),geol_ipv6_mask=dict(type='int',)),user_tag=dict(type='str',),uuid=dict(type='str',)),geo_location_geolite2_city=dict(type='bool',),geoloc_load_file_list=dict(type='list',geo_location_load_filename=dict(type='str',),template_name=dict(type='str',)),geo_location_iana=dict(type='bool',),uuid=dict(type='str',)),
        mgmt_port=dict(type='dict',port_index=dict(type='int',),pci_address=dict(type='str',),mac_address=dict(type='str',)),
        geolocation_file=dict(type='dict',error_info=dict(type='dict',uuid=dict(type='str',)),uuid=dict(type='str',)),
        promiscuous_mode=dict(type='bool',),
        ndisc_ra=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','good_recv','periodic_sent','rate_limit','bad_hop_limit','truncated','bad_icmpv6_csum','bad_icmpv6_code','bad_icmpv6_option','l2_addr_and_unspec','no_free_buffers'])),uuid=dict(type='str',)),
        tcp=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','activeopens','passiveopens','attemptfails','estabresets','insegs','outsegs','retranssegs','inerrs','outrsts','sock_alloc','orphan_count','mem_alloc','recv_mem','send_mem','currestab','currsyssnt','currsynrcv','currfinw1','currfinw2','currtimew','currclose','currclsw','currlack','currlstn','currclsg','pawsactiverejected','syn_rcv_rstack','syn_rcv_rst','syn_rcv_ack','ax_rexmit_syn','tcpabortontimeout','noroute','exceedmss','tfo_conns','tfo_actives','tfo_denied'])),uuid=dict(type='str',)),
        bandwidth=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','input-bytes-per-sec','output-bytes-per-sec'])),uuid=dict(type='str',)),
        session=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_l4_conn','conn_counter','conn_freed_counter','total_l4_packet_count','total_l7_packet_count','total_l4_conn_proxy','total_l7_conn','total_tcp_conn','curr_free_conn','tcp_est_counter','tcp_half_open_counter','tcp_half_close_counter','udp_counter','ip_counter','other_counter','reverse_nat_tcp_counter','reverse_nat_udp_counter','tcp_syn_half_open_counter','conn_smp_alloc_counter','conn_smp_free_counter','conn_smp_aged_counter','ssl_count_curr','ssl_count_total','server_ssl_count_curr','server_ssl_count_total','client_ssl_reuse_total','server_ssl_reuse_total','ssl_failed_total','ssl_failed_ca_verification','ssl_server_cert_error','ssl_client_cert_auth_fail','total_ip_nat_conn','total_l2l3_conn','client_ssl_ctx_malloc_failure','conn_type_0_available','conn_type_1_available','conn_type_2_available','conn_type_3_available','conn_type_4_available','conn_smp_type_0_available','conn_smp_type_1_available','conn_smp_type_2_available','conn_smp_type_3_available','conn_smp_type_4_available','sctp-half-open-counter','sctp-est-counter','nonssl_bypass','ssl_failsafe_total','ssl_forward_proxy_failed_handshake_total','ssl_forward_proxy_failed_tcp_total','ssl_forward_proxy_failed_crypto_total','ssl_forward_proxy_failed_cert_verify_total','ssl_forward_proxy_invalid_ocsp_stapling_total','ssl_forward_proxy_revoked_ocsp_total','ssl_forward_proxy_failed_cert_signing_total','ssl_forward_proxy_failed_ssl_version_total','ssl_forward_proxy_sni_bypass_total','ssl_forward_proxy_client_auth_bypass_total','conn_app_smp_alloc_counter','diameter_conn_counter','diameter_conn_freed_counter','debug_tcp_counter','debug_udp_counter','total_fw_conn','total_local_conn','total_curr_conn','client_ssl_fatal_alert','client_ssl_fin_rst','fp_session_fin_rst','server_ssl_fatal_alert','server_ssl_fin_rst','client_template_int_err','client_template_unknown_err','server_template_int_err','server_template_unknown_err','total_debug_conn','ssl_forward_proxy_failed_aflex_total','ssl_forward_proxy_cert_subject_bypass_total','ssl_forward_proxy_cert_issuer_bypass_total','ssl_forward_proxy_cert_san_bypass_total','ssl_forward_proxy_no_sni_bypass_total','ssl_forward_proxy_no_sni_reset_total','ssl_forward_proxy_username_bypass_total','ssl_forward_proxy_ad_grpup_bypass_total','diameter_concurrent_user_sessions_counter'])),uuid=dict(type='str',)),
        session_reclaim_limit=dict(type='dict',scan_freq=dict(type='int',),nscan_limit=dict(type='int',),uuid=dict(type='str',)),
        inuse_cpu_list=dict(type='dict',uuid=dict(type='str',)),
        add_port=dict(type='dict',port_index=dict(type='int',)),
        uuid=dict(type='str',),
        bfd=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','ip_checksum_error','udp_checksum_error','session_not_found','multihop_mismatch','version_mismatch','length_too_small','data_is_short','invalid_detect_mult','invalid_multipoint','invalid_my_disc','invalid_ttl','auth_length_invalid','auth_mismatch','auth_type_mismatch','auth_key_id_mismatch','auth_key_mismatch','auth_seqnum_invalid','auth_failed','local_state_admin_down','dest_unreachable','no_ipv6_enable','other_error'])),uuid=dict(type='str',)),
        ddos_attack=dict(type='bool',),
        trunk_xaui_hw_hash=dict(type='dict',mode=dict(type='int',),uuid=dict(type='str',)),
        environment=dict(type='dict',uuid=dict(type='str',)),
        port_info=dict(type='dict',uuid=dict(type='str',)),
        trunk_hw_hash=dict(type='dict',mode=dict(type='int',),uuid=dict(type='str',)),
        ve_mac_scheme=dict(type='dict',ve_mac_scheme_val=dict(type='str',choices=['hash-based','round-robin','system-mac']),uuid=dict(type='str',)),
        template_bind=dict(type='dict',monitor_list=dict(type='list',template_monitor=dict(type='int',required=True,),uuid=dict(type='str',))),
        ipmi=dict(type='dict',reset=dict(type='bool',),ip=dict(type='dict',ipv4_address=dict(type='str',),default_gateway=dict(type='str',),ipv4_netmask=dict(type='str',)),ipsrc=dict(type='dict',dhcp=dict(type='bool',),static=dict(type='bool',)),tool=dict(type='dict',cmd=dict(type='str',)),user=dict(type='dict',administrator=dict(type='bool',),setname=dict(type='str',),newname=dict(type='str',),newpass=dict(type='str',),callback=dict(type='bool',),add=dict(type='str',),disable=dict(type='str',),setpass=dict(type='str',),user=dict(type='bool',),operator=dict(type='bool',),password=dict(type='str',),privilege=dict(type='str',))),
        icmp_rate=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','over_limit_drop','limit_intf_drop','limit_vserver_drop','limit_total_drop','lockup_time_left','curr_rate','v6_over_limit_drop','v6_limit_intf_drop','v6_limit_vserver_drop','v6_limit_total_drop','v6_lockup_time_left','v6_curr_rate'])),uuid=dict(type='str',)),
        telemetry_log=dict(type='dict',device_status=dict(type='dict',uuid=dict(type='str',)),top_k_source_list=dict(type='dict',uuid=dict(type='str',)),top_k_app_svc_list=dict(type='dict',uuid=dict(type='str',)),partition_metrics=dict(type='dict',uuid=dict(type='str',))),
        ipsec=dict(type='dict',packet_round_robin=dict(type='bool',),crypto_core=dict(type='int',),uuid=dict(type='str',),fpga_decrypt=dict(type='dict',action=dict(type='str',choices=['enable','disable'])),crypto_mem=dict(type='int',)),
        hrxq_status=dict(type='dict',uuid=dict(type='str',)),
        cosq_stats=dict(type='dict',uuid=dict(type='str',)),
        sockstress_disable=dict(type='bool',),
        io_cpu=dict(type='dict',max_cores=dict(type='int',)),
        cpu_map=dict(type='dict',uuid=dict(type='str',)),
        ports=dict(type='dict',link_detection_interval=dict(type='int',),uuid=dict(type='str',)),
        app_performance=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total-throughput-bits-per-sec','l4-conns-per-sec','l7-conns-per-sec','l7-trans-per-sec','ssl-conns-per-sec','ip-nat-conns-per-sec','total-new-conns-per-sec','total-curr-conns','l4-bandwidth','l7-bandwidth','serv-ssl-conns-per-sec','fw-conns-per-sec','gifw-conns-per-sec'])),uuid=dict(type='str',)),
        counter_lib_accounting=dict(type='dict',uuid=dict(type='str',)),
        inuse_port_list=dict(type='dict',uuid=dict(type='str',)),
        control_cpu=dict(type='dict',uuid=dict(type='str',)),
        password_policy=dict(type='dict',aging=dict(type='str',choices=['Strict','Medium','Simple']),complexity=dict(type='str',choices=['Strict','Medium','Simple']),history=dict(type='str',choices=['Strict','Medium','Simple']),uuid=dict(type='str',),min_pswd_len=dict(type='int',)),
        module_ctrl_cpu=dict(type='str',choices=['high','low','medium']),
        radius=dict(type='dict',server=dict(type='dict',accounting_start=dict(type='str',choices=['ignore','append-entry','replace-entry']),attribute_name=dict(type='str',choices=['msisdn','imei','imsi','custom1','custom2','custom3']),vrid=dict(type='int',),remote=dict(type='dict',ip_list=dict(type='list',ip_list_name=dict(type='str',),ip_list_encrypted=dict(type='str',),ip_list_secret_string=dict(type='str',),ip_list_secret=dict(type='bool',))),uuid=dict(type='str',),encrypted=dict(type='str',),disable_reply=dict(type='bool',),accounting_interim_update=dict(type='str',choices=['ignore','append-entry','replace-entry']),secret=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','msisdn-received','imei-received','imsi-received','custom-received','radius-request-received','radius-request-dropped','request-bad-secret-dropped','request-no-key-vap-dropped','request-malformed-dropped','request-ignored','radius-table-full','secret-not-configured-dropped','ha-standby-dropped','ipv6-prefix-length-mismatch','invalid-key','smp-created','smp-deleted','smp-mem-allocated','smp-mem-alloc-failed','smp-mem-freed','smp-in-rml','mem-allocated','mem-alloc-failed','mem-freed','ha-sync-create-sent','ha-sync-delete-sent','ha-sync-create-recv','ha-sync-delete-recv','acct-on-filters-full','acct-on-dup-request','ip-mismatch-delete','ip-add-race-drop','ha-sync-no-key-vap-dropped','inter-card-msg-fail-drop'])),accounting_stop=dict(type='str',choices=['ignore','delete-entry','delete-entry-and-sessions']),attribute=dict(type='list',prefix_number=dict(type='int',),prefix_length=dict(type='str',choices=['32','48','64','80','96','112']),name=dict(type='str',),prefix_vendor=dict(type='int',),number=dict(type='int',),value=dict(type='str',choices=['hexadecimal']),custom_vendor=dict(type='int',),custom_number=dict(type='int',),vendor=dict(type='int',),attribute_value=dict(type='str',choices=['inside-ipv6-prefix','inside-ip','inside-ipv6','imei','imsi','msisdn','custom1','custom2','custom3'])),listen_port=dict(type='int',),accounting_on=dict(type='str',choices=['ignore','delete-entries-using-attribute']),secret_string=dict(type='str',))),
        modify_port=dict(type='dict',port_index=dict(type='int',),port_number=dict(type='int',)),
        del_port=dict(type='dict',port_index=dict(type='int',)),
        shared_poll_mode=dict(type='dict',enable=dict(type='bool',),disable=dict(type='bool',)),
        queuing_buffer=dict(type='dict',enable=dict(type='bool',),uuid=dict(type='str',)),
        reboot=dict(type='dict',uuid=dict(type='str',)),
        domain_list_info=dict(type='dict',uuid=dict(type='str',)),
        template=dict(type='dict',template_policy=dict(type='str',),uuid=dict(type='str',)),
        anomaly_log=dict(type='bool',),
        core=dict(type='dict',uuid=dict(type='str',)),
        apps_global=dict(type='dict',msl_time=dict(type='int',),uuid=dict(type='str',),log_session_on_established=dict(type='bool',)),
        multi_queue_support=dict(type='dict',enable=dict(type='bool',)),
        trunk=dict(type='dict',load_balance=dict(type='dict',use_l4=dict(type='bool',),uuid=dict(type='str',),use_l3=dict(type='bool',))),
        attack_log=dict(type='bool',),
        resource_usage=dict(type='dict',l4_session_count=dict(type='int',),nat_pool_addr_count=dict(type='int',),max_aflex_authz_collection_number=dict(type='int',),visibility=dict(type='dict',monitored_entity_count=dict(type='int',),uuid=dict(type='str',)),class_list_ipv6_addr_count=dict(type='int',),authz_policy_number=dict(type='int',),max_aflex_file_size=dict(type='int',),class_list_ac_entry_count=dict(type='int',),ssl_dma_memory=dict(type='int',),radius_table_size=dict(type='int',),aflex_table_entry_count=dict(type='int',),ssl_context_memory=dict(type='int',),auth_portal_html_file_size=dict(type='int',),auth_portal_image_file_size=dict(type='int',),uuid=dict(type='str',)),
        syslog_time_msec=dict(type='dict',enable_flag=dict(type='bool',)),
        domain_list_hitcount_enable=dict(type='bool',),
        cm_update_file_name_ref=dict(type='dict',source_name=dict(type='str',),id=dict(type='int',),dest_name=dict(type='str',)),
        spe_status=dict(type='dict',uuid=dict(type='str',)),
        src_ip_hash_enable=dict(type='bool',),
        ssl_req_q=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num-ssl-queues','ssl-req-q-depth-tot','ssl-req-q-inuse-tot','ssl-hw-q-depth-tot','ssl-hw-q-inuse-tot'])),uuid=dict(type='str',)),
        cpu_load_sharing=dict(type='dict',packets_per_second=dict(type='dict',min=dict(type='int',)),cpu_usage=dict(type='dict',high=dict(type='int',),low=dict(type='int',)),disable=dict(type='bool',),uuid=dict(type='str',)),
        geoloc_list_list=dict(type='list',uuid=dict(type='str',),user_tag=dict(type='str',),name=dict(type='str',required=True,),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hit-count','total-geoloc','total-active'])),shared=dict(type='bool',),exclude_geoloc_name_list=dict(type='list',exclude_geoloc_name_val=dict(type='str',)),include_geoloc_name_list=dict(type='list',include_geoloc_name_val=dict(type='str',))),
        shutdown=dict(type='dict',uuid=dict(type='str',)),
        ip_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inreceives','inhdrerrors','intoobigerrors','innoroutes','inaddrerrors','inunknownprotos','intruncatedpkts','indiscards','indelivers','outforwdatagrams','outrequests','outdiscards','outnoroutes','reasmtimeout','reasmreqds','reasmoks','reasmfails','fragoks','fragfails','fragcreates','inmcastpkts','outmcastpkts'])),uuid=dict(type='str',)),
        ip6_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','inreceives','inhdrerrors','intoobigerrors','innoroutes','inaddrerrors','inunknownprotos','intruncatedpkts','indiscards','indelivers','outforwdatagrams','outrequests','outdiscards','outnoroutes','reasmtimeout','reasmreqds','reasmoks','reasmfails','fragoks','fragfails','fragcreates','inmcastpkts','outmcastpkts'])),uuid=dict(type='str',)),
        attack=dict(type='bool',),
        cpu_list=dict(type='dict',uuid=dict(type='str',)),
        dns=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','slb_req','slb_resp','slb_no_resp','slb_req_rexmit','slb_resp_no_match','slb_no_resource','nat_req','nat_resp','nat_no_resp','nat_req_rexmit','nat_resp_no_match','nat_no_resource','nat_xid_reused'])),uuid=dict(type='str',)),
        memory=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','usage-percentage'])),uuid=dict(type='str',)),
        cpu_hyper_thread=dict(type='dict',enable=dict(type='bool',),disable=dict(type='bool',)),
        dynamic_service_dns_socket_pool=dict(type='bool',),
        glid=dict(type='int',),
        ddos_log=dict(type='bool',),
        spe_profile=dict(type='dict',action=dict(type='str',choices=['ipv4-only','ipv6-only','ipv4-ipv6'])),
        add_cpu_core=dict(type='dict',core_index=dict(type='int',)),
        log_cpu_interval=dict(type='int',),
        icmp=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','inmsgs','inerrors','indestunreachs','intimeexcds','inparmprobs','insrcquenchs','inredirects','inechos','inechoreps','intimestamps','intimestampreps','inaddrmasks','inaddrmaskreps','outmsgs','outerrors','outdestunreachs','outtimeexcds','outparmprobs','outsrcquenchs','outredirects','outechos','outechoreps','outtimestamps','outtimestampreps','outaddrmasks','outaddrmaskreps'])),uuid=dict(type='str',)),
        gui_image_list=dict(type='dict',uuid=dict(type='str',)),
        hardware_forward=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hit-counts','hit-index','ipv4-forward-counts','ipv6-forward-counts','hw-fwd-module-status','hw-fwd-prog-reqs','hw-fwd-prog-errors','hw-fwd-flow-singlebit-errors','hw-fwd-flow-tag-mismatch','hw-fwd-flow-seq-mismatch','hw-fwd-ageout-drop-count','hw-fwd-invalidation-drop','hw-fwd-flow-hit-index','hw-fwd-flow-reason-flags','hw-fwd-flow-drop-count','hw-fwd-flow-error-count','hw-fwd-flow-unalign-count','hw-fwd-flow-underflow-count','hw-fwd-flow-tx-full-drop','hw-fwd-flow-qdr-full-drop','hw-fwd-phyport-mismatch-drop','hw-fwd-vlanid-mismatch-drop','hw-fwd-vmid-drop','hw-fwd-protocol-mismatch-drop','hw-fwd-avail-ipv4-entry','hw-fwd-avail-ipv6-entry'])),uuid=dict(type='str',)),
        tcp_stats=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','connattempt','connects','drops','conndrops','closed','segstimed','rttupdated','delack','timeoutdrop','rexmttimeo','persisttimeo','keeptimeo','keepprobe','keepdrops','sndtotal','sndpack','sndbyte','sndrexmitpack','sndrexmitbyte','sndrexmitbad','sndacks','sndprobe','sndurg','sndwinup','sndctrl','sndrst','sndfin','sndsyn','rcvtotal','rcvpack','rcvbyte','rcvbadoff','rcvmemdrop','rcvduppack','rcvdupbyte','rcvpartduppack','rcvpartdupbyte','rcvoopack','rcvoobyte','rcvpackafterwin','rcvbyteafterwin','rcvwinprobe','rcvdupack','rcvacktoomuch','rcvackpack','rcvackbyte','rcvwinupd','pawsdrop','predack','preddat','persistdrop','badrst','finwait2_drops','sack_recovery_episode','sack_rexmits','sack_rexmit_bytes','sack_rcv_blocks','sack_send_blocks','sndcack','cacklim','reassmemdrop','reasstimeout','cc_idle','cc_reduce','rcvdsack','a2brcvwnd','a2bsackpresent','a2bdupack','a2brxdata','a2btcpoptions','a2boodata','a2bpartialack','a2bfsmtransition','a2btransitionnum','b2atransitionnum','bad_iochan','atcpforward','atcpsent','atcprexmitsadrop','atcpsendbackack','atcprexmit','atcpbuffallocfail','a2bappbuffering','atcpsendfail','earlyrexmit','mburstlim','a2bsndwnd'])),uuid=dict(type='str',)),
        delete_cpu_core=dict(type='dict',core_index=dict(type='int',)),
        geoloc_name_helper=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','place-holder'])),uuid=dict(type='str',)),
        shell_privileges=dict(type='dict',uuid=dict(type='str',)),
        class_list_hitcount_enable=dict(type='bool',),
        port_list=dict(type='dict',uuid=dict(type='str',)),
        resource_accounting=dict(type='dict',uuid=dict(type='str',),template_list=dict(type='list',app_resources=dict(type='dict',gslb_site_cfg=dict(type='dict',gslb_site_min_guarantee=dict(type='int',),gslb_site_max=dict(type='int',)),gslb_policy_cfg=dict(type='dict',gslb_policy_min_guarantee=dict(type='int',),gslb_policy_max=dict(type='int',)),gslb_service_cfg=dict(type='dict',gslb_service_min_guarantee=dict(type='int',),gslb_service_max=dict(type='int',)),gslb_geo_location_cfg=dict(type='dict',gslb_geo_location_max=dict(type='int',),gslb_geo_location_min_guarantee=dict(type='int',)),uuid=dict(type='str',),real_server_cfg=dict(type='dict',real_server_max=dict(type='int',),real_server_min_guarantee=dict(type='int',)),gslb_ip_list_cfg=dict(type='dict',gslb_ip_list_max=dict(type='int',),gslb_ip_list_min_guarantee=dict(type='int',)),gslb_template_cfg=dict(type='dict',gslb_template_max=dict(type='int',),gslb_template_min_guarantee=dict(type='int',)),gslb_zone_cfg=dict(type='dict',gslb_zone_min_guarantee=dict(type='int',),gslb_zone_max=dict(type='int',)),gslb_device_cfg=dict(type='dict',gslb_device_min_guarantee=dict(type='int',),gslb_device_max=dict(type='int',)),virtual_server_cfg=dict(type='dict',virtual_server_max=dict(type='int',),virtual_server_min_guarantee=dict(type='int',)),real_port_cfg=dict(type='dict',real_port_min_guarantee=dict(type='int',),real_port_max=dict(type='int',)),health_monitor_cfg=dict(type='dict',health_monitor_max=dict(type='int',),health_monitor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),gslb_svc_group_cfg=dict(type='dict',gslb_svc_group_max=dict(type='int',),gslb_svc_group_min_guarantee=dict(type='int',)),service_group_cfg=dict(type='dict',service_group_max=dict(type='int',),service_group_min_guarantee=dict(type='int',)),gslb_service_port_cfg=dict(type='dict',gslb_service_port_max=dict(type='int',),gslb_service_port_min_guarantee=dict(type='int',)),gslb_service_ip_cfg=dict(type='dict',gslb_service_ip_max=dict(type='int',),gslb_service_ip_min_guarantee=dict(type='int',))),name=dict(type='str',required=True,),system_resources=dict(type='dict',l4_session_limit_cfg=dict(type='dict',l4_session_limit_max=dict(type='str',),l4_session_limit_min_guarantee=dict(type='str',)),l7cps_limit_cfg=dict(type='dict',l7cps_limit_max=dict(type='int',)),l4cps_limit_cfg=dict(type='dict',l4cps_limit_max=dict(type='int',)),uuid=dict(type='str',),natcps_limit_cfg=dict(type='dict',natcps_limit_max=dict(type='int',)),sslcps_limit_cfg=dict(type='dict',sslcps_limit_max=dict(type='int',)),fwcps_limit_cfg=dict(type='dict',fwcps_limit_max=dict(type='int',)),ssl_throughput_limit_cfg=dict(type='dict',ssl_throughput_limit_watermark_disable=dict(type='bool',),ssl_throughput_limit_max=dict(type='int',)),threshold=dict(type='int',),bw_limit_cfg=dict(type='dict',bw_limit_max=dict(type='int',),bw_limit_watermark_disable=dict(type='bool',)),concurrent_session_limit_cfg=dict(type='dict',concurrent_session_limit_max=dict(type='int',))),user_tag=dict(type='str',),network_resources=dict(type='dict',static_ipv6_route_cfg=dict(type='dict',static_ipv6_route_max=dict(type='int',),static_ipv6_route_min_guarantee=dict(type='int',)),uuid=dict(type='str',),ipv4_acl_line_cfg=dict(type='dict',ipv4_acl_line_min_guarantee=dict(type='int',),ipv4_acl_line_max=dict(type='int',)),static_ipv4_route_cfg=dict(type='dict',static_ipv4_route_max=dict(type='int',),static_ipv4_route_min_guarantee=dict(type='int',)),static_arp_cfg=dict(type='dict',static_arp_min_guarantee=dict(type='int',),static_arp_max=dict(type='int',)),object_group_clause_cfg=dict(type='dict',object_group_clause_min_guarantee=dict(type='int',),object_group_clause_max=dict(type='int',)),static_mac_cfg=dict(type='dict',static_mac_min_guarantee=dict(type='int',),static_mac_max=dict(type='int',)),object_group_cfg=dict(type='dict',object_group_min_guarantee=dict(type='int',),object_group_max=dict(type='int',)),static_neighbor_cfg=dict(type='dict',static_neighbor_max=dict(type='int',),static_neighbor_min_guarantee=dict(type='int',)),threshold=dict(type='int',),ipv6_acl_line_cfg=dict(type='dict',ipv6_acl_line_max=dict(type='int',),ipv6_acl_line_min_guarantee=dict(type='int',))),uuid=dict(type='str',))),
        hardware=dict(type='dict',uuid=dict(type='str',)),
        link_capability=dict(type='dict',enable=dict(type='bool',),uuid=dict(type='str',)),
        all_vlan_limit=dict(type='dict',unknown_ucast=dict(type='int',),bcast=dict(type='int',),mcast=dict(type='int',),ipmcast=dict(type='int',),uuid=dict(type='str',)),
        guest_file=dict(type='dict',uuid=dict(type='str',)),
        per_vlan_limit=dict(type='dict',unknown_ucast=dict(type='int',),bcast=dict(type='int',),mcast=dict(type='int',),ipmcast=dict(type='int',),uuid=dict(type='str',)),
        deep_hrxq=dict(type='dict',enable=dict(type='bool',)),
        cosq_show=dict(type='dict',uuid=dict(type='str',)),
        geo_db_hitcount_enable=dict(type='bool',),
        throughput=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','global-system-throughput-bits-per-sec','per-part-throughput-bits-per-sec'])),uuid=dict(type='str',)),
        ipmi_service=dict(type='dict',disable=dict(type='bool',),uuid=dict(type='str',)),
        data_cpu=dict(type='dict',uuid=dict(type='str',)),
        dns_cache=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_q','total_r','hit','bad_q','encode_q','multiple_q','oversize_q','bad_r','oversize_r','encode_r','multiple_r','answer_r','ttl_r','ageout','bad_answer','ageout_weight','total_log','total_alloc','total_freed','current_allocate','current_data_allocate'])),uuid=dict(type='str',)),
        fw=dict(type='dict',application_flow=dict(type='int',),basic_dpi_enable=dict(type='bool',),uuid=dict(type='str',),application_mempool=dict(type='bool',)),
        ip_dns_cache=dict(type='dict',uuid=dict(type='str',)),
        mon_template=dict(type='dict',monitor_list=dict(type='list',clear_cfg=dict(type='list',clear_sequence=dict(type='int',),clear_all_sequence=dict(type='int',),sessions=dict(type='str',choices=['all','sequence'])),uuid=dict(type='str',),link_enable_cfg=dict(type='list',ena_sequence=dict(type='int',),enaeth=dict(type='str',)),link_up_cfg=dict(type='list',linkup_ethernet3=dict(type='str',),linkup_ethernet2=dict(type='str',),linkup_ethernet1=dict(type='str',),link_up_sequence1=dict(type='int',),link_up_sequence3=dict(type='int',),link_up_sequence2=dict(type='int',)),link_down_cfg=dict(type='list',link_down_sequence1=dict(type='int',),link_down_sequence2=dict(type='int',),link_down_sequence3=dict(type='int',),linkdown_ethernet2=dict(type='str',),linkdown_ethernet3=dict(type='str',),linkdown_ethernet1=dict(type='str',)),user_tag=dict(type='str',),link_disable_cfg=dict(type='list',dis_sequence=dict(type='int',),diseth=dict(type='str',)),monitor_relation=dict(type='str',choices=['monitor-and','monitor-or']),id=dict(type='int',required=True,))),
        geoloc=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','place-holder'])),uuid=dict(type='str',)),
        upgrade_status=dict(type='dict',uuid=dict(type='str',)),
        icmp6=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','in_msgs','in_errors','in_dest_un_reach','in_pkt_too_big','in_time_exceeds','in_param_prob','in_echoes','in_exho_reply','in_grp_mem_query','in_grp_mem_resp','in_grp_mem_reduction','in_router_sol','in_ra','in_ns','in_na','in_redirect','out_msg','out_dst_un_reach','out_pkt_too_big','out_time_exceeds','out_param_prob','out_echo_req','out_echo_replies','out_rs','out_ra','out_ns','out_na','out_redirects','out_mem_resp','out_mem_reductions','err_rs','err_ra','err_ns','err_na','err_redirects','err_echoes','err_echo_replies'])),uuid=dict(type='str',)),
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["system"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
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
    payload = build_json("system", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("system", module)
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
    if partition and not module.check_mode:
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