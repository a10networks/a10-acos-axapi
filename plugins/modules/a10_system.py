#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system
description:
    - Configure System Parameters
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
    anomaly_log:
        description:
        - "log system anomalies"
        type: bool
        required: False
    attack:
        description:
        - "System Attack"
        type: bool
        required: False
    attack_log:
        description:
        - "log attack anomalies"
        type: bool
        required: False
    ddos_attack:
        description:
        - "System DDoS Attack"
        type: bool
        required: False
    ddos_log:
        description:
        - "log DDoS attack anomalies"
        type: bool
        required: False
    log_cpu_interval:
        description:
        - "Log high CPU interval (Specify consecutive seconds before logging high CPU)"
        type: int
        required: False
    sockstress_disable:
        description:
        - "Disable sockstress protection"
        type: bool
        required: False
    promiscuous_mode:
        description:
        - "Run in promiscous mode settings"
        type: bool
        required: False
    glid:
        description:
        - "Apply limits to the whole system"
        type: int
        required: False
    module_ctrl_cpu:
        description:
        - "'high'= high cpu usage; 'low'= low cpu usage; 'medium'= medium cpu usage;"
        type: str
        required: False
    src_ip_hash_enable:
        description:
        - "Enable source ip hash"
        type: bool
        required: False
    class_list_hitcount_enable:
        description:
        - "Enable class list hit count"
        type: bool
        required: False
    geo_db_hitcount_enable:
        description:
        - "Enable Geolocation database hit count"
        type: bool
        required: False
    domain_list_hitcount_enable:
        description:
        - "Enable class list hit count"
        type: bool
        required: False
    dynamic_service_dns_socket_pool:
        description:
        - "Enable socket pool for dynamic-service DNS"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    timeout_value:
        description:
        - "Field timeout_value"
        type: dict
        required: False
        suboptions:
            ftp:
                description:
                - "set timeout to stop ftp transfer in seconds, 0 is no limit"
                type: int
            scp:
                description:
                - "set timeout to stop scp transfer in seconds, 0 is no limit"
                type: int
            sftp:
                description:
                - "set timeout to stop sftp transfer in seconds, 0 is no limit"
                type: int
            tftp:
                description:
                - "set timeout to stop tftp transfer in seconds, 0 is no limit"
                type: int
            http:
                description:
                - "set timeout to stop http transfer in seconds, 0 is no limit"
                type: int
            https:
                description:
                - "set timeout to stop https transfer in seconds, 0 is no limit"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    bandwidth:
        description:
        - "Field bandwidth"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    counter_lib_accounting:
        description:
        - "Field counter_lib_accounting"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    control_cpu:
        description:
        - "Field control_cpu"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    data_cpu:
        description:
        - "Field data_cpu"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    mgmt_port:
        description:
        - "Field mgmt_port"
        type: dict
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
                type: int
            mac_address:
                description:
                - "mac-address to be configured as mgmt port"
                type: str
            pci_address:
                description:
                - "pci-address to be configured as mgmt port"
                type: str
    shared_poll_mode:
        description:
        - "Field shared_poll_mode"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable shared poll mode"
                type: bool
            disable:
                description:
                - "Disable shared poll mode"
                type: bool
    probe_network_devices:
        description:
        - "Field probe_network_devices"
        type: dict
        required: False
    management_interface_mode:
        description:
        - "Field management_interface_mode"
        type: dict
        required: False
        suboptions:
            dedicated:
                description:
                - "Set management interface in dedicated mode"
                type: bool
            non_dedicated:
                description:
                - "Set management interface in non-dedicated mode"
                type: bool
    add_port:
        description:
        - "Field add_port"
        type: dict
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
                type: int
    del_port:
        description:
        - "Field del_port"
        type: dict
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
                type: int
    modify_port:
        description:
        - "Field modify_port"
        type: dict
        required: False
        suboptions:
            port_index:
                description:
                - "port index to be configured (Specify port index)"
                type: int
            port_number:
                description:
                - "port number to be configured (Specify port number)"
                type: int
    multi_queue_support:
        description:
        - "Field multi_queue_support"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable Multi-Queue-Support"
                type: bool
    add_cpu_core:
        description:
        - "Field add_cpu_core"
        type: dict
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be added (Specify core index)"
                type: int
    delete_cpu_core:
        description:
        - "Field delete_cpu_core"
        type: dict
        required: False
        suboptions:
            core_index:
                description:
                - "core index to be deleted (Specify core index)"
                type: int
    cpu_hyper_thread:
        description:
        - "Field cpu_hyper_thread"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable CPU Hyperthreading"
                type: bool
            disable:
                description:
                - "Disable CPU Hyperthreading"
                type: bool
    io_cpu:
        description:
        - "Field io_cpu"
        type: dict
        required: False
        suboptions:
            max_cores:
                description:
                - "max number of IO cores (Specify number of cores)"
                type: int
    link_monitor:
        description:
        - "Field link_monitor"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable Link Monitoring"
                type: bool
            disable:
                description:
                - "Disable Link Monitoring"
                type: bool
    port_list:
        description:
        - "Field port_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    port_info:
        description:
        - "Field port_info"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    inuse_port_list:
        description:
        - "Field inuse_port_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cpu_list:
        description:
        - "Field cpu_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cpu_map:
        description:
        - "Field cpu_map"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    inuse_cpu_list:
        description:
        - "Field inuse_cpu_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            template_policy:
                description:
                - "Apply policy template to the whole system (Policy template name)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    template_bind:
        description:
        - "Field template_bind"
        type: dict
        required: False
        suboptions:
            monitor_list:
                description:
                - "Field monitor_list"
                type: list
    mon_template:
        description:
        - "Field mon_template"
        type: dict
        required: False
        suboptions:
            monitor_list:
                description:
                - "Field monitor_list"
                type: list
    memory:
        description:
        - "Field memory"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    resource_usage:
        description:
        - "Field resource_usage"
        type: dict
        required: False
        suboptions:
            ssl_context_memory:
                description:
                - "Total SSL context memory needed in units of MB. Will be rounded to closest
          multiple of 2MB"
                type: int
            ssl_dma_memory:
                description:
                - "Total SSL DMA memory needed in units of MB. Will be rounded to closest multiple
          of 2MB"
                type: int
            nat_pool_addr_count:
                description:
                - "Total configurable NAT Pool addresses in the System"
                type: int
            l4_session_count:
                description:
                - "Total Sessions in the System"
                type: int
            auth_portal_html_file_size:
                description:
                - "Specify maximum html file size for each html page in auth portal (in KB)"
                type: int
            auth_portal_image_file_size:
                description:
                - "Specify maximum image file size for default portal (in KB)"
                type: int
            max_aflex_file_size:
                description:
                - "Set maximum aFleX file size (Maximum file size in KBytes, default is 32K)"
                type: int
            aflex_table_entry_count:
                description:
                - "Total aFleX table entry in the system (Total aFlex entry in the system)"
                type: int
            class_list_ipv6_addr_count:
                description:
                - "Total IPv6 addresses for class-list"
                type: int
            class_list_ac_entry_count:
                description:
                - "Total entries for AC class-list"
                type: int
            max_aflex_authz_collection_number:
                description:
                - "Specify the maximum number of collections supported by aFleX authorization"
                type: int
            radius_table_size:
                description:
                - "Total configurable CGNV6 RADIUS Table entries"
                type: int
            authz_policy_number:
                description:
                - "Specify the maximum number of authorization policies"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            visibility:
                description:
                - "Field visibility"
                type: dict
    link_capability:
        description:
        - "Field link_capability"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable/Disable link capabilities"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    resource_accounting:
        description:
        - "Field resource_accounting"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            template_list:
                description:
                - "Field template_list"
                type: list
    trunk:
        description:
        - "Field trunk"
        type: dict
        required: False
        suboptions:
            load_balance:
                description:
                - "Field load_balance"
                type: dict
    ports:
        description:
        - "Field ports"
        type: dict
        required: False
        suboptions:
            link_detection_interval:
                description:
                - "Link detection interval in msecs"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    table_integrity_check:
        description:
        - "Field table_integrity_check"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "Enable table integrity check"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    ipsec:
        description:
        - "Field ipsec"
        type: dict
        required: False
        suboptions:
            packet_round_robin:
                description:
                - "Enable packet round robin for IPsec packets"
                type: bool
            crypto_core:
                description:
                - "Crypto cores assigned for IPsec processing"
                type: int
            crypto_mem:
                description:
                - "Crypto memory percentage assigned for IPsec processing (rounded to increments
          of 10)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            fpga_decrypt:
                description:
                - "Field fpga_decrypt"
                type: dict
    spe_profile:
        description:
        - "Field spe_profile"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "'ipv4-only'= Enable IPv4 HW forward entries only; 'ipv6-only'= Enable IPv6 HW
          forward entries only; 'ipv4-ipv6'= Enable Both IPv4/IPv6 HW forward entries
          (shared);"
                type: str
    spe_status:
        description:
        - "Field spe_status"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    deep_hrxq:
        description:
        - "Field deep_hrxq"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Field enable"
                type: bool
    hrxq_status:
        description:
        - "Field hrxq_status"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cpu_load_sharing:
        description:
        - "Field cpu_load_sharing"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable CPU load sharing in overload situations"
                type: bool
            packets_per_second:
                description:
                - "Field packets_per_second"
                type: dict
            cpu_usage:
                description:
                - "Field cpu_usage"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    per_vlan_limit:
        description:
        - "Field per_vlan_limit"
        type: dict
        required: False
        suboptions:
            bcast:
                description:
                - "broadcast packets (per second limit)"
                type: int
            ipmcast:
                description:
                - "IP multicast packets (per second limit)"
                type: int
            mcast:
                description:
                - "multicast packets (per second limit)"
                type: int
            unknown_ucast:
                description:
                - "unknown unicast packets (per second limit)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    all_vlan_limit:
        description:
        - "Field all_vlan_limit"
        type: dict
        required: False
        suboptions:
            bcast:
                description:
                - "broadcast packets (per second limit)"
                type: int
            ipmcast:
                description:
                - "IP multicast packets (per second limit)"
                type: int
            mcast:
                description:
                - "multicast packets (per second limit)"
                type: int
            unknown_ucast:
                description:
                - "unknown unicast packets (per second limit)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    ve_mac_scheme:
        description:
        - "Field ve_mac_scheme"
        type: dict
        required: False
        suboptions:
            ve_mac_scheme_val:
                description:
                - "'hash-based'= Hash-based using the VE number; 'round-robin'= Round Robin
          scheme; 'system-mac'= Use system MAC address;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    session_reclaim_limit:
        description:
        - "Field session_reclaim_limit"
        type: dict
        required: False
        suboptions:
            nscan_limit:
                description:
                - "smp session scan limit (number of smp sessions per scan)"
                type: int
            scan_freq:
                description:
                - "smp session scan frequency (scan per second)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    hardware:
        description:
        - "Field hardware"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    platformtype:
        description:
        - "Field platformtype"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    reboot:
        description:
        - "Field reboot"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    shutdown:
        description:
        - "Field shutdown"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    environment:
        description:
        - "Field environment"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    hardware_forward:
        description:
        - "Field hardware_forward"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    throughput:
        description:
        - "Field throughput"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ipmi:
        description:
        - "Field ipmi"
        type: dict
        required: False
        suboptions:
            reset:
                description:
                - "Reset IPMI Controller"
                type: bool
            ip:
                description:
                - "Field ip"
                type: dict
            ipsrc:
                description:
                - "Field ipsrc"
                type: dict
            user:
                description:
                - "Field user"
                type: dict
            tool:
                description:
                - "Field tool"
                type: dict
    queuing_buffer:
        description:
        - "Field queuing_buffer"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable/Disable micro-burst traffic support"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    trunk_hw_hash:
        description:
        - "Field trunk_hw_hash"
        type: dict
        required: False
        suboptions:
            mode:
                description:
                - "Set HW hash mode, default is 6 (1=dst-mac 2=src-mac 3=src-dst-mac 4=src-ip
          5=dst-ip 6=rtag6 7=rtag7)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    trunk_xaui_hw_hash:
        description:
        - "Field trunk_xaui_hw_hash"
        type: dict
        required: False
        suboptions:
            mode:
                description:
                - "Set HW hash mode, default is 6 (1=dst-mac 2=src-mac 3=src-dst-mac 4=src-ip
          5=dst-ip 6=rtag6 7=rtag7)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    upgrade_status:
        description:
        - "Field upgrade_status"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    guest_file:
        description:
        - "Field guest_file"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cm_update_file_name_ref:
        description:
        - "Field cm_update_file_name_ref"
        type: dict
        required: False
        suboptions:
            source_name:
                description:
                - "bind source name"
                type: str
            dest_name:
                description:
                - "bind dest name"
                type: str
            id:
                description:
                - "Specify unique Partition id"
                type: int
    core:
        description:
        - "Field core"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    apps_global:
        description:
        - "Field apps_global"
        type: dict
        required: False
        suboptions:
            log_session_on_established:
                description:
                - "Send TCP session creation log on completion of 3-way handshake"
                type: bool
            msl_time:
                description:
                - "Configure maximum session life, default is 2 seconds (1-40 seconds, default is
          2 seconds)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    shell_privileges:
        description:
        - "Field shell_privileges"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cosq_stats:
        description:
        - "Field cosq_stats"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    cosq_show:
        description:
        - "Field cosq_show"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    fw:
        description:
        - "Field fw"
        type: dict
        required: False
        suboptions:
            application_mempool:
                description:
                - "Enable application memory pool"
                type: bool
            application_flow:
                description:
                - "Number of flows"
                type: int
            basic_dpi_enable:
                description:
                - "Enable basic dpi"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    password_policy:
        description:
        - "Field password_policy"
        type: dict
        required: False
        suboptions:
            complexity:
                description:
                - "'Strict'= Strict= Min length=8, Min Lower Case=2, Min Upper Case=2, Min
          Numbers=2, Min Special Character=1; 'Medium'= Medium= Min length=6, Min Lower
          Case=2, Min Upper Case=2, Min Numbers=1, Min Special Character=1; 'Simple'=
          Simple= Min length=4, Min Lower Case=1, Min Upper Case=1, Min Numbers=1, Min
          Special Character=0;"
                type: str
            aging:
                description:
                - "'Strict'= Strict= Max Age-60 Days; 'Medium'= Medium= Max Age- 90 Days;
          'Simple'= Simple= Max Age-120 Days;"
                type: str
            history:
                description:
                - "'Strict'= Strict= Does not allow upto 5 old passwords; 'Medium'= Medium= Does
          not allow upto 4 old passwords; 'Simple'= Simple= Does not allow upto 3 old
          passwords;"
                type: str
            min_pswd_len:
                description:
                - "Configure custom password length"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    radius:
        description:
        - "Field radius"
        type: dict
        required: False
        suboptions:
            server:
                description:
                - "Field server"
                type: dict
    geoloc_list_list:
        description:
        - "Field geoloc_list_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify name of Geolocation list"
                type: str
            shared:
                description:
                - "Enable sharing with other partitions"
                type: bool
            include_geoloc_name_list:
                description:
                - "Field include_geoloc_name_list"
                type: list
            exclude_geoloc_name_list:
                description:
                - "Field exclude_geoloc_name_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    geoloc_name_helper:
        description:
        - "Field geoloc_name_helper"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    geolocation_file:
        description:
        - "Field geolocation_file"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            error_info:
                description:
                - "Field error_info"
                type: dict
    geoloc:
        description:
        - "Field geoloc"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    geo_location:
        description:
        - "Field geo_location"
        type: dict
        required: False
        suboptions:
            geo_location_iana:
                description:
                - "Load built-in IANA Database"
                type: bool
            geo_location_geolite2_city:
                description:
                - "Load built-in Maxmind GeoLite2-City database. Database available from
          http=//www.maxmind.com"
                type: bool
            geolite2_city_include_ipv6:
                description:
                - "Include IPv6 address"
                type: bool
            geo_location_geolite2_country:
                description:
                - "Load built-in Maxmind GeoLite2-Country database. Database available from
          http=//www.maxmind.com"
                type: bool
            geolite2_country_include_ipv6:
                description:
                - "Include IPv6 address"
                type: bool
            geoloc_load_file_list:
                description:
                - "Field geoloc_load_file_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            entry_list:
                description:
                - "Field entry_list"
                type: list
    fpga_core_crc:
        description:
        - "Field fpga_core_crc"
        type: dict
        required: False
        suboptions:
            monitor_disable:
                description:
                - "Disable FPGA Core CRC error monitoring and act on it"
                type: bool
            reboot_enable:
                description:
                - "Enable system reboot if system encounters FPGA Core CRC error"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    gui_image_list:
        description:
        - "Field gui_image_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    syslog_time_msec:
        description:
        - "Field syslog_time_msec"
        type: dict
        required: False
        suboptions:
            enable_flag:
                description:
                - "Field enable_flag"
                type: bool
    ipmi_service:
        description:
        - "Field ipmi_service"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable IPMI on platform"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    app_performance:
        description:
        - "Field app_performance"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ssl_req_q:
        description:
        - "Field ssl_req_q"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    tcp:
        description:
        - "Field tcp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    icmp:
        description:
        - "Field icmp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    icmp6:
        description:
        - "Field icmp6"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ip_stats:
        description:
        - "Field ip_stats"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ip6_stats:
        description:
        - "Field ip6_stats"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    domain_list_info:
        description:
        - "Field domain_list_info"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ip_dns_cache:
        description:
        - "Field ip_dns_cache"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    bfd:
        description:
        - "Field bfd"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    icmp_rate:
        description:
        - "Field icmp_rate"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns:
        description:
        - "Field dns"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_cache:
        description:
        - "Field dns_cache"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    session:
        description:
        - "Field session"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    ndisc_ra:
        description:
        - "Field ndisc_ra"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    tcp_stats:
        description:
        - "Field tcp_stats"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    telemetry_log:
        description:
        - "Field telemetry_log"
        type: dict
        required: False
        suboptions:
            top_k_source_list:
                description:
                - "Field top_k_source_list"
                type: dict
            top_k_app_svc_list:
                description:
                - "Field top_k_app_svc_list"
                type: dict
            device_status:
                description:
                - "Field device_status"
                type: dict
            partition_metrics:
                description:
                - "Field partition_metrics"
                type: dict

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
    "add_cpu_core",
    "add_port",
    "all_vlan_limit",
    "anomaly_log",
    "app_performance",
    "apps_global",
    "attack",
    "attack_log",
    "bandwidth",
    "bfd",
    "class_list_hitcount_enable",
    "cm_update_file_name_ref",
    "control_cpu",
    "core",
    "cosq_show",
    "cosq_stats",
    "counter_lib_accounting",
    "cpu_hyper_thread",
    "cpu_list",
    "cpu_load_sharing",
    "cpu_map",
    "data_cpu",
    "ddos_attack",
    "ddos_log",
    "deep_hrxq",
    "del_port",
    "delete_cpu_core",
    "dns",
    "dns_cache",
    "domain_list_hitcount_enable",
    "domain_list_info",
    "dynamic_service_dns_socket_pool",
    "environment",
    "fpga_core_crc",
    "fw",
    "geo_db_hitcount_enable",
    "geo_location",
    "geoloc",
    "geoloc_list_list",
    "geoloc_name_helper",
    "geolocation_file",
    "glid",
    "guest_file",
    "gui_image_list",
    "hardware",
    "hardware_forward",
    "hrxq_status",
    "icmp",
    "icmp_rate",
    "icmp6",
    "inuse_cpu_list",
    "inuse_port_list",
    "io_cpu",
    "ip_dns_cache",
    "ip_stats",
    "ip6_stats",
    "ipmi",
    "ipmi_service",
    "ipsec",
    "link_capability",
    "link_monitor",
    "log_cpu_interval",
    "management_interface_mode",
    "memory",
    "mgmt_port",
    "modify_port",
    "module_ctrl_cpu",
    "mon_template",
    "multi_queue_support",
    "ndisc_ra",
    "password_policy",
    "per_vlan_limit",
    "platformtype",
    "port_info",
    "port_list",
    "ports",
    "probe_network_devices",
    "promiscuous_mode",
    "queuing_buffer",
    "radius",
    "reboot",
    "resource_accounting",
    "resource_usage",
    "session",
    "session_reclaim_limit",
    "shared_poll_mode",
    "shell_privileges",
    "shutdown",
    "sockstress_disable",
    "spe_profile",
    "spe_status",
    "src_ip_hash_enable",
    "ssl_req_q",
    "syslog_time_msec",
    "table_integrity_check",
    "tcp",
    "tcp_stats",
    "telemetry_log",
    "template",
    "template_bind",
    "throughput",
    "timeout_value",
    "trunk",
    "trunk_hw_hash",
    "trunk_xaui_hw_hash",
    "upgrade_status",
    "uuid",
    "ve_mac_scheme",
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
        'anomaly_log': {
            'type': 'bool',
        },
        'attack': {
            'type': 'bool',
        },
        'attack_log': {
            'type': 'bool',
        },
        'ddos_attack': {
            'type': 'bool',
        },
        'ddos_log': {
            'type': 'bool',
        },
        'log_cpu_interval': {
            'type': 'int',
        },
        'sockstress_disable': {
            'type': 'bool',
        },
        'promiscuous_mode': {
            'type': 'bool',
        },
        'glid': {
            'type': 'int',
        },
        'module_ctrl_cpu': {
            'type': 'str',
            'choices': ['high', 'low', 'medium']
        },
        'src_ip_hash_enable': {
            'type': 'bool',
        },
        'class_list_hitcount_enable': {
            'type': 'bool',
        },
        'geo_db_hitcount_enable': {
            'type': 'bool',
        },
        'domain_list_hitcount_enable': {
            'type': 'bool',
        },
        'dynamic_service_dns_socket_pool': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'timeout_value': {
            'type': 'dict',
            'ftp': {
                'type': 'int',
            },
            'scp': {
                'type': 'int',
            },
            'sftp': {
                'type': 'int',
            },
            'tftp': {
                'type': 'int',
            },
            'http': {
                'type': 'int',
            },
            'https': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'bandwidth': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices':
                    ['all', 'input-bytes-per-sec', 'output-bytes-per-sec']
                }
            }
        },
        'counter_lib_accounting': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'control_cpu': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'data_cpu': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'mgmt_port': {
            'type': 'dict',
            'port_index': {
                'type': 'int',
            },
            'mac_address': {
                'type': 'str',
            },
            'pci_address': {
                'type': 'str',
            }
        },
        'shared_poll_mode': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'disable': {
                'type': 'bool',
            }
        },
        'probe_network_devices': {
            'type': 'dict',
        },
        'management_interface_mode': {
            'type': 'dict',
            'dedicated': {
                'type': 'bool',
            },
            'non_dedicated': {
                'type': 'bool',
            }
        },
        'add_port': {
            'type': 'dict',
            'port_index': {
                'type': 'int',
            }
        },
        'del_port': {
            'type': 'dict',
            'port_index': {
                'type': 'int',
            }
        },
        'modify_port': {
            'type': 'dict',
            'port_index': {
                'type': 'int',
            },
            'port_number': {
                'type': 'int',
            }
        },
        'multi_queue_support': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            }
        },
        'add_cpu_core': {
            'type': 'dict',
            'core_index': {
                'type': 'int',
            }
        },
        'delete_cpu_core': {
            'type': 'dict',
            'core_index': {
                'type': 'int',
            }
        },
        'cpu_hyper_thread': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'disable': {
                'type': 'bool',
            }
        },
        'io_cpu': {
            'type': 'dict',
            'max_cores': {
                'type': 'int',
            }
        },
        'link_monitor': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'disable': {
                'type': 'bool',
            }
        },
        'port_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'port_info': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'inuse_port_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cpu_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cpu_map': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'inuse_cpu_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'template': {
            'type': 'dict',
            'template_policy': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'template_bind': {
            'type': 'dict',
            'monitor_list': {
                'type': 'list',
                'template_monitor': {
                    'type': 'int',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'mon_template': {
            'type': 'dict',
            'monitor_list': {
                'type': 'list',
                'id': {
                    'type': 'int',
                    'required': True,
                },
                'clear_cfg': {
                    'type': 'list',
                    'sessions': {
                        'type': 'str',
                        'choices': ['all', 'sequence']
                    },
                    'clear_all_sequence': {
                        'type': 'int',
                    },
                    'clear_sequence': {
                        'type': 'int',
                    }
                },
                'link_disable_cfg': {
                    'type': 'list',
                    'diseth': {
                        'type': 'str',
                    },
                    'dis_sequence': {
                        'type': 'int',
                    }
                },
                'link_enable_cfg': {
                    'type': 'list',
                    'enaeth': {
                        'type': 'str',
                    },
                    'ena_sequence': {
                        'type': 'int',
                    }
                },
                'monitor_relation': {
                    'type': 'str',
                    'choices': ['monitor-and', 'monitor-or']
                },
                'link_up_cfg': {
                    'type': 'list',
                    'linkup_ethernet1': {
                        'type': 'str',
                    },
                    'link_up_sequence1': {
                        'type': 'int',
                    },
                    'linkup_ethernet2': {
                        'type': 'str',
                    },
                    'link_up_sequence2': {
                        'type': 'int',
                    },
                    'linkup_ethernet3': {
                        'type': 'str',
                    },
                    'link_up_sequence3': {
                        'type': 'int',
                    }
                },
                'link_down_cfg': {
                    'type': 'list',
                    'linkdown_ethernet1': {
                        'type': 'str',
                    },
                    'link_down_sequence1': {
                        'type': 'int',
                    },
                    'linkdown_ethernet2': {
                        'type': 'str',
                    },
                    'link_down_sequence2': {
                        'type': 'int',
                    },
                    'linkdown_ethernet3': {
                        'type': 'str',
                    },
                    'link_down_sequence3': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            }
        },
        'memory': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'usage-percentage']
                }
            }
        },
        'resource_usage': {
            'type': 'dict',
            'ssl_context_memory': {
                'type': 'int',
            },
            'ssl_dma_memory': {
                'type': 'int',
            },
            'nat_pool_addr_count': {
                'type': 'int',
            },
            'l4_session_count': {
                'type': 'int',
            },
            'auth_portal_html_file_size': {
                'type': 'int',
            },
            'auth_portal_image_file_size': {
                'type': 'int',
            },
            'max_aflex_file_size': {
                'type': 'int',
            },
            'aflex_table_entry_count': {
                'type': 'int',
            },
            'class_list_ipv6_addr_count': {
                'type': 'int',
            },
            'class_list_ac_entry_count': {
                'type': 'int',
            },
            'max_aflex_authz_collection_number': {
                'type': 'int',
            },
            'radius_table_size': {
                'type': 'int',
            },
            'authz_policy_number': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'visibility': {
                'type': 'dict',
                'monitored_entity_count': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'link_capability': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'resource_accounting': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'template_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                },
                'app_resources': {
                    'type': 'dict',
                    'gslb_device_cfg': {
                        'type': 'dict',
                        'gslb_device_max': {
                            'type': 'int',
                        },
                        'gslb_device_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_geo_location_cfg': {
                        'type': 'dict',
                        'gslb_geo_location_max': {
                            'type': 'int',
                        },
                        'gslb_geo_location_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_ip_list_cfg': {
                        'type': 'dict',
                        'gslb_ip_list_max': {
                            'type': 'int',
                        },
                        'gslb_ip_list_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_policy_cfg': {
                        'type': 'dict',
                        'gslb_policy_max': {
                            'type': 'int',
                        },
                        'gslb_policy_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_service_cfg': {
                        'type': 'dict',
                        'gslb_service_max': {
                            'type': 'int',
                        },
                        'gslb_service_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_service_ip_cfg': {
                        'type': 'dict',
                        'gslb_service_ip_max': {
                            'type': 'int',
                        },
                        'gslb_service_ip_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_service_port_cfg': {
                        'type': 'dict',
                        'gslb_service_port_max': {
                            'type': 'int',
                        },
                        'gslb_service_port_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_site_cfg': {
                        'type': 'dict',
                        'gslb_site_max': {
                            'type': 'int',
                        },
                        'gslb_site_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_svc_group_cfg': {
                        'type': 'dict',
                        'gslb_svc_group_max': {
                            'type': 'int',
                        },
                        'gslb_svc_group_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_template_cfg': {
                        'type': 'dict',
                        'gslb_template_max': {
                            'type': 'int',
                        },
                        'gslb_template_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'gslb_zone_cfg': {
                        'type': 'dict',
                        'gslb_zone_max': {
                            'type': 'int',
                        },
                        'gslb_zone_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'health_monitor_cfg': {
                        'type': 'dict',
                        'health_monitor_max': {
                            'type': 'int',
                        },
                        'health_monitor_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'real_port_cfg': {
                        'type': 'dict',
                        'real_port_max': {
                            'type': 'int',
                        },
                        'real_port_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'real_server_cfg': {
                        'type': 'dict',
                        'real_server_max': {
                            'type': 'int',
                        },
                        'real_server_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'service_group_cfg': {
                        'type': 'dict',
                        'service_group_max': {
                            'type': 'int',
                        },
                        'service_group_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'virtual_server_cfg': {
                        'type': 'dict',
                        'virtual_server_max': {
                            'type': 'int',
                        },
                        'virtual_server_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'threshold': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'network_resources': {
                    'type': 'dict',
                    'static_ipv4_route_cfg': {
                        'type': 'dict',
                        'static_ipv4_route_max': {
                            'type': 'int',
                        },
                        'static_ipv4_route_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'static_ipv6_route_cfg': {
                        'type': 'dict',
                        'static_ipv6_route_max': {
                            'type': 'int',
                        },
                        'static_ipv6_route_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'ipv4_acl_line_cfg': {
                        'type': 'dict',
                        'ipv4_acl_line_max': {
                            'type': 'int',
                        },
                        'ipv4_acl_line_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'ipv6_acl_line_cfg': {
                        'type': 'dict',
                        'ipv6_acl_line_max': {
                            'type': 'int',
                        },
                        'ipv6_acl_line_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'static_arp_cfg': {
                        'type': 'dict',
                        'static_arp_max': {
                            'type': 'int',
                        },
                        'static_arp_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'static_neighbor_cfg': {
                        'type': 'dict',
                        'static_neighbor_max': {
                            'type': 'int',
                        },
                        'static_neighbor_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'static_mac_cfg': {
                        'type': 'dict',
                        'static_mac_max': {
                            'type': 'int',
                        },
                        'static_mac_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'object_group_cfg': {
                        'type': 'dict',
                        'object_group_max': {
                            'type': 'int',
                        },
                        'object_group_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'object_group_clause_cfg': {
                        'type': 'dict',
                        'object_group_clause_max': {
                            'type': 'int',
                        },
                        'object_group_clause_min_guarantee': {
                            'type': 'int',
                        }
                    },
                    'threshold': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'system_resources': {
                    'type': 'dict',
                    'bw_limit_cfg': {
                        'type': 'dict',
                        'bw_limit_max': {
                            'type': 'int',
                        },
                        'bw_limit_watermark_disable': {
                            'type': 'bool',
                        }
                    },
                    'concurrent_session_limit_cfg': {
                        'type': 'dict',
                        'concurrent_session_limit_max': {
                            'type': 'int',
                        }
                    },
                    'l4_session_limit_cfg': {
                        'type': 'dict',
                        'l4_session_limit_max': {
                            'type': 'str',
                        },
                        'l4_session_limit_min_guarantee': {
                            'type': 'str',
                        }
                    },
                    'l4cps_limit_cfg': {
                        'type': 'dict',
                        'l4cps_limit_max': {
                            'type': 'int',
                        }
                    },
                    'l7cps_limit_cfg': {
                        'type': 'dict',
                        'l7cps_limit_max': {
                            'type': 'int',
                        }
                    },
                    'natcps_limit_cfg': {
                        'type': 'dict',
                        'natcps_limit_max': {
                            'type': 'int',
                        }
                    },
                    'fwcps_limit_cfg': {
                        'type': 'dict',
                        'fwcps_limit_max': {
                            'type': 'int',
                        }
                    },
                    'ssl_throughput_limit_cfg': {
                        'type': 'dict',
                        'ssl_throughput_limit_max': {
                            'type': 'int',
                        },
                        'ssl_throughput_limit_watermark_disable': {
                            'type': 'bool',
                        }
                    },
                    'sslcps_limit_cfg': {
                        'type': 'dict',
                        'sslcps_limit_max': {
                            'type': 'int',
                        }
                    },
                    'threshold': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            }
        },
        'trunk': {
            'type': 'dict',
            'load_balance': {
                'type': 'dict',
                'use_l3': {
                    'type': 'bool',
                },
                'use_l4': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'ports': {
            'type': 'dict',
            'link_detection_interval': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'table_integrity_check': {
            'type': 'dict',
            'action': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'ipsec': {
            'type': 'dict',
            'packet_round_robin': {
                'type': 'bool',
            },
            'crypto_core': {
                'type': 'int',
            },
            'crypto_mem': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'fpga_decrypt': {
                'type': 'dict',
                'action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                }
            }
        },
        'spe_profile': {
            'type': 'dict',
            'action': {
                'type': 'str',
                'choices': ['ipv4-only', 'ipv6-only', 'ipv4-ipv6']
            }
        },
        'spe_status': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'deep_hrxq': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            }
        },
        'hrxq_status': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cpu_load_sharing': {
            'type': 'dict',
            'disable': {
                'type': 'bool',
            },
            'packets_per_second': {
                'type': 'dict',
                'min': {
                    'type': 'int',
                }
            },
            'cpu_usage': {
                'type': 'dict',
                'low': {
                    'type': 'int',
                },
                'high': {
                    'type': 'int',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'per_vlan_limit': {
            'type': 'dict',
            'bcast': {
                'type': 'int',
            },
            'ipmcast': {
                'type': 'int',
            },
            'mcast': {
                'type': 'int',
            },
            'unknown_ucast': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'all_vlan_limit': {
            'type': 'dict',
            'bcast': {
                'type': 'int',
            },
            'ipmcast': {
                'type': 'int',
            },
            'mcast': {
                'type': 'int',
            },
            'unknown_ucast': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        've_mac_scheme': {
            'type': 'dict',
            've_mac_scheme_val': {
                'type': 'str',
                'choices': ['hash-based', 'round-robin', 'system-mac']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'session_reclaim_limit': {
            'type': 'dict',
            'nscan_limit': {
                'type': 'int',
            },
            'scan_freq': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'hardware': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'platformtype': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'reboot': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'shutdown': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'environment': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'hardware_forward': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'hit-counts', 'hit-index',
                        'ipv4-forward-counts', 'ipv6-forward-counts',
                        'hw-fwd-module-status', 'hw-fwd-prog-reqs',
                        'hw-fwd-prog-errors', 'hw-fwd-flow-singlebit-errors',
                        'hw-fwd-flow-tag-mismatch', 'hw-fwd-flow-seq-mismatch',
                        'hw-fwd-ageout-drop-count', 'hw-fwd-invalidation-drop',
                        'hw-fwd-flow-hit-index', 'hw-fwd-flow-reason-flags',
                        'hw-fwd-flow-drop-count', 'hw-fwd-flow-error-count',
                        'hw-fwd-flow-unalign-count',
                        'hw-fwd-flow-underflow-count',
                        'hw-fwd-flow-tx-full-drop',
                        'hw-fwd-flow-qdr-full-drop',
                        'hw-fwd-phyport-mismatch-drop',
                        'hw-fwd-vlanid-mismatch-drop', 'hw-fwd-vmid-drop',
                        'hw-fwd-protocol-mismatch-drop',
                        'hw-fwd-avail-ipv4-entry', 'hw-fwd-avail-ipv6-entry',
                        'hw-fwd-entry-create', 'hw-fwd-entry-create-failure',
                        'hw-fwd-entry-create-fail-server-down',
                        'hw-fwd-entry-create-fail-max-entry',
                        'hw-fwd-entry-free', 'hw-fwd-entry-free-opp-entry',
                        'hw-fwd-entry-free-no-hw-prog',
                        'hw-fwd-entry-free-no-conn',
                        'hw-fwd-entry-free-no-sw-entry',
                        'hw-fwd-entry-counter', 'hw-fwd-entry-age-out',
                        'hw-fwd-entry-age-out-idle',
                        'hw-fwd-entry-age-out-tcp-fin',
                        'hw-fwd-entry-age-out-tcp-rst',
                        'hw-fwd-entry-age-out-invalid-dst',
                        'hw-fwd-entry-force-hw-invalidate',
                        'hw-fwd-entry-invalidate-server-down',
                        'hw-fwd-tcam-create', 'hw-fwd-tcam-free',
                        'hw-fwd-tcam-counter'
                    ]
                }
            }
        },
        'throughput': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'global-system-throughput-bits-per-sec',
                        'per-part-throughput-bits-per-sec'
                    ]
                }
            }
        },
        'ipmi': {
            'type': 'dict',
            'reset': {
                'type': 'bool',
            },
            'ip': {
                'type': 'dict',
                'ipv4_address': {
                    'type': 'str',
                },
                'ipv4_netmask': {
                    'type': 'str',
                },
                'default_gateway': {
                    'type': 'str',
                }
            },
            'ipsrc': {
                'type': 'dict',
                'dhcp': {
                    'type': 'bool',
                },
                'static': {
                    'type': 'bool',
                }
            },
            'user': {
                'type': 'dict',
                'add': {
                    'type': 'str',
                },
                'password': {
                    'type': 'str',
                },
                'administrator': {
                    'type': 'bool',
                },
                'callback': {
                    'type': 'bool',
                },
                'operator': {
                    'type': 'bool',
                },
                'user': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'str',
                },
                'privilege': {
                    'type': 'str',
                },
                'setname': {
                    'type': 'str',
                },
                'newname': {
                    'type': 'str',
                },
                'setpass': {
                    'type': 'str',
                },
                'newpass': {
                    'type': 'str',
                }
            },
            'tool': {
                'type': 'dict',
                'cmd': {
                    'type': 'str',
                }
            }
        },
        'queuing_buffer': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'trunk_hw_hash': {
            'type': 'dict',
            'mode': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'trunk_xaui_hw_hash': {
            'type': 'dict',
            'mode': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'upgrade_status': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'guest_file': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cm_update_file_name_ref': {
            'type': 'dict',
            'source_name': {
                'type': 'str',
            },
            'dest_name': {
                'type': 'str',
            },
            'id': {
                'type': 'int',
            }
        },
        'core': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'apps_global': {
            'type': 'dict',
            'log_session_on_established': {
                'type': 'bool',
            },
            'msl_time': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'shell_privileges': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cosq_stats': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'cosq_show': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'fw': {
            'type': 'dict',
            'application_mempool': {
                'type': 'bool',
            },
            'application_flow': {
                'type': 'int',
            },
            'basic_dpi_enable': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'password_policy': {
            'type': 'dict',
            'complexity': {
                'type': 'str',
                'choices': ['Strict', 'Medium', 'Simple']
            },
            'aging': {
                'type': 'str',
                'choices': ['Strict', 'Medium', 'Simple']
            },
            'history': {
                'type': 'str',
                'choices': ['Strict', 'Medium', 'Simple']
            },
            'min_pswd_len': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'radius': {
            'type': 'dict',
            'server': {
                'type': 'dict',
                'listen_port': {
                    'type': 'int',
                },
                'remote': {
                    'type': 'dict',
                    'ip_list': {
                        'type': 'list',
                        'ip_list_name': {
                            'type': 'str',
                        },
                        'ip_list_secret': {
                            'type': 'bool',
                        },
                        'ip_list_secret_string': {
                            'type': 'str',
                        },
                        'ip_list_encrypted': {
                            'type': 'str',
                        }
                    }
                },
                'secret': {
                    'type': 'bool',
                },
                'secret_string': {
                    'type': 'str',
                },
                'encrypted': {
                    'type': 'str',
                },
                'vrid': {
                    'type': 'int',
                },
                'attribute': {
                    'type': 'list',
                    'attribute_value': {
                        'type':
                        'str',
                        'choices': [
                            'inside-ipv6-prefix', 'inside-ip', 'inside-ipv6',
                            'imei', 'imsi', 'msisdn', 'custom1', 'custom2',
                            'custom3'
                        ]
                    },
                    'prefix_length': {
                        'type': 'str',
                        'choices': ['32', '48', '64', '80', '96', '112']
                    },
                    'prefix_vendor': {
                        'type': 'int',
                    },
                    'prefix_number': {
                        'type': 'int',
                    },
                    'name': {
                        'type': 'str',
                    },
                    'value': {
                        'type': 'str',
                        'choices': ['hexadecimal']
                    },
                    'custom_vendor': {
                        'type': 'int',
                    },
                    'custom_number': {
                        'type': 'int',
                    },
                    'vendor': {
                        'type': 'int',
                    },
                    'number': {
                        'type': 'int',
                    }
                },
                'disable_reply': {
                    'type': 'bool',
                },
                'accounting_start': {
                    'type': 'str',
                    'choices': ['ignore', 'append-entry', 'replace-entry']
                },
                'accounting_stop': {
                    'type':
                    'str',
                    'choices':
                    ['ignore', 'delete-entry', 'delete-entry-and-sessions']
                },
                'accounting_interim_update': {
                    'type': 'str',
                    'choices': ['ignore', 'append-entry', 'replace-entry']
                },
                'accounting_on': {
                    'type': 'str',
                    'choices': ['ignore', 'delete-entries-using-attribute']
                },
                'attribute_name': {
                    'type':
                    'str',
                    'choices': [
                        'msisdn', 'imei', 'imsi', 'custom1', 'custom2',
                        'custom3'
                    ]
                },
                'uuid': {
                    'type': 'str',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type':
                        'str',
                        'choices': [
                            'all', 'msisdn-received', 'imei-received',
                            'imsi-received', 'custom-received',
                            'radius-request-received',
                            'radius-request-dropped',
                            'request-bad-secret-dropped',
                            'request-no-key-vap-dropped',
                            'request-malformed-dropped', 'request-ignored',
                            'radius-table-full',
                            'secret-not-configured-dropped',
                            'ha-standby-dropped',
                            'ipv6-prefix-length-mismatch', 'invalid-key',
                            'smp-created', 'smp-deleted', 'smp-mem-allocated',
                            'smp-mem-alloc-failed', 'smp-mem-freed',
                            'smp-in-rml', 'mem-allocated', 'mem-alloc-failed',
                            'mem-freed', 'ha-sync-create-sent',
                            'ha-sync-delete-sent', 'ha-sync-create-recv',
                            'ha-sync-delete-recv', 'acct-on-filters-full',
                            'acct-on-dup-request', 'ip-mismatch-delete',
                            'ip-add-race-drop', 'ha-sync-no-key-vap-dropped',
                            'inter-card-msg-fail-drop',
                            'radius-packets-redirected',
                            'radius-packets-redirect-fail-dropped',
                            'radius-packets-process-local',
                            'radius-packets-dropped-not-lo'
                        ]
                    }
                }
            }
        },
        'geoloc_list_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'shared': {
                'type': 'bool',
            },
            'include_geoloc_name_list': {
                'type': 'list',
                'include_geoloc_name_val': {
                    'type': 'str',
                }
            },
            'exclude_geoloc_name_list': {
                'type': 'list',
                'exclude_geoloc_name_val': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            },
            'user_tag': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices':
                    ['all', 'hit-count', 'total-geoloc', 'total-active']
                }
            }
        },
        'geoloc_name_helper': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'place-holder']
                }
            }
        },
        'geolocation_file': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'error_info': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'geoloc': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'place-holder']
                }
            }
        },
        'geo_location': {
            'type': 'dict',
            'geo_location_iana': {
                'type': 'bool',
            },
            'geo_location_geolite2_city': {
                'type': 'bool',
            },
            'geolite2_city_include_ipv6': {
                'type': 'bool',
            },
            'geo_location_geolite2_country': {
                'type': 'bool',
            },
            'geolite2_country_include_ipv6': {
                'type': 'bool',
            },
            'geoloc_load_file_list': {
                'type': 'list',
                'geo_location_load_filename': {
                    'type': 'str',
                },
                'template_name': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            },
            'entry_list': {
                'type': 'list',
                'geo_locn_obj_name': {
                    'type': 'str',
                    'required': True,
                },
                'geo_locn_multiple_addresses': {
                    'type': 'list',
                    'first_ip_address': {
                        'type': 'str',
                    },
                    'geol_ipv4_mask': {
                        'type': 'str',
                    },
                    'ip_addr2': {
                        'type': 'str',
                    },
                    'first_ipv6_address': {
                        'type': 'str',
                    },
                    'geol_ipv6_mask': {
                        'type': 'int',
                    },
                    'ipv6_addr2': {
                        'type': 'str',
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            }
        },
        'fpga_core_crc': {
            'type': 'dict',
            'monitor_disable': {
                'type': 'bool',
            },
            'reboot_enable': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'gui_image_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'syslog_time_msec': {
            'type': 'dict',
            'enable_flag': {
                'type': 'bool',
            }
        },
        'ipmi_service': {
            'type': 'dict',
            'disable': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'app_performance': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'total-throughput-bits-per-sec',
                        'l4-conns-per-sec', 'l7-conns-per-sec',
                        'l7-trans-per-sec', 'ssl-conns-per-sec',
                        'ip-nat-conns-per-sec', 'total-new-conns-per-sec',
                        'total-curr-conns', 'l4-bandwidth', 'l7-bandwidth',
                        'serv-ssl-conns-per-sec', 'fw-conns-per-sec',
                        'gifw-conns-per-sec'
                    ]
                }
            }
        },
        'ssl_req_q': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'num-ssl-queues', 'ssl-req-q-depth-tot',
                        'ssl-req-q-inuse-tot', 'ssl-hw-q-depth-tot',
                        'ssl-hw-q-inuse-tot'
                    ]
                }
            }
        },
        'tcp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'activeopens', 'passiveopens', 'attemptfails',
                        'estabresets', 'insegs', 'outsegs', 'retranssegs',
                        'inerrs', 'outrsts', 'sock_alloc', 'orphan_count',
                        'mem_alloc', 'recv_mem', 'send_mem', 'currestab',
                        'currsyssnt', 'currsynrcv', 'currfinw1', 'currfinw2',
                        'currtimew', 'currclose', 'currclsw', 'currlack',
                        'currlstn', 'currclsg', 'pawsactiverejected',
                        'syn_rcv_rstack', 'syn_rcv_rst', 'syn_rcv_ack',
                        'ax_rexmit_syn', 'tcpabortontimeout', 'noroute',
                        'exceedmss', 'tfo_conns', 'tfo_actives', 'tfo_denied'
                    ]
                }
            }
        },
        'icmp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'num', 'inmsgs', 'inerrors', 'indestunreachs',
                        'intimeexcds', 'inparmprobs', 'insrcquenchs',
                        'inredirects', 'inechos', 'inechoreps', 'intimestamps',
                        'intimestampreps', 'inaddrmasks', 'inaddrmaskreps',
                        'outmsgs', 'outerrors', 'outdestunreachs',
                        'outtimeexcds', 'outparmprobs', 'outsrcquenchs',
                        'outredirects', 'outechos', 'outechoreps',
                        'outtimestamps', 'outtimestampreps', 'outaddrmasks',
                        'outaddrmaskreps'
                    ]
                }
            }
        },
        'icmp6': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'in_msgs', 'in_errors', 'in_dest_un_reach',
                        'in_pkt_too_big', 'in_time_exceeds', 'in_param_prob',
                        'in_echoes', 'in_exho_reply', 'in_grp_mem_query',
                        'in_grp_mem_resp', 'in_grp_mem_reduction',
                        'in_router_sol', 'in_ra', 'in_ns', 'in_na',
                        'in_redirect', 'out_msg', 'out_dst_un_reach',
                        'out_pkt_too_big', 'out_time_exceeds',
                        'out_param_prob', 'out_echo_req', 'out_echo_replies',
                        'out_rs', 'out_ra', 'out_ns', 'out_na',
                        'out_redirects', 'out_mem_resp', 'out_mem_reductions',
                        'err_rs', 'err_ra', 'err_ns', 'err_na',
                        'err_redirects', 'err_echoes', 'err_echo_replies'
                    ]
                }
            }
        },
        'ip_stats': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'inreceives', 'inhdrerrors', 'intoobigerrors',
                        'innoroutes', 'inaddrerrors', 'inunknownprotos',
                        'intruncatedpkts', 'indiscards', 'indelivers',
                        'outforwdatagrams', 'outrequests', 'outdiscards',
                        'outnoroutes', 'reasmtimeout', 'reasmreqds',
                        'reasmoks', 'reasmfails', 'fragoks', 'fragfails',
                        'fragcreates', 'inmcastpkts', 'outmcastpkts'
                    ]
                }
            }
        },
        'ip6_stats': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'inreceives', 'inhdrerrors', 'intoobigerrors',
                        'innoroutes', 'inaddrerrors', 'inunknownprotos',
                        'intruncatedpkts', 'indiscards', 'indelivers',
                        'outforwdatagrams', 'outrequests', 'outdiscards',
                        'outnoroutes', 'reasmtimeout', 'reasmreqds',
                        'reasmoks', 'reasmfails', 'fragoks', 'fragfails',
                        'fragcreates', 'inmcastpkts', 'outmcastpkts'
                    ]
                }
            }
        },
        'domain_list_info': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'ip_dns_cache': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'bfd': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'ip_checksum_error', 'udp_checksum_error',
                        'session_not_found', 'multihop_mismatch',
                        'version_mismatch', 'length_too_small',
                        'data_is_short', 'invalid_detect_mult',
                        'invalid_multipoint', 'invalid_my_disc', 'invalid_ttl',
                        'auth_length_invalid', 'auth_mismatch',
                        'auth_type_mismatch', 'auth_key_id_mismatch',
                        'auth_key_mismatch', 'auth_seqnum_invalid',
                        'auth_failed', 'local_state_admin_down',
                        'dest_unreachable', 'no_ipv6_enable', 'other_error'
                    ]
                }
            }
        },
        'icmp_rate': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'over_limit_drop', 'limit_intf_drop',
                        'limit_vserver_drop', 'limit_total_drop',
                        'lockup_time_left', 'curr_rate', 'v6_over_limit_drop',
                        'v6_limit_intf_drop', 'v6_limit_vserver_drop',
                        'v6_limit_total_drop', 'v6_lockup_time_left',
                        'v6_curr_rate'
                    ]
                }
            }
        },
        'dns': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'slb_req', 'slb_resp', 'slb_no_resp',
                        'slb_req_rexmit', 'slb_resp_no_match',
                        'slb_no_resource', 'nat_req', 'nat_resp',
                        'nat_no_resp', 'nat_req_rexmit', 'nat_resp_no_match',
                        'nat_no_resource', 'nat_xid_reused'
                    ]
                }
            }
        },
        'dns_cache': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'total_q', 'total_r', 'hit', 'bad_q',
                        'encode_q', 'multiple_q', 'oversize_q', 'bad_r',
                        'oversize_r', 'encode_r', 'multiple_r', 'answer_r',
                        'ttl_r', 'ageout', 'bad_answer', 'ageout_weight',
                        'total_log', 'total_alloc', 'total_freed',
                        'current_allocate', 'current_data_allocate'
                    ]
                }
            }
        },
        'session': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'total_l4_conn', 'conn_counter',
                        'conn_freed_counter', 'total_l4_packet_count',
                        'total_l7_packet_count', 'total_l4_conn_proxy',
                        'total_l7_conn', 'total_tcp_conn', 'curr_free_conn',
                        'tcp_est_counter', 'tcp_half_open_counter',
                        'tcp_half_close_counter', 'udp_counter', 'ip_counter',
                        'other_counter', 'reverse_nat_tcp_counter',
                        'reverse_nat_udp_counter', 'tcp_syn_half_open_counter',
                        'conn_smp_alloc_counter', 'conn_smp_free_counter',
                        'conn_smp_aged_counter', 'ssl_count_curr',
                        'ssl_count_total', 'server_ssl_count_curr',
                        'server_ssl_count_total', 'client_ssl_reuse_total',
                        'server_ssl_reuse_total', 'ssl_failed_total',
                        'ssl_failed_ca_verification', 'ssl_server_cert_error',
                        'ssl_client_cert_auth_fail', 'total_ip_nat_conn',
                        'total_l2l3_conn', 'client_ssl_ctx_malloc_failure',
                        'conn_type_0_available', 'conn_type_1_available',
                        'conn_type_2_available', 'conn_type_3_available',
                        'conn_type_4_available', 'conn_smp_type_0_available',
                        'conn_smp_type_1_available',
                        'conn_smp_type_2_available',
                        'conn_smp_type_3_available',
                        'conn_smp_type_4_available', 'sctp-half-open-counter',
                        'sctp-est-counter', 'nonssl_bypass',
                        'ssl_failsafe_total',
                        'ssl_forward_proxy_failed_handshake_total',
                        'ssl_forward_proxy_failed_tcp_total',
                        'ssl_forward_proxy_failed_crypto_total',
                        'ssl_forward_proxy_failed_cert_verify_total',
                        'ssl_forward_proxy_invalid_ocsp_stapling_total',
                        'ssl_forward_proxy_revoked_ocsp_total',
                        'ssl_forward_proxy_failed_cert_signing_total',
                        'ssl_forward_proxy_failed_ssl_version_total',
                        'ssl_forward_proxy_sni_bypass_total',
                        'ssl_forward_proxy_client_auth_bypass_total',
                        'conn_app_smp_alloc_counter', 'diameter_conn_counter',
                        'diameter_conn_freed_counter', 'debug_tcp_counter',
                        'debug_udp_counter', 'total_fw_conn',
                        'total_local_conn', 'total_curr_conn',
                        'client_ssl_fatal_alert', 'client_ssl_fin_rst',
                        'fp_session_fin_rst', 'server_ssl_fatal_alert',
                        'server_ssl_fin_rst', 'client_template_int_err',
                        'client_template_unknown_err',
                        'server_template_int_err',
                        'server_template_unknown_err', 'total_debug_conn',
                        'ssl_forward_proxy_failed_aflex_total',
                        'ssl_forward_proxy_cert_subject_bypass_total',
                        'ssl_forward_proxy_cert_issuer_bypass_total',
                        'ssl_forward_proxy_cert_san_bypass_total',
                        'ssl_forward_proxy_no_sni_bypass_total',
                        'ssl_forward_proxy_no_sni_reset_total',
                        'ssl_forward_proxy_username_bypass_total',
                        'ssl_forward_proxy_ad_grpup_bypass_total',
                        'diameter_concurrent_user_sessions_counter'
                    ]
                }
            }
        },
        'ndisc_ra': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'good_recv', 'periodic_sent', 'rate_limit',
                        'bad_hop_limit', 'truncated', 'bad_icmpv6_csum',
                        'bad_icmpv6_code', 'bad_icmpv6_option',
                        'l2_addr_and_unspec', 'no_free_buffers'
                    ]
                }
            }
        },
        'tcp_stats': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'connattempt', 'connects', 'drops', 'conndrops',
                        'closed', 'segstimed', 'rttupdated', 'delack',
                        'timeoutdrop', 'rexmttimeo', 'persisttimeo',
                        'keeptimeo', 'keepprobe', 'keepdrops', 'sndtotal',
                        'sndpack', 'sndbyte', 'sndrexmitpack', 'sndrexmitbyte',
                        'sndrexmitbad', 'sndacks', 'sndprobe', 'sndurg',
                        'sndwinup', 'sndctrl', 'sndrst', 'sndfin', 'sndsyn',
                        'rcvtotal', 'rcvpack', 'rcvbyte', 'rcvbadoff',
                        'rcvmemdrop', 'rcvduppack', 'rcvdupbyte',
                        'rcvpartduppack', 'rcvpartdupbyte', 'rcvoopack',
                        'rcvoobyte', 'rcvpackafterwin', 'rcvbyteafterwin',
                        'rcvwinprobe', 'rcvdupack', 'rcvacktoomuch',
                        'rcvackpack', 'rcvackbyte', 'rcvwinupd', 'pawsdrop',
                        'predack', 'preddat', 'persistdrop', 'badrst',
                        'finwait2_drops', 'sack_recovery_episode',
                        'sack_rexmits', 'sack_rexmit_bytes', 'sack_rcv_blocks',
                        'sack_send_blocks', 'sndcack', 'cacklim',
                        'reassmemdrop', 'reasstimeout', 'cc_idle', 'cc_reduce',
                        'rcvdsack', 'a2brcvwnd', 'a2bsackpresent', 'a2bdupack',
                        'a2brxdata', 'a2btcpoptions', 'a2boodata',
                        'a2bpartialack', 'a2bfsmtransition',
                        'a2btransitionnum', 'b2atransitionnum', 'bad_iochan',
                        'atcpforward', 'atcpsent', 'atcprexmitsadrop',
                        'atcpsendbackack', 'atcprexmit', 'atcpbuffallocfail',
                        'a2bappbuffering', 'atcpsendfail', 'earlyrexmit',
                        'mburstlim', 'a2bsndwnd', 'proxyheaderv1',
                        'proxyheaderv2'
                    ]
                }
            }
        },
        'telemetry_log': {
            'type': 'dict',
            'top_k_source_list': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                }
            },
            'top_k_app_svc_list': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                }
            },
            'device_status': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                }
            },
            'partition_metrics': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["system"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["system"].get(k) != v:
            change_results["changed"] = True
            config_changes["system"][k] = v

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
    payload = utils.build_json("system", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "system"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "system-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
