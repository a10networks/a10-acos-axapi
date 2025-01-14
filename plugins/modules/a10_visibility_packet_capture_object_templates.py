#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_object_templates
description:
    - Configure object packet capture templates for T2 counters
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    templ_gtp_plcy_tmpl_list:
        description:
        - "Field templ_gtp_plcy_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    interface_ethernet_tmpl_list:
        description:
        - "Field interface_ethernet_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    interface_tunnel_tmpl_list:
        description:
        - "Field interface_tunnel_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_jwt_authorization_tmpl_list:
        description:
        - "Field aam_jwt_authorization_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_aaa_policy_tmpl_list:
        description:
        - "Field aam_aaa_policy_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_logon_http_ins_tmpl_list:
        description:
        - "Field aam_auth_logon_http_ins_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_server_ldap_inst_tmpl_list:
        description:
        - "Field aam_auth_server_ldap_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_server_ocsp_inst_tmpl_list:
        description:
        - "Field aam_auth_server_ocsp_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_server_rad_inst_tmpl_list:
        description:
        - "Field aam_auth_server_rad_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_server_win_inst_tmpl_list:
        description:
        - "Field aam_auth_server_win_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_saml_service_prov_tmpl_list:
        description:
        - "Field aam_auth_saml_service_prov_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_saml_id_prov_tmpl_list:
        description:
        - "Field aam_auth_saml_id_prov_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_service_group_tmpl_list:
        description:
        - "Field aam_auth_service_group_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_service_group_mem_tmpl_list:
        description:
        - "Field aam_auth_service_group_mem_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_relay_hbase_inst_tmpl_list:
        description:
        - "Field aam_auth_relay_hbase_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_relay_form_inst_tmpl_list:
        description:
        - "Field aam_auth_relay_form_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_relay_ws_fed_tmpl_list:
        description:
        - "Field aam_auth_relay_ws_fed_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    aam_auth_captcha_inst_tmpl_list:
        description:
        - "Field aam_auth_captcha_inst_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    slb_templ_cache_tmpl_list:
        description:
        - "Field slb_templ_cache_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    slb_port_tmpl_list:
        description:
        - "Field slb_port_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    slb_service_tmpl_list:
        description:
        - "Field slb_service_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    slb_vport_tmpl_list:
        description:
        - "Field slb_vport_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    cgnv6_serv_group_tmpl_list:
        description:
        - "Field cgnv6_serv_group_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    cgnv6_dns64_vs_port_tmpl_list:
        description:
        - "Field cgnv6_dns64_vs_port_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    cgnv6_map_trans_domain_tmpl_list:
        description:
        - "Field cgnv6_map_trans_domain_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    cgnv6_encap_domain_tmpl_list:
        description:
        - "Field cgnv6_encap_domain_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    netflow_monitor_tmpl_list:
        description:
        - "Field netflow_monitor_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    rule_set_tmpl_list:
        description:
        - "Field rule_set_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    rule_set_rule_tmpl_list:
        description:
        - "Field rule_set_rule_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    fw_server_port_tmpl_list:
        description:
        - "Field fw_server_port_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    fw_service_group_tmpl_list:
        description:
        - "Field fw_service_group_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    fw_service_group_mem_tmpl_list:
        description:
        - "Field fw_service_group_mem_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    dns_vport_tmpl_list:
        description:
        - "Field dns_vport_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    smtp_vport_tmpl_list:
        description:
        - "Field smtp_vport_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    pop3_vport_tmpl_list:
        description:
        - "Field pop3_vport_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
                type: dict
    imap_vport_tmpl_list:
        description:
        - "Field imap_vport_tmpl_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Packet Capture Template Name"
                type: str
            capture_config:
                description:
                - "Specify name of the capture-config to use with this template"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            trigger_stats_severity:
                description:
                - "Field trigger_stats_severity"
                type: dict
            trigger_stats_inc:
                description:
                - "Field trigger_stats_inc"
                type: dict
            trigger_stats_rate:
                description:
                - "Field trigger_stats_rate"
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
    "aam_aaa_policy_tmpl_list", "aam_auth_captcha_inst_tmpl_list", "aam_auth_logon_http_ins_tmpl_list", "aam_auth_relay_form_inst_tmpl_list", "aam_auth_relay_hbase_inst_tmpl_list", "aam_auth_relay_ws_fed_tmpl_list", "aam_auth_saml_id_prov_tmpl_list", "aam_auth_saml_service_prov_tmpl_list", "aam_auth_server_ldap_inst_tmpl_list",
    "aam_auth_server_ocsp_inst_tmpl_list", "aam_auth_server_rad_inst_tmpl_list", "aam_auth_server_win_inst_tmpl_list", "aam_auth_service_group_mem_tmpl_list", "aam_auth_service_group_tmpl_list", "aam_jwt_authorization_tmpl_list", "cgnv6_dns64_vs_port_tmpl_list", "cgnv6_encap_domain_tmpl_list", "cgnv6_map_trans_domain_tmpl_list",
    "cgnv6_serv_group_tmpl_list", "dns_vport_tmpl_list", "fw_server_port_tmpl_list", "fw_service_group_mem_tmpl_list", "fw_service_group_tmpl_list", "imap_vport_tmpl_list", "interface_ethernet_tmpl_list", "interface_tunnel_tmpl_list", "netflow_monitor_tmpl_list", "pop3_vport_tmpl_list", "rule_set_rule_tmpl_list", "rule_set_tmpl_list",
    "slb_port_tmpl_list", "slb_service_tmpl_list", "slb_templ_cache_tmpl_list", "slb_vport_tmpl_list", "smtp_vport_tmpl_list", "templ_gtp_plcy_tmpl_list", "uuid",
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
        'uuid': {
            'type': 'str',
            },
        'templ_gtp_plcy_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'drop_vld_gtp_ie_repeat_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_field_set': {
                    'type': 'bool',
                    },
                'drop_vld_tunnel_id_flag': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_flow_label_v0': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_teid': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_ie_in_grouped_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_order_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state_ie': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_version_not_supported': {
                    'type': 'bool',
                    },
                'drop_vld_message_length': {
                    'type': 'bool',
                    },
                'drop_vld_cross_layer_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_country_code_mismatch': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_u_spoofed_source_address': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_bearer_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                    'type': 'bool',
                    },
                'drop_vld_v0_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_v1_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_v2_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_pkt_len_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sanity_failed_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sequence_num_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv0_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv1_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv2_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_imsi_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_apn_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_protocol_flag_unset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'drop_vld_gtp_ie_repeat_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_field_set': {
                    'type': 'bool',
                    },
                'drop_vld_tunnel_id_flag': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_flow_label_v0': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_teid': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_mandatory_ie_in_grouped_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_order_ie': {
                    'type': 'bool',
                    },
                'drop_vld_out_of_state_ie': {
                    'type': 'bool',
                    },
                'drop_vld_reserved_information_element': {
                    'type': 'bool',
                    },
                'drop_vld_version_not_supported': {
                    'type': 'bool',
                    },
                'drop_vld_message_length': {
                    'type': 'bool',
                    },
                'drop_vld_cross_layer_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_country_code_mismatch': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_u_spoofed_source_address': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_bearer_count_exceed': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                    'type': 'bool',
                    },
                'drop_vld_v0_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_v1_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_v2_reserved_message_drop': {
                    'type': 'bool',
                    },
                'drop_vld_invalid_pkt_len_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sanity_failed_piggyback': {
                    'type': 'bool',
                    },
                'drop_vld_sequence_num_correlation': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv0_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv1_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtpv2_seqnum_buffer_full': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_imsi_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_gtp_invalid_apn_len_drop': {
                    'type': 'bool',
                    },
                'drop_vld_protocol_flag_unset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'interface_ethernet_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'input_errors': {
                    'type': 'bool',
                    },
                'crc': {
                    'type': 'bool',
                    },
                'runts': {
                    'type': 'bool',
                    },
                'giants': {
                    'type': 'bool',
                    },
                'output_errors': {
                    'type': 'bool',
                    },
                'collisions': {
                    'type': 'bool',
                    },
                'giants_output': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'input_errors': {
                    'type': 'bool',
                    },
                'crc': {
                    'type': 'bool',
                    },
                'runts': {
                    'type': 'bool',
                    },
                'giants': {
                    'type': 'bool',
                    },
                'output_errors': {
                    'type': 'bool',
                    },
                'collisions': {
                    'type': 'bool',
                    },
                'giants_output': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'interface_tunnel_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'num_rx_err_pkts': {
                    'type': 'bool',
                    },
                'num_tx_err_pkts': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'num_rx_err_pkts': {
                    'type': 'bool',
                    },
                'num_tx_err_pkts': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_jwt_authorization_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'jwt_authorize_failure': {
                    'type': 'bool',
                    },
                'jwt_missing_token': {
                    'type': 'bool',
                    },
                'jwt_missing_claim': {
                    'type': 'bool',
                    },
                'jwt_token_expired': {
                    'type': 'bool',
                    },
                'jwt_signature_failure': {
                    'type': 'bool',
                    },
                'jwt_other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'jwt_authorize_failure': {
                    'type': 'bool',
                    },
                'jwt_missing_token': {
                    'type': 'bool',
                    },
                'jwt_missing_claim': {
                    'type': 'bool',
                    },
                'jwt_token_expired': {
                    'type': 'bool',
                    },
                'jwt_signature_failure': {
                    'type': 'bool',
                    },
                'jwt_other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_aaa_policy_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_logon_http_ins_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'spn_krb_faiure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'spn_krb_faiure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_server_ldap_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'admin_bind_failure': {
                    'type': 'bool',
                    },
                'bind_failure': {
                    'type': 'bool',
                    },
                'search_failure': {
                    'type': 'bool',
                    },
                'authorize_failure': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'ssl_session_failure': {
                    'type': 'bool',
                    },
                'pw_change_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'admin_bind_failure': {
                    'type': 'bool',
                    },
                'bind_failure': {
                    'type': 'bool',
                    },
                'search_failure': {
                    'type': 'bool',
                    },
                'authorize_failure': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'ssl_session_failure': {
                    'type': 'bool',
                    },
                'pw_change_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_server_ocsp_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'timeout': {
                    'type': 'bool',
                    },
                'fail': {
                    'type': 'bool',
                    },
                'stapling_timeout': {
                    'type': 'bool',
                    },
                'stapling_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'timeout': {
                    'type': 'bool',
                    },
                'fail': {
                    'type': 'bool',
                    },
                'stapling_timeout': {
                    'type': 'bool',
                    },
                'stapling_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_server_rad_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'authen_failure': {
                    'type': 'bool',
                    },
                'authorize_failure': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'accounting_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'authen_failure': {
                    'type': 'bool',
                    },
                'authorize_failure': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'accounting_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_server_win_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'krb_timeout_error': {
                    'type': 'bool',
                    },
                'krb_other_error': {
                    'type': 'bool',
                    },
                'krb_pw_expiry': {
                    'type': 'bool',
                    },
                'krb_pw_change_failure': {
                    'type': 'bool',
                    },
                'krb_validate_kdc_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'krb_timeout_error': {
                    'type': 'bool',
                    },
                'krb_other_error': {
                    'type': 'bool',
                    },
                'krb_pw_expiry': {
                    'type': 'bool',
                    },
                'krb_pw_change_failure': {
                    'type': 'bool',
                    },
                'krb_validate_kdc_failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_saml_service_prov_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'acs_authz_fail': {
                    'type': 'bool',
                    },
                'acs_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'acs_authz_fail': {
                    'type': 'bool',
                    },
                'acs_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_saml_id_prov_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'md_fail': {
                    'type': 'bool',
                    },
                'acs_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'md_fail': {
                    'type': 'bool',
                    },
                'acs_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_service_group_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_service_group_mem_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'curr_conn_overflow': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'curr_conn_overflow': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_relay_hbase_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'no_creds': {
                    'type': 'bool',
                    },
                'bad_req': {
                    'type': 'bool',
                    },
                'unauth': {
                    'type': 'bool',
                    },
                'forbidden': {
                    'type': 'bool',
                    },
                'not_found': {
                    'type': 'bool',
                    },
                'server_error': {
                    'type': 'bool',
                    },
                'unavailable': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'no_creds': {
                    'type': 'bool',
                    },
                'bad_req': {
                    'type': 'bool',
                    },
                'unauth': {
                    'type': 'bool',
                    },
                'forbidden': {
                    'type': 'bool',
                    },
                'not_found': {
                    'type': 'bool',
                    },
                'server_error': {
                    'type': 'bool',
                    },
                'unavailable': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_relay_form_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'invalid_srv_rsp': {
                    'type': 'bool',
                    },
                'post_fail': {
                    'type': 'bool',
                    },
                'invalid_cred': {
                    'type': 'bool',
                    },
                'bad_req': {
                    'type': 'bool',
                    },
                'not_fnd': {
                    'type': 'bool',
                    },
                'error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'invalid_srv_rsp': {
                    'type': 'bool',
                    },
                'post_fail': {
                    'type': 'bool',
                    },
                'invalid_cred': {
                    'type': 'bool',
                    },
                'bad_req': {
                    'type': 'bool',
                    },
                'not_fnd': {
                    'type': 'bool',
                    },
                'error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_relay_ws_fed_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'failure': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'aam_auth_captcha_inst_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'parse_fail': {
                    'type': 'bool',
                    },
                'json_fail': {
                    'type': 'bool',
                    },
                'attr_fail': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'parse_fail': {
                    'type': 'bool',
                    },
                'json_fail': {
                    'type': 'bool',
                    },
                'attr_fail': {
                    'type': 'bool',
                    },
                'timeout_error': {
                    'type': 'bool',
                    },
                'other_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'slb_templ_cache_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'nc_req_header': {
                    'type': 'bool',
                    },
                'nc_res_header': {
                    'type': 'bool',
                    },
                'rv_failure': {
                    'type': 'bool',
                    },
                'content_toobig': {
                    'type': 'bool',
                    },
                'content_toosmall': {
                    'type': 'bool',
                    },
                'entry_create_failures': {
                    'type': 'bool',
                    },
                'header_save_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'nc_req_header': {
                    'type': 'bool',
                    },
                'nc_res_header': {
                    'type': 'bool',
                    },
                'rv_failure': {
                    'type': 'bool',
                    },
                'content_toobig': {
                    'type': 'bool',
                    },
                'content_toosmall': {
                    'type': 'bool',
                    },
                'entry_create_failures': {
                    'type': 'bool',
                    },
                'header_save_error': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'slb_port_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'es_resp_300': {
                    'type': 'bool',
                    },
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'resp_3xx': {
                    'type': 'bool',
                    },
                'resp_4xx': {
                    'type': 'bool',
                    },
                'resp_5xx': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'es_resp_300': {
                    'type': 'bool',
                    },
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'resp_3xx': {
                    'type': 'bool',
                    },
                'resp_4xx': {
                    'type': 'bool',
                    },
                'resp_5xx': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'slb_service_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'es_resp_300': {
                    'type': 'bool',
                    },
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'resp_3xx': {
                    'type': 'bool',
                    },
                'resp_4xx': {
                    'type': 'bool',
                    },
                'resp_5xx': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'es_resp_300': {
                    'type': 'bool',
                    },
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'resp_3xx': {
                    'type': 'bool',
                    },
                'resp_4xx': {
                    'type': 'bool',
                    },
                'resp_5xx': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'slb_vport_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'total_mf_dns_pkts': {
                    'type': 'bool',
                    },
                'es_total_failure_actions': {
                    'type': 'bool',
                    },
                'compression_miss_no_client': {
                    'type': 'bool',
                    },
                'compression_miss_template_exclusion': {
                    'type': 'bool',
                    },
                'loc_deny': {
                    'type': 'bool',
                    },
                'dnsrrl_total_dropped': {
                    'type': 'bool',
                    },
                'dnsrrl_bad_fqdn': {
                    'type': 'bool',
                    },
                'dnsrrl_nx_exceed': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'total_mf_dns_pkts': {
                    'type': 'bool',
                    },
                'es_total_failure_actions': {
                    'type': 'bool',
                    },
                'compression_miss_no_client': {
                    'type': 'bool',
                    },
                'compression_miss_template_exclusion': {
                    'type': 'bool',
                    },
                'loc_deny': {
                    'type': 'bool',
                    },
                'dnsrrl_total_dropped': {
                    'type': 'bool',
                    },
                'dnsrrl_bad_fqdn': {
                    'type': 'bool',
                    },
                'dnsrrl_nx_exceed': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'cgnv6_serv_group_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'server_selection_fail_drop': {
                    'type': 'bool',
                    },
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'server_selection_fail_drop': {
                    'type': 'bool',
                    },
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'cgnv6_dns64_vs_port_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'es_total_failure_actions': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'es_total_failure_actions': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'cgnv6_map_trans_domain_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'inbound_addr_port_validation_failed': {
                    'type': 'bool',
                    },
                'inbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'inbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'outbound_addr_validation_failed': {
                    'type': 'bool',
                    },
                'outbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'outbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'packet_mtu_exceeded': {
                    'type': 'bool',
                    },
                'interface_not_configured': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'inbound_addr_port_validation_failed': {
                    'type': 'bool',
                    },
                'inbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'inbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'outbound_addr_validation_failed': {
                    'type': 'bool',
                    },
                'outbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'outbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'packet_mtu_exceeded': {
                    'type': 'bool',
                    },
                'interface_not_configured': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'cgnv6_encap_domain_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'inbound_addr_port_validation_failed': {
                    'type': 'bool',
                    },
                'inbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'inbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'outbound_addr_validation_failed': {
                    'type': 'bool',
                    },
                'outbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'outbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'packet_mtu_exceeded': {
                    'type': 'bool',
                    },
                'interface_not_configured': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'inbound_addr_port_validation_failed': {
                    'type': 'bool',
                    },
                'inbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'inbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'outbound_addr_validation_failed': {
                    'type': 'bool',
                    },
                'outbound_rev_lookup_failed': {
                    'type': 'bool',
                    },
                'outbound_dest_unreachable': {
                    'type': 'bool',
                    },
                'packet_mtu_exceeded': {
                    'type': 'bool',
                    },
                'interface_not_configured': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'netflow_monitor_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'nat44_records_sent_failure': {
                    'type': 'bool',
                    },
                'nat64_records_sent_failure': {
                    'type': 'bool',
                    },
                'dslite_records_sent_failure': {
                    'type': 'bool',
                    },
                'session_event_nat44_records_sent_failur': {
                    'type': 'bool',
                    },
                'session_event_nat64_records_sent_failur': {
                    'type': 'bool',
                    },
                'session_event_dslite_records_sent_failu': {
                    'type': 'bool',
                    },
                'session_event_fw4_records_sent_failure': {
                    'type': 'bool',
                    },
                'session_event_fw6_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_nat44_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_nat64_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_dslite_records_sent_failur': {
                    'type': 'bool',
                    },
                'netflow_v5_records_sent_failure': {
                    'type': 'bool',
                    },
                'netflow_v5_ext_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_batching_nat44_records_sent_failur': {
                    'type': 'bool',
                    },
                'port_batching_nat64_records_sent_failur': {
                    'type': 'bool',
                    },
                'port_batching_dslite_records_sent_failu': {
                    'type': 'bool',
                    },
                'port_batching_v2_nat44_records_sent_fai': {
                    'type': 'bool',
                    },
                'port_batching_v2_nat64_records_sent_fai': {
                    'type': 'bool',
                    },
                'port_batching_v2_dslite_records_sent_fa': {
                    'type': 'bool',
                    },
                'custom_session_event_nat44_creation_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_nat64_creation_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_dslite_creation_re': {
                    'type': 'bool',
                    },
                'custom_session_event_nat44_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_nat64_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_dslite_deletion_re': {
                    'type': 'bool',
                    },
                'custom_session_event_fw4_creation_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw6_creation_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw4_deletion_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw6_deletion_recor': {
                    'type': 'bool',
                    },
                'custom_deny_reset_event_fw4_records_sen': {
                    'type': 'bool',
                    },
                'custom_deny_reset_event_fw6_records_sen': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat44_creation_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat64_creation_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_dslite_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat44_deletion_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat64_deletion_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_dslite_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat44_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat64_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_dslite_creation_re': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat44_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat64_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_dslite_deletion_re': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat44_creation_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat64_creation_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_dslite_creation': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat44_deletion_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat64_deletion_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_dslite_deletion': {
                    'type': 'bool',
                    },
                'custom_gtp_c_tunnel_event_records_sent_': {
                    'type': 'bool',
                    },
                'custom_gtp_u_tunnel_event_records_sent_': {
                    'type': 'bool',
                    },
                'custom_gtp_deny_event_records_sent_fail': {
                    'type': 'bool',
                    },
                'custom_gtp_info_event_records_sent_fail': {
                    'type': 'bool',
                    },
                'custom_fw_iddos_entry_created_records_s': {
                    'type': 'bool',
                    },
                'custom_fw_iddos_entry_deleted_records_s': {
                    'type': 'bool',
                    },
                'custom_fw_sesn_limit_exceeded_records_s': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l3_entry_created_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l3_entry_deleted_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l4_entry_created_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l4_entry_deleted_recor': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'nat44_records_sent_failure': {
                    'type': 'bool',
                    },
                'nat64_records_sent_failure': {
                    'type': 'bool',
                    },
                'dslite_records_sent_failure': {
                    'type': 'bool',
                    },
                'session_event_nat44_records_sent_failur': {
                    'type': 'bool',
                    },
                'session_event_nat64_records_sent_failur': {
                    'type': 'bool',
                    },
                'session_event_dslite_records_sent_failu': {
                    'type': 'bool',
                    },
                'session_event_fw4_records_sent_failure': {
                    'type': 'bool',
                    },
                'session_event_fw6_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_nat44_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_nat64_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_mapping_dslite_records_sent_failur': {
                    'type': 'bool',
                    },
                'netflow_v5_records_sent_failure': {
                    'type': 'bool',
                    },
                'netflow_v5_ext_records_sent_failure': {
                    'type': 'bool',
                    },
                'port_batching_nat44_records_sent_failur': {
                    'type': 'bool',
                    },
                'port_batching_nat64_records_sent_failur': {
                    'type': 'bool',
                    },
                'port_batching_dslite_records_sent_failu': {
                    'type': 'bool',
                    },
                'port_batching_v2_nat44_records_sent_fai': {
                    'type': 'bool',
                    },
                'port_batching_v2_nat64_records_sent_fai': {
                    'type': 'bool',
                    },
                'port_batching_v2_dslite_records_sent_fa': {
                    'type': 'bool',
                    },
                'custom_session_event_nat44_creation_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_nat64_creation_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_dslite_creation_re': {
                    'type': 'bool',
                    },
                'custom_session_event_nat44_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_nat64_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_session_event_dslite_deletion_re': {
                    'type': 'bool',
                    },
                'custom_session_event_fw4_creation_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw6_creation_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw4_deletion_recor': {
                    'type': 'bool',
                    },
                'custom_session_event_fw6_deletion_recor': {
                    'type': 'bool',
                    },
                'custom_deny_reset_event_fw4_records_sen': {
                    'type': 'bool',
                    },
                'custom_deny_reset_event_fw6_records_sen': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat44_creation_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat64_creation_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_dslite_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat44_deletion_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_nat64_deletion_reco': {
                    'type': 'bool',
                    },
                'custom_port_mapping_dslite_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat44_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat64_creation_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_dslite_creation_re': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat44_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_nat64_deletion_rec': {
                    'type': 'bool',
                    },
                'custom_port_batching_dslite_deletion_re': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat44_creation_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat64_creation_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_dslite_creation': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat44_deletion_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_nat64_deletion_': {
                    'type': 'bool',
                    },
                'custom_port_batching_v2_dslite_deletion': {
                    'type': 'bool',
                    },
                'custom_gtp_c_tunnel_event_records_sent_': {
                    'type': 'bool',
                    },
                'custom_gtp_u_tunnel_event_records_sent_': {
                    'type': 'bool',
                    },
                'custom_gtp_deny_event_records_sent_fail': {
                    'type': 'bool',
                    },
                'custom_gtp_info_event_records_sent_fail': {
                    'type': 'bool',
                    },
                'custom_fw_iddos_entry_created_records_s': {
                    'type': 'bool',
                    },
                'custom_fw_iddos_entry_deleted_records_s': {
                    'type': 'bool',
                    },
                'custom_fw_sesn_limit_exceeded_records_s': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l3_entry_created_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l3_entry_deleted_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l4_entry_created_recor': {
                    'type': 'bool',
                    },
                'custom_nat_iddos_l4_entry_deleted_recor': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'rule_set_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'unmatched_drops': {
                    'type': 'bool',
                    },
                'deny': {
                    'type': 'bool',
                    },
                'reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'unmatched_drops': {
                    'type': 'bool',
                    },
                'deny': {
                    'type': 'bool',
                    },
                'reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'rule_set_rule_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'syn_cookie_verification_failed': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'syn_cookie_verification_failed': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'fw_server_port_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'es_resp_invalid_http': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'es_resp_400': {
                    'type': 'bool',
                    },
                'es_resp_500': {
                    'type': 'bool',
                    },
                'es_resp_invalid_http': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'fw_service_group_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'server_selection_fail_reset': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'fw_service_group_mem_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'curr_conn_overflow': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'curr_conn_overflow': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'dns_vport_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'dnsrrl_total_dropped': {
                    'type': 'bool',
                    },
                'total_filter_drop': {
                    'type': 'bool',
                    },
                'total_max_query_len_drop': {
                    'type': 'bool',
                    },
                'rcode_notimpl_receive': {
                    'type': 'bool',
                    },
                'rcode_notimpl_response': {
                    'type': 'bool',
                    },
                'gslb_query_bad': {
                    'type': 'bool',
                    },
                'gslb_response_bad': {
                    'type': 'bool',
                    },
                'total_dns_filter_type_drop': {
                    'type': 'bool',
                    },
                'total_dns_filter_class_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_a_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_aaaa_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_cname_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_mx_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_ns_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_srv_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_ptr_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_soa_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_txt_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_any_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_others_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_internet_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_chaos_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_hesiod_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_none_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_any_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_others_drop': {
                    'type': 'bool',
                    },
                'dns_rpz_action_drop': {
                    'type': 'bool',
                    },
                'dnsrrl_bad_fqdn': {
                    'type': 'bool',
                    },
                'dns_filter_tld_drop': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'dnsrrl_total_dropped': {
                    'type': 'bool',
                    },
                'total_filter_drop': {
                    'type': 'bool',
                    },
                'total_max_query_len_drop': {
                    'type': 'bool',
                    },
                'rcode_notimpl_receive': {
                    'type': 'bool',
                    },
                'rcode_notimpl_response': {
                    'type': 'bool',
                    },
                'gslb_query_bad': {
                    'type': 'bool',
                    },
                'gslb_response_bad': {
                    'type': 'bool',
                    },
                'total_dns_filter_type_drop': {
                    'type': 'bool',
                    },
                'total_dns_filter_class_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_a_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_aaaa_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_cname_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_mx_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_ns_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_srv_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_ptr_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_soa_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_txt_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_any_drop': {
                    'type': 'bool',
                    },
                'dns_filter_type_others_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_internet_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_chaos_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_hesiod_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_none_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_any_drop': {
                    'type': 'bool',
                    },
                'dns_filter_class_others_drop': {
                    'type': 'bool',
                    },
                'dns_rpz_action_drop': {
                    'type': 'bool',
                    },
                'dnsrrl_bad_fqdn': {
                    'type': 'bool',
                    },
                'dns_filter_tld_drop': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'smtp_vport_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'no_proxy': {
                    'type': 'bool',
                    },
                'parse_req_fail': {
                    'type': 'bool',
                    },
                'server_select_fail': {
                    'type': 'bool',
                    },
                'forward_req_fail': {
                    'type': 'bool',
                    },
                'forward_req_data_fail': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'send_client_service_not_ready': {
                    'type': 'bool',
                    },
                'recv_server_unknow_reply_code': {
                    'type': 'bool',
                    },
                'read_request_line_fail': {
                    'type': 'bool',
                    },
                'get_all_headers_fail': {
                    'type': 'bool',
                    },
                'too_many_headers': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'line_extend_fail': {
                    'type': 'bool',
                    },
                'line_table_extend_fail': {
                    'type': 'bool',
                    },
                'parse_request_line_fail': {
                    'type': 'bool',
                    },
                'insert_resonse_line_fail': {
                    'type': 'bool',
                    },
                'remove_resonse_line_fail': {
                    'type': 'bool',
                    },
                'parse_resonse_line_fail': {
                    'type': 'bool',
                    },
                'server_STARTTLS_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'no_proxy': {
                    'type': 'bool',
                    },
                'parse_req_fail': {
                    'type': 'bool',
                    },
                'server_select_fail': {
                    'type': 'bool',
                    },
                'forward_req_fail': {
                    'type': 'bool',
                    },
                'forward_req_data_fail': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'send_client_service_not_ready': {
                    'type': 'bool',
                    },
                'recv_server_unknow_reply_code': {
                    'type': 'bool',
                    },
                'read_request_line_fail': {
                    'type': 'bool',
                    },
                'get_all_headers_fail': {
                    'type': 'bool',
                    },
                'too_many_headers': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'line_extend_fail': {
                    'type': 'bool',
                    },
                'line_table_extend_fail': {
                    'type': 'bool',
                    },
                'parse_request_line_fail': {
                    'type': 'bool',
                    },
                'insert_resonse_line_fail': {
                    'type': 'bool',
                    },
                'remove_resonse_line_fail': {
                    'type': 'bool',
                    },
                'parse_resonse_line_fail': {
                    'type': 'bool',
                    },
                'server_STARTTLS_fail': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'pop3_vport_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'svrsel_fail': {
                    'type': 'bool',
                    },
                'no_route': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'invalid_start_line': {
                    'type': 'bool',
                    },
                'unsupported_command': {
                    'type': 'bool',
                    },
                'bad_sequence': {
                    'type': 'bool',
                    },
                'rsv_persist_conn_fail': {
                    'type': 'bool',
                    },
                'smp_v6_fail': {
                    'type': 'bool',
                    },
                'smp_v4_fail': {
                    'type': 'bool',
                    },
                'insert_tuple_fail': {
                    'type': 'bool',
                    },
                'cl_est_err': {
                    'type': 'bool',
                    },
                'ser_connecting_err': {
                    'type': 'bool',
                    },
                'server_response_err': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'svrsel_fail': {
                    'type': 'bool',
                    },
                'no_route': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'invalid_start_line': {
                    'type': 'bool',
                    },
                'unsupported_command': {
                    'type': 'bool',
                    },
                'bad_sequence': {
                    'type': 'bool',
                    },
                'rsv_persist_conn_fail': {
                    'type': 'bool',
                    },
                'smp_v6_fail': {
                    'type': 'bool',
                    },
                'smp_v4_fail': {
                    'type': 'bool',
                    },
                'insert_tuple_fail': {
                    'type': 'bool',
                    },
                'cl_est_err': {
                    'type': 'bool',
                    },
                'ser_connecting_err': {
                    'type': 'bool',
                    },
                'server_response_err': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'imap_vport_tmpl_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'capture_config': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'trigger_stats_severity': {
                'type': 'dict',
                'error': {
                    'type': 'bool',
                    },
                'error_alert': {
                    'type': 'bool',
                    },
                'error_warning': {
                    'type': 'bool',
                    },
                'error_critical': {
                    'type': 'bool',
                    },
                'drop': {
                    'type': 'bool',
                    },
                'drop_alert': {
                    'type': 'bool',
                    },
                'drop_warning': {
                    'type': 'bool',
                    },
                'drop_critical': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_inc': {
                'type': 'dict',
                'svrsel_fail': {
                    'type': 'bool',
                    },
                'no_route': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'invalid_start_line': {
                    'type': 'bool',
                    },
                'cant_find_pasv': {
                    'type': 'bool',
                    },
                'smp_create_fail': {
                    'type': 'bool',
                    },
                'data_server_conn_fail': {
                    'type': 'bool',
                    },
                'data_send_fail': {
                    'type': 'bool',
                    },
                'cant_find_epsv': {
                    'type': 'bool',
                    },
                'auth_unsupported': {
                    'type': 'bool',
                    },
                'unsupported_pbsz_value': {
                    'type': 'bool',
                    },
                'unsupported_prot_value': {
                    'type': 'bool',
                    },
                'bad_sequence': {
                    'type': 'bool',
                    },
                'rsv_persist_conn_fail': {
                    'type': 'bool',
                    },
                'smp_v6_fail': {
                    'type': 'bool',
                    },
                'smp_v4_fail': {
                    'type': 'bool',
                    },
                'insert_tuple_fail': {
                    'type': 'bool',
                    },
                'cl_est_err': {
                    'type': 'bool',
                    },
                'ser_connecting_err': {
                    'type': 'bool',
                    },
                'server_response_err': {
                    'type': 'bool',
                    },
                'cl_request_err': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trigger_stats_rate': {
                'type': 'dict',
                'threshold_exceeded_by': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'svrsel_fail': {
                    'type': 'bool',
                    },
                'no_route': {
                    'type': 'bool',
                    },
                'snat_fail': {
                    'type': 'bool',
                    },
                'line_too_long': {
                    'type': 'bool',
                    },
                'invalid_start_line': {
                    'type': 'bool',
                    },
                'cant_find_pasv': {
                    'type': 'bool',
                    },
                'smp_create_fail': {
                    'type': 'bool',
                    },
                'data_server_conn_fail': {
                    'type': 'bool',
                    },
                'data_send_fail': {
                    'type': 'bool',
                    },
                'cant_find_epsv': {
                    'type': 'bool',
                    },
                'auth_unsupported': {
                    'type': 'bool',
                    },
                'unsupported_pbsz_value': {
                    'type': 'bool',
                    },
                'unsupported_prot_value': {
                    'type': 'bool',
                    },
                'bad_sequence': {
                    'type': 'bool',
                    },
                'rsv_persist_conn_fail': {
                    'type': 'bool',
                    },
                'smp_v6_fail': {
                    'type': 'bool',
                    },
                'smp_v4_fail': {
                    'type': 'bool',
                    },
                'insert_tuple_fail': {
                    'type': 'bool',
                    },
                'cl_est_err': {
                    'type': 'bool',
                    },
                'ser_connecting_err': {
                    'type': 'bool',
                    },
                'server_response_err': {
                    'type': 'bool',
                    },
                'cl_request_err': {
                    'type': 'bool',
                    },
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
    url_base = "/axapi/v3/visibility/packet-capture/object-templates"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/object-templates"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["object-templates"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["object-templates"].get(k) != v:
            change_results["changed"] = True
            config_changes["object-templates"][k] = v

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
    payload = utils.build_json("object-templates", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["object-templates"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["object-templates-list"] if info != "NotFound" else info
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
