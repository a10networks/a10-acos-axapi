#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_rule_set_rule
description:
    - Configure rule-set rule
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
    rule_set_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    name:
        description:
        - "Rule name"
        type: str
        required: True
    remark:
        description:
        - "Rule entry comment (Notes for this rule)"
        type: str
        required: False
    status:
        description:
        - "'enable'= Enable rule; 'disable'= Disable rule;"
        type: str
        required: False
    action:
        description:
        - "'permit'= permit; 'deny'= deny; 'reset'= reset;"
        type: str
        required: False
    log:
        description:
        - "Enable logging"
        type: bool
        required: False
    reset_lid:
        description:
        - "Apply a Template LID"
        type: int
        required: False
    listen_on_port:
        description:
        - "Listen on port"
        type: bool
        required: False
    policy:
        description:
        - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet;"
        type: str
        required: False
    forward_listen_on_port:
        description:
        - "Listen on port"
        type: bool
        required: False
    lid:
        description:
        - "Apply a Template LID"
        type: int
        required: False
    listen_on_port_lid:
        description:
        - "Apply a Template LID"
        type: int
        required: False
    fw_log:
        description:
        - "Enable logging"
        type: bool
        required: False
    fwlog:
        description:
        - "Enable logging"
        type: bool
        required: False
    cgnv6_log:
        description:
        - "Enable logging"
        type: bool
        required: False
    forward_log:
        description:
        - "Enable logging"
        type: bool
        required: False
    lidlog:
        description:
        - "Enable logging"
        type: bool
        required: False
    reset_lidlog:
        description:
        - "Enable logging"
        type: bool
        required: False
    listen_on_port_lidlog:
        description:
        - "Enable logging"
        type: bool
        required: False
    cgnv6_policy:
        description:
        - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT;"
        type: str
        required: False
    cgnv6_fixed_nat_log:
        description:
        - "Enable logging"
        type: bool
        required: False
    cgnv6_lsn_lid:
        description:
        - "LSN LID"
        type: int
        required: False
    cgnv6_lsn_log:
        description:
        - "Enable logging"
        type: bool
        required: False
    ip_version:
        description:
        - "'v4'= IPv4 rule; 'v6'= IPv6 rule;"
        type: str
        required: False
    src_class_list:
        description:
        - "Match source IP against class-list"
        type: str
        required: False
    src_geoloc_name:
        description:
        - "Single geolocation name"
        type: str
        required: False
    src_geoloc_list:
        description:
        - "Geolocation name list"
        type: str
        required: False
    src_geoloc_list_shared:
        description:
        - "Use Geolocation list from shared partition"
        type: bool
        required: False
    src_ipv4_any:
        description:
        - "'any'= Any IPv4 address;"
        type: str
        required: False
    src_ipv6_any:
        description:
        - "'any'= Any IPv6 address;"
        type: str
        required: False
    source_list:
        description:
        - "Field source_list"
        type: list
        required: False
        suboptions:
            src_ip_subnet:
                description:
                - "IPv4 IP Address"
                type: str
            src_ipv6_subnet:
                description:
                - "IPv6 IP Address"
                type: str
            src_obj_network:
                description:
                - "Network object"
                type: str
            src_obj_grp_network:
                description:
                - "Network object group"
                type: str
            src_slb_server:
                description:
                - "SLB Real server name"
                type: str
    src_zone:
        description:
        - "Zone name"
        type: str
        required: False
    src_zone_any:
        description:
        - "'any'= any;"
        type: str
        required: False
    src_threat_list:
        description:
        - "Bind threat-list for source IP based filtering"
        type: str
        required: False
    dst_class_list:
        description:
        - "Match destination IP against class-list"
        type: str
        required: False
    dst_geoloc_name:
        description:
        - "Single geolocation name"
        type: str
        required: False
    dst_geoloc_list:
        description:
        - "Geolocation name list"
        type: str
        required: False
    dst_geoloc_list_shared:
        description:
        - "Use Geolocation list from shared partition"
        type: bool
        required: False
    dst_ipv4_any:
        description:
        - "'any'= Any IPv4 address;"
        type: str
        required: False
    dst_ipv6_any:
        description:
        - "'any'= Any IPv6 address;"
        type: str
        required: False
    dest_list:
        description:
        - "Field dest_list"
        type: list
        required: False
        suboptions:
            dst_ip_subnet:
                description:
                - "IPv4 IP Address"
                type: str
            dst_ipv6_subnet:
                description:
                - "IPv6 IP Address"
                type: str
            dst_obj_network:
                description:
                - "Network object"
                type: str
            dst_obj_grp_network:
                description:
                - "Network object group"
                type: str
            dst_slb_server:
                description:
                - "SLB Real server name"
                type: str
            dst_slb_vserver:
                description:
                - "SLB Virtual server name"
                type: str
    dst_domain_list:
        description:
        - "Match destination IP against domain-list"
        type: str
        required: False
    dst_zone:
        description:
        - "Zone name"
        type: str
        required: False
    dst_zone_any:
        description:
        - "'any'= any;"
        type: str
        required: False
    dst_threat_list:
        description:
        - "Bind threat-list for destination IP based filtering"
        type: str
        required: False
    service_any:
        description:
        - "'any'= any;"
        type: str
        required: False
    service_list:
        description:
        - "Field service_list"
        type: list
        required: False
        suboptions:
            protocols:
                description:
                - "'tcp'= tcp; 'udp'= udp; 'sctp'= sctp;"
                type: str
            proto_id:
                description:
                - "Protocol ID"
                type: int
            obj_grp_service:
                description:
                - "service object group"
                type: str
            icmp:
                description:
                - "ICMP"
                type: bool
            icmpv6:
                description:
                - "ICMPv6"
                type: bool
            icmp_type:
                description:
                - "ICMP type number"
                type: int
            special_type:
                description:
                - "'any-type'= Any ICMP type; 'echo-reply'= Type 0, echo reply; 'echo-request'=
          Type 8, echo request; 'info-reply'= Type 16, information reply; 'info-request'=
          Type 15, information request; 'mask-reply'= Type 18, address mask reply; 'mask-
          request'= Type 17, address mask request; 'parameter-problem'= Type 12,
          parameter problem; 'redirect'= Type 5, redirect message; 'source-quench'= Type
          4, source quench; 'time-exceeded'= Type 11, time exceeded; 'timestamp'= Type
          13, timestamp; 'timestamp-reply'= Type 14, timestamp reply; 'dest-unreachable'=
          Type 3, destination unreachable;"
                type: str
            icmp_code:
                description:
                - "ICMP code number"
                type: int
            special_code:
                description:
                - "'any-code'= Any ICMP code; 'frag-required'= Code 4, fragmentation required;
          'host-unreachable'= Code 1, destination host unreachable; 'network-
          unreachable'= Code 0, destination network unreachable; 'port-unreachable'= Code
          3, destination port unreachable; 'proto-unreachable'= Code 2, destination
          protocol unreachable; 'route-failed'= Code 5, source route failed;"
                type: str
            icmpv6_type:
                description:
                - "ICMPv6 type number"
                type: int
            special_v6_type:
                description:
                - "'any-type'= Any ICMPv6 type; 'dest-unreachable'= Type 1, destination
          unreachable; 'echo-reply'= Type 129, echo reply; 'echo-request'= Type 128, echo
          request; 'packet-too-big'= Type 2, packet too big; 'param-prob'= Type 4,
          parameter problem; 'time-exceeded'= Type 3, time exceeded;"
                type: str
            icmpv6_code:
                description:
                - "ICMPv6 code number"
                type: int
            special_v6_code:
                description:
                - "'any-code'= Any ICMPv6 code; 'addr-unreachable'= Code 3, address unreachable;
          'admin-prohibited'= Code 1, admin prohibited; 'no-route'= Code 0, no route to
          destination; 'not-neighbour'= Code 2, not neighbor; 'port-unreachable'= Code 4,
          destination port unreachable;"
                type: str
            eq_src_port:
                description:
                - "Equal to the port number"
                type: int
            gt_src_port:
                description:
                - "Greater than the port number"
                type: int
            lt_src_port:
                description:
                - "Lower than the port number"
                type: int
            range_src_port:
                description:
                - "Port range (Starting Port Number)"
                type: int
            port_num_end_src:
                description:
                - "Ending Port Number"
                type: int
            eq_dst_port:
                description:
                - "Equal to the port number"
                type: int
            gt_dst_port:
                description:
                - "Greater than the port number"
                type: int
            lt_dst_port:
                description:
                - "Lower than the port number"
                type: int
            range_dst_port:
                description:
                - "Port range (Starting Port Number)"
                type: int
            port_num_end_dst:
                description:
                - "Ending Port Number"
                type: int
            sctp_template:
                description:
                - "SCTP Template"
                type: str
            alg:
                description:
                - "'FTP'= FTP; 'TFTP'= TFTP; 'SIP'= SIP; 'DNS'= DNS; 'PPTP'= PPTP; 'RTSP'= RTSP;"
                type: str
            gtp_template:
                description:
                - "Configure GTP template (GTP Template Name)"
                type: str
    idle_timeout:
        description:
        - "TCP/UDP idle-timeout"
        type: int
        required: False
    application_any:
        description:
        - "'any'= any;"
        type: str
        required: False
    app_list:
        description:
        - "Field app_list"
        type: list
        required: False
        suboptions:
            obj_grp_application:
                description:
                - "Application object group"
                type: str
            protocol:
                description:
                - "Specify application(s)"
                type: str
            protocol_tag:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and
          Accounting) purposes.; 'adult-content'= Adult content.; 'advertising'=
          Advertising networks and applications.; 'analytics-and-statistics'= user-
          analytics and statistics.; 'anonymizers-and-proxies'= Traffic-anonymization
          protocol/application.; 'audio-chat'= Protocol/application used for Audio Chat.;
          'basic'= Protocols required for basic classification, e.g., ARP, HTTP; 'blog'=
          Blogging platform.; 'cdn'= Protocol/application used for Content-Delivery
          Networks.; 'chat'= Protocol/application used for Text Chat.; 'classified-ads'=
          Protocol/application used for Classified ads.; 'cloud-based-services'= SaaS
          and/or PaaS cloud based services.; 'crowdfunding'= Service for funding a
          project or venture by raising small amounts of money from a large number of
          people.; 'cryptocurrency'= Cryptocurrency.; 'database'= Database-specific
          protocols.; 'disposable-email'= Disposable email accounts.; 'ebook-reader'=
          Services for e-book readers.; 'email'= Native email protocol.; 'enterprise'=
          Protocol/application used in an enterprise network.; 'file-management'=
          Protocol/application designed specifically for file management and exchange,
          e.g., Dropbox, SMB; 'file-transfer'= Protocol that offers file transferring as
          a functionality as a secondary feature. e.g., Skype, Whatsapp; 'forum'= Online
          forum.; 'gaming'= Protocol/application used by games.; 'instant-messaging-and-
          multimedia-conferencing'= Protocol/application used for Instant messaging or
          multiconferencing.; 'internet-of-things'= Internet Of Things
          protocol/application.; 'mobile'= Mobile-specific protocol/application.; 'map-
          service'= Digital Maps service.; 'multimedia-streaming'= Protocol/application
          used for multimedia streaming.; 'networking'= Protocol used for (inter)
          networking purpose.; 'news-portal'= Protocol/application used for News
          Portals.; 'peer-to-peer'= Protocol/application used for Peer-to-peer purposes.;
          'remote-access'= Protocol/application used for remote access.; 'scada'= SCADA
          (Supervisory control and data acquisition) protocols, all generations.;
          'social-networks'= Social networking application.; 'software-update'= Auto-
          update protocol.; 'standards-based'= Protocol issued from standardized bodies
          such as IETF, ITU, IEEE, ETSI, OIF.; 'transportation'= Transportation.; 'video-
          chat'= Protocol/application used for Video Chat.; 'voip'= Application used for
          Voice over IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling
          purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'=
          Protocol/application used for E-commerce websites.; 'web-search-engines'=
          Protocol/application used for Web search portals.; 'web-websites'=
          Protocol/application used for Company Websites.; 'webmails'= Web email
          application.; 'web-ext-adult'= Web Extension Adult; 'web-ext-auctions'= Web
          Extension Auctions; 'web-ext-blogs'= Web Extension Blogs; 'web-ext-business-
          and-economy'= Web Extension Business and Economy; 'web-ext-cdns'= Web Extension
          CDNs; 'web-ext-collaboration'= Web Extension Collaboration; 'web-ext-computer-
          and-internet-info'= Web Extension Computer and Internet Info; 'web-ext-
          computer-and-internet-security'= Web Extension Computer and Internet Security;
          'web-ext-dating'= Web Extension Dating; 'web-ext-educational-institutions'= Web
          Extension Educational Institutions; 'web-ext-entertainment-and-arts'= Web
          Extension Entertainment and Arts; 'web-ext-fashion-and-beauty'= Web Extension
          Fashion and Beauty; 'web-ext-file-share'= Web Extension File Share; 'web-ext-
          financial-services'= Web Extension Financial Services; 'web-ext-gambling'= Web
          Extension Gambling; 'web-ext-games'= Web Extension Games; 'web-ext-government'=
          Web Extension Government; 'web-ext-health-and-medicine'= Web Extension Health
          and Medicine; 'web-ext-individual-stock-advice-and-tools'= Web Extension
          Individual Stock Advice and Tools; 'web-ext-internet-portals'= Web Extension
          Internet Portals; 'web-ext-job-search'= Web Extension Job Search; 'web-ext-
          local-information'= Web Extension Local Information; 'web-ext-malware'= Web
          Extension Malware; 'web-ext-motor-vehicles'= Web Extension Motor Vehicles;
          'web-ext-music'= Web Extension Music; 'web-ext-news'= Web Extension News; 'web-
          ext-p2p'= Web Extension P2P; 'web-ext-parked-sites'= Web Extension Parked
          Sites; 'web-ext-proxy-avoid-and-anonymizers'= Web Extension Proxy Avoid and
          Anonymizers; 'web-ext-real-estate'= Web Extension Real Estate; 'web-ext-
          reference-and-research'= Web Extension Reference and Research; 'web-ext-search-
          engines'= Web Extension Search Engines; 'web-ext-shopping'= Web Extension
          Shopping; 'web-ext-social-network'= Web Extension Social Network; 'web-ext-
          society'= Web Extension Society; 'web-ext-software'= Web Extension Software;
          'web-ext-sports'= Web Extension Sports; 'web-ext-streaming-media'= Web
          Extension Streaming Media; 'web-ext-training-and-tools'= Web Extension Training
          and Tools; 'web-ext-translation'= Web Extension Translation; 'web-ext-travel'=
          Web Extension Travel; 'web-ext-web-advertisements'= Web Extension Web
          Advertisements; 'web-ext-web-based-email'= Web Extension Web based Email; 'web-
          ext-web-hosting'= Web Extension Web Hosting; 'web-ext-web-service'= Web
          Extension Web Service;"
                type: str
    track_application:
        description:
        - "Enable application statistic"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
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
                - "'all'= all; 'hit-count'= Hit counts; 'permit-bytes'= Permitted bytes counter;
          'deny-bytes'= Denied bytes counter; 'reset-bytes'= Reset bytes counter;
          'permit-packets'= Permitted packets counter; 'deny-packets'= Denied packets
          counter; 'reset-packets'= Reset packets counter; 'active-session-tcp'= Active
          TCP session counter; 'active-session-udp'= Active UDP session counter; 'active-
          session-icmp'= Active ICMP session counter; 'active-session-other'= Active
          other protocol session counter; 'session-tcp'= TCP session counter; 'session-
          udp'= UDP session counter; 'session-icmp'= ICMP session counter; 'session-
          other'= Other protocol session counter; 'active-session-sctp'= Active SCTP
          session counter; 'session-sctp'= SCTP session counter; 'hitcount-timestamp'=
          Last hit counts timestamp;"
                type: str
    move_rule:
        description:
        - "Field move_rule"
        type: dict
        required: False
        suboptions:
            location:
                description:
                - "'top'= top; 'before'= before; 'after'= after; 'bottom'= bottom;"
                type: str
            target_rule:
                description:
                - "Field target_rule"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            hitcount:
                description:
                - "Field hitcount"
                type: int
            last_hitcount_time:
                description:
                - "Field last_hitcount_time"
                type: str
            action:
                description:
                - "Field action"
                type: str
            status:
                description:
                - "Field status"
                type: str
            permitbytes:
                description:
                - "Field permitbytes"
                type: int
            denybytes:
                description:
                - "Field denybytes"
                type: int
            resetbytes:
                description:
                - "Field resetbytes"
                type: int
            totalbytes:
                description:
                - "Field totalbytes"
                type: int
            permitpackets:
                description:
                - "Field permitpackets"
                type: int
            denypackets:
                description:
                - "Field denypackets"
                type: int
            resetpackets:
                description:
                - "Field resetpackets"
                type: int
            totalpackets:
                description:
                - "Field totalpackets"
                type: int
            activesessiontcp:
                description:
                - "Field activesessiontcp"
                type: int
            activesessionudp:
                description:
                - "Field activesessionudp"
                type: int
            activesessionicmp:
                description:
                - "Field activesessionicmp"
                type: int
            activesessionsctp:
                description:
                - "Field activesessionsctp"
                type: int
            activesessionother:
                description:
                - "Field activesessionother"
                type: int
            activesessiontotal:
                description:
                - "Field activesessiontotal"
                type: int
            sessiontcp:
                description:
                - "Field sessiontcp"
                type: int
            sessionudp:
                description:
                - "Field sessionudp"
                type: int
            sessionicmp:
                description:
                - "Field sessionicmp"
                type: int
            sessionsctp:
                description:
                - "Field sessionsctp"
                type: int
            sessionother:
                description:
                - "Field sessionother"
                type: int
            sessiontotal:
                description:
                - "Field sessiontotal"
                type: int
            name:
                description:
                - "Rule name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hit_count:
                description:
                - "Hit counts"
                type: str
            permit_bytes:
                description:
                - "Permitted bytes counter"
                type: str
            deny_bytes:
                description:
                - "Denied bytes counter"
                type: str
            reset_bytes:
                description:
                - "Reset bytes counter"
                type: str
            permit_packets:
                description:
                - "Permitted packets counter"
                type: str
            deny_packets:
                description:
                - "Denied packets counter"
                type: str
            reset_packets:
                description:
                - "Reset packets counter"
                type: str
            active_session_tcp:
                description:
                - "Active TCP session counter"
                type: str
            active_session_udp:
                description:
                - "Active UDP session counter"
                type: str
            active_session_icmp:
                description:
                - "Active ICMP session counter"
                type: str
            active_session_other:
                description:
                - "Active other protocol session counter"
                type: str
            session_tcp:
                description:
                - "TCP session counter"
                type: str
            session_udp:
                description:
                - "UDP session counter"
                type: str
            session_icmp:
                description:
                - "ICMP session counter"
                type: str
            session_other:
                description:
                - "Other protocol session counter"
                type: str
            active_session_sctp:
                description:
                - "Active SCTP session counter"
                type: str
            session_sctp:
                description:
                - "SCTP session counter"
                type: str
            hitcount_timestamp:
                description:
                - "Last hit counts timestamp"
                type: str
            name:
                description:
                - "Rule name"
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

# standard ansible module imports
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
AVAILABLE_PROPERTIES = ["action", "app_list", "application_any", "cgnv6_fixed_nat_log", "cgnv6_log", "cgnv6_lsn_lid", "cgnv6_lsn_log", "cgnv6_policy", "dest_list", "dst_class_list", "dst_domain_list", "dst_geoloc_list", "dst_geoloc_list_shared", "dst_geoloc_name", "dst_ipv4_any", "dst_ipv6_any", "dst_threat_list", "dst_zone", "dst_zone_any", "forward_listen_on_port", "forward_log", "fw_log", "fwlog", "idle_timeout", "ip_version", "lid", "lidlog", "listen_on_port", "listen_on_port_lid", "listen_on_port_lidlog", "log", "move_rule", "name", "oper", "policy", "remark", "reset_lid", "reset_lidlog", "sampling_enable", "service_any", "service_list", "source_list", "src_class_list", "src_geoloc_list", "src_geoloc_list_shared", "src_geoloc_name", "src_ipv4_any", "src_ipv6_any", "src_threat_list", "src_zone", "src_zone_any", "stats", "status", "track_application", "user_tag", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'name': {'type': 'str', 'required': True, },
        'remark': {'type': 'str', },
        'status': {'type': 'str', 'choices': ['enable', 'disable']},
        'action': {'type': 'str', 'choices': ['permit', 'deny', 'reset']},
        'log': {'type': 'bool', },
        'reset_lid': {'type': 'int', },
        'listen_on_port': {'type': 'bool', },
        'policy': {'type': 'str', 'choices': ['cgnv6', 'forward']},
        'forward_listen_on_port': {'type': 'bool', },
        'lid': {'type': 'int', },
        'listen_on_port_lid': {'type': 'int', },
        'fw_log': {'type': 'bool', },
        'fwlog': {'type': 'bool', },
        'cgnv6_log': {'type': 'bool', },
        'forward_log': {'type': 'bool', },
        'lidlog': {'type': 'bool', },
        'reset_lidlog': {'type': 'bool', },
        'listen_on_port_lidlog': {'type': 'bool', },
        'cgnv6_policy': {'type': 'str', 'choices': ['lsn-lid', 'fixed-nat']},
        'cgnv6_fixed_nat_log': {'type': 'bool', },
        'cgnv6_lsn_lid': {'type': 'int', },
        'cgnv6_lsn_log': {'type': 'bool', },
        'ip_version': {'type': 'str', 'choices': ['v4', 'v6']},
        'src_class_list': {'type': 'str', },
        'src_geoloc_name': {'type': 'str', },
        'src_geoloc_list': {'type': 'str', },
        'src_geoloc_list_shared': {'type': 'bool', },
        'src_ipv4_any': {'type': 'str', 'choices': ['any']},
        'src_ipv6_any': {'type': 'str', 'choices': ['any']},
        'source_list': {'type': 'list', 'src_ip_subnet': {'type': 'str', }, 'src_ipv6_subnet': {'type': 'str', }, 'src_obj_network': {'type': 'str', }, 'src_obj_grp_network': {'type': 'str', }, 'src_slb_server': {'type': 'str', }},
        'src_zone': {'type': 'str', },
        'src_zone_any': {'type': 'str', 'choices': ['any']},
        'src_threat_list': {'type': 'str', },
        'dst_class_list': {'type': 'str', },
        'dst_geoloc_name': {'type': 'str', },
        'dst_geoloc_list': {'type': 'str', },
        'dst_geoloc_list_shared': {'type': 'bool', },
        'dst_ipv4_any': {'type': 'str', 'choices': ['any']},
        'dst_ipv6_any': {'type': 'str', 'choices': ['any']},
        'dest_list': {'type': 'list', 'dst_ip_subnet': {'type': 'str', }, 'dst_ipv6_subnet': {'type': 'str', }, 'dst_obj_network': {'type': 'str', }, 'dst_obj_grp_network': {'type': 'str', }, 'dst_slb_server': {'type': 'str', }, 'dst_slb_vserver': {'type': 'str', }},
        'dst_domain_list': {'type': 'str', },
        'dst_zone': {'type': 'str', },
        'dst_zone_any': {'type': 'str', 'choices': ['any']},
        'dst_threat_list': {'type': 'str', },
        'service_any': {'type': 'str', 'choices': ['any']},
        'service_list': {'type': 'list', 'protocols': {'type': 'str', 'choices': ['tcp', 'udp', 'sctp']}, 'proto_id': {'type': 'int', }, 'obj_grp_service': {'type': 'str', }, 'icmp': {'type': 'bool', }, 'icmpv6': {'type': 'bool', }, 'icmp_type': {'type': 'int', }, 'special_type': {'type': 'str', 'choices': ['any-type', 'echo-reply', 'echo-request', 'info-reply', 'info-request', 'mask-reply', 'mask-request', 'parameter-problem', 'redirect', 'source-quench', 'time-exceeded', 'timestamp', 'timestamp-reply', 'dest-unreachable']}, 'icmp_code': {'type': 'int', }, 'special_code': {'type': 'str', 'choices': ['any-code', 'frag-required', 'host-unreachable', 'network-unreachable', 'port-unreachable', 'proto-unreachable', 'route-failed']}, 'icmpv6_type': {'type': 'int', }, 'special_v6_type': {'type': 'str', 'choices': ['any-type', 'dest-unreachable', 'echo-reply', 'echo-request', 'packet-too-big', 'param-prob', 'time-exceeded']}, 'icmpv6_code': {'type': 'int', }, 'special_v6_code': {'type': 'str', 'choices': ['any-code', 'addr-unreachable', 'admin-prohibited', 'no-route', 'not-neighbour', 'port-unreachable']}, 'eq_src_port': {'type': 'int', }, 'gt_src_port': {'type': 'int', }, 'lt_src_port': {'type': 'int', }, 'range_src_port': {'type': 'int', }, 'port_num_end_src': {'type': 'int', }, 'eq_dst_port': {'type': 'int', }, 'gt_dst_port': {'type': 'int', }, 'lt_dst_port': {'type': 'int', }, 'range_dst_port': {'type': 'int', }, 'port_num_end_dst': {'type': 'int', }, 'sctp_template': {'type': 'str', }, 'alg': {'type': 'str', 'choices': ['FTP', 'TFTP', 'SIP', 'DNS', 'PPTP', 'RTSP']}, 'gtp_template': {'type': 'str', }},
        'idle_timeout': {'type': 'int', },
        'application_any': {'type': 'str', 'choices': ['any']},
        'app_list': {'type': 'list', 'obj_grp_application': {'type': 'str', }, 'protocol': {'type': 'str', }, 'protocol_tag': {'type': 'str', 'choices': ['aaa', 'adult-content', 'advertising', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'chat', 'classified-ads', 'cloud-based-services', 'crowdfunding', 'cryptocurrency', 'database', 'disposable-email', 'ebook-reader', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'mobile', 'map-service', 'multimedia-streaming', 'networking', 'news-portal', 'peer-to-peer', 'remote-access', 'scada', 'social-networks', 'software-update', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites', 'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration', 'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions', 'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government', 'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals', 'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers', 'web-ext-real-estate', 'web-ext-reference-and-research', 'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements', 'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service']}},
        'track_application': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'hit-count', 'permit-bytes', 'deny-bytes', 'reset-bytes', 'permit-packets', 'deny-packets', 'reset-packets', 'active-session-tcp', 'active-session-udp', 'active-session-icmp', 'active-session-other', 'session-tcp', 'session-udp', 'session-icmp', 'session-other', 'active-session-sctp', 'session-sctp', 'hitcount-timestamp']}},
        'move_rule': {'type': 'dict', 'location': {'type': 'str', 'choices': ['top', 'before', 'after', 'bottom']}, 'target_rule': {'type': 'str', }},
        'oper': {'type': 'dict', 'hitcount': {'type': 'int', }, 'last_hitcount_time': {'type': 'str', }, 'action': {'type': 'str', }, 'status': {'type': 'str', }, 'permitbytes': {'type': 'int', }, 'denybytes': {'type': 'int', }, 'resetbytes': {'type': 'int', }, 'totalbytes': {'type': 'int', }, 'permitpackets': {'type': 'int', }, 'denypackets': {'type': 'int', }, 'resetpackets': {'type': 'int', }, 'totalpackets': {'type': 'int', }, 'activesessiontcp': {'type': 'int', }, 'activesessionudp': {'type': 'int', }, 'activesessionicmp': {'type': 'int', }, 'activesessionsctp': {'type': 'int', }, 'activesessionother': {'type': 'int', }, 'activesessiontotal': {'type': 'int', }, 'sessiontcp': {'type': 'int', }, 'sessionudp': {'type': 'int', }, 'sessionicmp': {'type': 'int', }, 'sessionsctp': {'type': 'int', }, 'sessionother': {'type': 'int', }, 'sessiontotal': {'type': 'int', }, 'name': {'type': 'str', 'required': True, }},
        'stats': {'type': 'dict', 'hit_count': {'type': 'str', }, 'permit_bytes': {'type': 'str', }, 'deny_bytes': {'type': 'str', }, 'reset_bytes': {'type': 'str', }, 'permit_packets': {'type': 'str', }, 'deny_packets': {'type': 'str', }, 'reset_packets': {'type': 'str', }, 'active_session_tcp': {'type': 'str', }, 'active_session_udp': {'type': 'str', }, 'active_session_icmp': {'type': 'str', }, 'active_session_other': {'type': 'str', }, 'session_tcp': {'type': 'str', }, 'session_udp': {'type': 'str', }, 'session_icmp': {'type': 'str', }, 'session_other': {'type': 'str', }, 'active_session_sctp': {'type': 'str', }, 'session_sctp': {'type': 'str', }, 'hitcount_timestamp': {'type': 'str', }, 'name': {'type': 'str', 'required': True, }}
    })
    # Parent keys
    rv.update(dict(
        rule_set_name=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{rule_set_name}/rule/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{rule_set_name}/rule/{name}"

    f_dict = {}
    f_dict["name"] = ""
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["rule"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["rule"].get(k) != v:
            change_results["changed"] = True
            config_changes["rule"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("rule", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
