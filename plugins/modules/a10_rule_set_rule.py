#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_rule_set_rule
description:
    - Configure rule-set rule
short_description: Configures A10 rule-set.rule
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    rule_set_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            denybytes:
                description:
                - "Field denybytes"
            activesessiontcp:
                description:
                - "Field activesessiontcp"
            permitbytes:
                description:
                - "Field permitbytes"
            sessiontcp:
                description:
                - "Field sessiontcp"
            resetpackets:
                description:
                - "Field resetpackets"
            sessionsctp:
                description:
                - "Field sessionsctp"
            sessionother:
                description:
                - "Field sessionother"
            totalbytes:
                description:
                - "Field totalbytes"
            activesessionicmp:
                description:
                - "Field activesessionicmp"
            denypackets:
                description:
                - "Field denypackets"
            hitcount:
                description:
                - "Field hitcount"
            status:
                description:
                - "Field status"
            activesessionother:
                description:
                - "Field activesessionother"
            sessionudp:
                description:
                - "Field sessionudp"
            sessionicmp:
                description:
                - "Field sessionicmp"
            sessiontotal:
                description:
                - "Field sessiontotal"
            totalpackets:
                description:
                - "Field totalpackets"
            activesessionudp:
                description:
                - "Field activesessionudp"
            permitpackets:
                description:
                - "Field permitpackets"
            name:
                description:
                - "Rule name"
            last_hitcount_time:
                description:
                - "Field last_hitcount_time"
            activesessiontotal:
                description:
                - "Field activesessiontotal"
            resetbytes:
                description:
                - "Field resetbytes"
            action:
                description:
                - "Field action"
            activesessionsctp:
                description:
                - "Field activesessionsctp"
    cgnv6_fixed_nat_log:
        description:
        - "Enable logging"
        required: False
    dst_geoloc_list_shared:
        description:
        - "Use Geolocation list from shared partition"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hit-count'= Hit counts; 'permit-bytes'= Permitted bytes counter; 'deny-bytes'= Denied bytes counter; 'reset-bytes'= Reset bytes counter; 'permit-packets'= Permitted packets counter; 'deny-packets'= Denied packets counter; 'reset-packets'= Reset packets counter; 'active-session-tcp'= Active TCP session counter; 'active-session-udp'= Active UDP session counter; 'active-session-icmp'= Active ICMP session counter; 'active-session-other'= Active other protocol session counter; 'session-tcp'= TCP session counter; 'session-udp'= UDP session counter; 'session-icmp'= ICMP session counter; 'session-other'= Other protocol session counter; 'active-session-sctp'= Active SCTP session counter; 'session-sctp'= SCTP session counter; 'hitcount-timestamp'= Last hit counts timestamp; "
    forward_listen_on_port:
        description:
        - "Listen on port"
        required: False
    reset_lidlog:
        description:
        - "Enable logging"
        required: False
    listen_on_port_lid:
        description:
        - "Apply a Template LID"
        required: False
    app_list:
        description:
        - "Field app_list"
        required: False
        suboptions:
            obj_grp_application:
                description:
                - "Application object group"
            protocol:
                description:
                - "Specify application(s)"
            protocol_tag:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and Accounting) purposes.; 'adult-content'= Adult content.; 'advertising'= Advertising networks and applications.; 'analytics-and-statistics'= user-analytics and statistics.; 'anonymizers-and-proxies'= Traffic-anonymization protocol/application.; 'audio-chat'= Protocol/application used for Audio Chat.; 'basic'= Protocols required for basic classification, e.g., ARP, HTTP; 'blog'= Blogging platform.; 'cdn'= Protocol/application used for Content-Delivery Networks.; 'chat'= Protocol/application used for Text Chat.; 'classified-ads'= Protocol/application used for Classified ads.; 'cloud-based-services'= SaaS and/or PaaS cloud based services.; 'cryptocurrency'= Cryptocurrency.; 'database'= Database-specific protocols.; 'disposable-email'= Disposable email accounts.; 'email'= Native email protocol.; 'enterprise'= Protocol/application used in an enterprise network.; 'file-management'= Protocol/application designed specifically for file management and exchange, e.g., Dropbox, SMB; 'file-transfer'= Protocol that offers file transferring as a functionality as a secondary feature. e.g., Skype, Whatsapp; 'forum'= Online forum.; 'gaming'= Protocol/application used by games.; 'instant-messaging-and-multimedia-conferencing'= Protocol/application used for Instant messaging or multiconferencing.; 'internet-of-things'= Internet Of Things protocol/application.; 'mobile'= Mobile-specific protocol/application.; 'multimedia-streaming'= Protocol/application used for multimedia streaming.; 'networking'= Protocol used for (inter) networking purpose.; 'news-portal'= Protocol/application used for News Portals.; 'peer-to-peer'= Protocol/application used for Peer-to-peer purposes.; 'remote-access'= Protocol/application used for remote access.; 'scada'= SCADA (Supervisory control and data acquisition) protocols, all generations.; 'social-networks'= Social networking application.; 'software-update'= Auto-update protocol.; 'standards-based'= Protocol issued from standardized bodies such as IETF, ITU, IEEE, ETSI, OIF.; 'transportation'= Transportation.; 'video-chat'= Protocol/application used for Video Chat.; 'voip'= Application used for Voice over IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'= Protocol/application used for E-commerce websites.; 'web-search-engines'= Protocol/application used for Web search portals.; 'web-websites'= Protocol/application used for Company Websites.; 'webmails'= Web email application.; 'web-ext-adult'= Web Extension Adult; 'web-ext-auctions'= Web Extension Auctions; 'web-ext-blogs'= Web Extension Blogs; 'web-ext-business-and-economy'= Web Extension Business and Economy; 'web-ext-cdns'= Web Extension CDNs; 'web-ext-collaboration'= Web Extension Collaboration; 'web-ext-computer-and-internet-info'= Web Extension Computer and Internet Info; 'web-ext-computer-and-internet-security'= Web Extension Computer and Internet Security; 'web-ext-dating'= Web Extension Dating; 'web-ext-educational-institutions'= Web Extension Educational Institutions; 'web-ext-entertainment-and-arts'= Web Extension Entertainment and Arts; 'web-ext-fashion-and-beauty'= Web Extension Fashion and Beauty; 'web-ext-file-share'= Web Extension File Share; 'web-ext-financial-services'= Web Extension Financial Services; 'web-ext-gambling'= Web Extension Gambling; 'web-ext-games'= Web Extension Games; 'web-ext-government'= Web Extension Government; 'web-ext-health-and-medicine'= Web Extension Health and Medicine; 'web-ext-individual-stock-advice-and-tools'= Web Extension Individual Stock Advice and Tools; 'web-ext-internet-portals'= Web Extension Internet Portals; 'web-ext-job-search'= Web Extension Job Search; 'web-ext-local-information'= Web Extension Local Information; 'web-ext-malware'= Web Extension Malware; 'web-ext-motor-vehicles'= Web Extension Motor Vehicles; 'web-ext-music'= Web Extension Music; 'web-ext-news'= Web Extension News; 'web-ext-p2p'= Web Extension P2P; 'web-ext-parked-sites'= Web Extension Parked Sites; 'web-ext-proxy-avoid-and-anonymizers'= Web Extension Proxy Avoid and Anonymizers; 'web-ext-real-estate'= Web Extension Real Estate; 'web-ext-reference-and-research'= Web Extension Reference and Research; 'web-ext-search-engines'= Web Extension Search Engines; 'web-ext-shopping'= Web Extension Shopping; 'web-ext-social-network'= Web Extension Social Network; 'web-ext-society'= Web Extension Society; 'web-ext-software'= Web Extension Software; 'web-ext-sports'= Web Extension Sports; 'web-ext-streaming-media'= Web Extension Streaming Media; 'web-ext-training-and-tools'= Web Extension Training and Tools; 'web-ext-translation'= Web Extension Translation; 'web-ext-travel'= Web Extension Travel; 'web-ext-web-advertisements'= Web Extension Web Advertisements; 'web-ext-web-based-email'= Web Extension Web based Email; 'web-ext-web-hosting'= Web Extension Web Hosting; 'web-ext-web-service'= Web Extension Web Service; "
    src_threat_list:
        description:
        - "Bind threat-list for source IP based filtering"
        required: False
    cgnv6_policy:
        description:
        - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT; "
        required: False
    src_geoloc_name:
        description:
        - "Single geolocation name"
        required: False
    cgnv6_log:
        description:
        - "Enable logging"
        required: False
    forward_log:
        description:
        - "Enable logging"
        required: False
    lid:
        description:
        - "Apply a Template LID"
        required: False
    listen_on_port:
        description:
        - "Listen on port"
        required: False
    move_rule:
        description:
        - "Field move_rule"
        required: False
        suboptions:
            location:
                description:
                - "'top'= top; 'before'= before; 'after'= after; 'bottom'= bottom; "
            target_rule:
                description:
                - "Field target_rule"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            active_session_other:
                description:
                - "Active other protocol session counter"
            session_icmp:
                description:
                - "ICMP session counter"
            hit_count:
                description:
                - "Hit counts"
            active_session_tcp:
                description:
                - "Active TCP session counter"
            deny_packets:
                description:
                - "Denied packets counter"
            session_other:
                description:
                - "Other protocol session counter"
            name:
                description:
                - "Rule name"
            session_sctp:
                description:
                - "SCTP session counter"
            active_session_icmp:
                description:
                - "Active ICMP session counter"
            permit_bytes:
                description:
                - "Permitted bytes counter"
            reset_packets:
                description:
                - "Reset packets counter"
            hitcount_timestamp:
                description:
                - "Last hit counts timestamp"
            reset_bytes:
                description:
                - "Reset bytes counter"
            session_tcp:
                description:
                - "TCP session counter"
            session_udp:
                description:
                - "UDP session counter"
            active_session_sctp:
                description:
                - "Active SCTP session counter"
            active_session_udp:
                description:
                - "Active UDP session counter"
            deny_bytes:
                description:
                - "Denied bytes counter"
            permit_packets:
                description:
                - "Permitted packets counter"
    log:
        description:
        - "Enable logging"
        required: False
    dst_geoloc_name:
        description:
        - "Single geolocation name"
        required: False
    idle_timeout:
        description:
        - "TCP/UDP idle-timeout"
        required: False
    listen_on_port_lidlog:
        description:
        - "Enable logging"
        required: False
    src_zone_any:
        description:
        - "'any'= any; "
        required: False
    ip_version:
        description:
        - "'v4'= IPv4 rule; 'v6'= IPv6 rule; "
        required: False
    application_any:
        description:
        - "'any'= any; "
        required: False
    src_zone:
        description:
        - "Zone name"
        required: False
    src_geoloc_list_shared:
        description:
        - "Use Geolocation list from shared partition"
        required: False
    policy:
        description:
        - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet; "
        required: False
    source_list:
        description:
        - "Field source_list"
        required: False
        suboptions:
            src_ipv6_subnet:
                description:
                - "IPv6 IP Address"
            src_obj_network:
                description:
                - "Network object"
            src_slb_server:
                description:
                - "SLB Real server name"
            src_obj_grp_network:
                description:
                - "Network object group"
            src_ip_subnet:
                description:
                - "IPv4 IP Address"
    dst_zone_any:
        description:
        - "'any'= any; "
        required: False
    status:
        description:
        - "'enable'= Enable rule; 'disable'= Disable rule; "
        required: False
    lidlog:
        description:
        - "Enable logging"
        required: False
    dst_ipv4_any:
        description:
        - "'any'= Any IPv4 address; "
        required: False
    cgnv6_lsn_lid:
        description:
        - "LSN LID"
        required: False
    src_geoloc_list:
        description:
        - "Geolocation name list"
        required: False
    src_ipv4_any:
        description:
        - "'any'= Any IPv4 address; "
        required: False
    fwlog:
        description:
        - "Enable logging"
        required: False
    dst_zone:
        description:
        - "Zone name"
        required: False
    dst_class_list:
        description:
        - "Match destination IP against class-list"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    dst_threat_list:
        description:
        - "Bind threat-list for destination IP based filtering"
        required: False
    remark:
        description:
        - "Rule entry comment (Notes for this rule)"
        required: False
    src_class_list:
        description:
        - "Match source IP against class-list"
        required: False
    name:
        description:
        - "Rule name"
        required: True
    src_ipv6_any:
        description:
        - "'any'= Any IPv6 address; "
        required: False
    reset_lid:
        description:
        - "Apply a Template LID"
        required: False
    dst_geoloc_list:
        description:
        - "Geolocation name list"
        required: False
    track_application:
        description:
        - "Enable application statistic"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    cgnv6_lsn_log:
        description:
        - "Enable logging"
        required: False
    dst_ipv6_any:
        description:
        - "'any'= Any IPv6 address; "
        required: False
    service_any:
        description:
        - "'any'= any; "
        required: False
    service_list:
        description:
        - "Field service_list"
        required: False
        suboptions:
            gtp_template:
                description:
                - "Configure GTP template (GTP Template Name)"
            icmp_type:
                description:
                - "ICMP type number"
            range_dst_port:
                description:
                - "Port range (Starting Port Number)"
            icmpv6_code:
                description:
                - "ICMPv6 code number"
            gt_src_port:
                description:
                - "Greater than the port number"
            lt_src_port:
                description:
                - "Lower than the port number"
            proto_id:
                description:
                - "Protocol ID"
            lt_dst_port:
                description:
                - "Lower than the port number"
            alg:
                description:
                - "'FTP'= FTP; 'TFTP'= TFTP; 'SIP'= SIP; 'DNS'= DNS; 'PPTP'= PPTP; 'RTSP'= RTSP; "
            obj_grp_service:
                description:
                - "service object group"
            icmpv6_type:
                description:
                - "ICMPv6 type number"
            icmp_code:
                description:
                - "ICMP code number"
            range_src_port:
                description:
                - "Port range (Starting Port Number)"
            eq_dst_port:
                description:
                - "Equal to the port number"
            sctp_template:
                description:
                - "SCTP Template"
            icmp:
                description:
                - "ICMP"
            protocols:
                description:
                - "'tcp'= tcp; 'udp'= udp; 'sctp'= sctp; "
            gt_dst_port:
                description:
                - "Greater than the port number"
            port_num_end_src:
                description:
                - "Ending Port Number"
            special_v6_type:
                description:
                - "'any-type'= Any ICMPv6 type; 'dest-unreachable'= Type 1, destination unreachable; 'echo-reply'= Type 129, echo reply; 'echo-request'= Type 128, echo request; 'packet-too-big'= Type 2, packet too big; 'param-prob'= Type 4, parameter problem; 'time-exceeded'= Type 3, time exceeded; "
            eq_src_port:
                description:
                - "Equal to the port number"
            special_v6_code:
                description:
                - "'any-code'= Any ICMPv6 code; 'addr-unreachable'= Code 3, address unreachable; 'admin-prohibited'= Code 1, admin prohibited; 'no-route'= Code 0, no route to destination; 'not-neighbour'= Code 2, not neighbor; 'port-unreachable'= Code 4, destination port unreachable; "
            icmpv6:
                description:
                - "ICMPv6"
            port_num_end_dst:
                description:
                - "Ending Port Number"
            special_code:
                description:
                - "'any-code'= Any ICMP code; 'frag-required'= Code 4, fragmentation required; 'host-unreachable'= Code 1, destination host unreachable; 'network-unreachable'= Code 0, destination network unreachable; 'port-unreachable'= Code 3, destination port unreachable; 'proto-unreachable'= Code 2, destination protocol unreachable; 'route-failed'= Code 5, source route failed; "
            special_type:
                description:
                - "'any-type'= Any ICMP type; 'echo-reply'= Type 0, echo reply; 'echo-request'= Type 8, echo request; 'info-reply'= Type 16, information reply; 'info-request'= Type 15, information request; 'mask-reply'= Type 18, address mask reply; 'mask-request'= Type 17, address mask request; 'parameter-problem'= Type 12, parameter problem; 'redirect'= Type 5, redirect message; 'source-quench'= Type 4, source quench; 'time-exceeded'= Type 11, time exceeded; 'timestamp'= Type 13, timestamp; 'timestamp-reply'= Type 14, timestamp reply; 'dest-unreachable'= Type 3, destination unreachable; "
    dst_domain_list:
        description:
        - "Match destination IP against domain-list"
        required: False
    dest_list:
        description:
        - "Field dest_list"
        required: False
        suboptions:
            dst_obj_network:
                description:
                - "Network object"
            dst_obj_grp_network:
                description:
                - "Network object group"
            dst_slb_vserver:
                description:
                - "SLB Virtual server name"
            dst_ip_subnet:
                description:
                - "IPv4 IP Address"
            dst_ipv6_subnet:
                description:
                - "IPv6 IP Address"
            dst_slb_server:
                description:
                - "SLB Real server name"
    action:
        description:
        - "'permit'= permit; 'deny'= deny; 'reset'= reset; "
        required: False
    fw_log:
        description:
        - "Enable logging"
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
AVAILABLE_PROPERTIES = ["action","app_list","application_any","cgnv6_fixed_nat_log","cgnv6_log","cgnv6_lsn_lid","cgnv6_lsn_log","cgnv6_policy","dest_list","dst_class_list","dst_domain_list","dst_geoloc_list","dst_geoloc_list_shared","dst_geoloc_name","dst_ipv4_any","dst_ipv6_any","dst_threat_list","dst_zone","dst_zone_any","forward_listen_on_port","forward_log","fw_log","fwlog","idle_timeout","ip_version","lid","lidlog","listen_on_port","listen_on_port_lid","listen_on_port_lidlog","log","move_rule","name","oper","policy","remark","reset_lid","reset_lidlog","sampling_enable","service_any","service_list","source_list","src_class_list","src_geoloc_list","src_geoloc_list_shared","src_geoloc_name","src_ipv4_any","src_ipv6_any","src_threat_list","src_zone","src_zone_any","stats","status","track_application","user_tag","uuid",]

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
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', denybytes=dict(type='int', ), activesessiontcp=dict(type='int', ), permitbytes=dict(type='int', ), sessiontcp=dict(type='int', ), resetpackets=dict(type='int', ), sessionsctp=dict(type='int', ), sessionother=dict(type='int', ), totalbytes=dict(type='int', ), activesessionicmp=dict(type='int', ), denypackets=dict(type='int', ), hitcount=dict(type='int', ), status=dict(type='str', ), activesessionother=dict(type='int', ), sessionudp=dict(type='int', ), sessionicmp=dict(type='int', ), sessiontotal=dict(type='int', ), totalpackets=dict(type='int', ), activesessionudp=dict(type='int', ), permitpackets=dict(type='int', ), name=dict(type='str', required=True, ), last_hitcount_time=dict(type='str', ), activesessiontotal=dict(type='int', ), resetbytes=dict(type='int', ), action=dict(type='str', ), activesessionsctp=dict(type='int', )),
        cgnv6_fixed_nat_log=dict(type='bool', ),
        dst_geoloc_list_shared=dict(type='bool', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hit-count', 'permit-bytes', 'deny-bytes', 'reset-bytes', 'permit-packets', 'deny-packets', 'reset-packets', 'active-session-tcp', 'active-session-udp', 'active-session-icmp', 'active-session-other', 'session-tcp', 'session-udp', 'session-icmp', 'session-other', 'active-session-sctp', 'session-sctp', 'hitcount-timestamp'])),
        forward_listen_on_port=dict(type='bool', ),
        reset_lidlog=dict(type='bool', ),
        listen_on_port_lid=dict(type='int', ),
        app_list=dict(type='list', obj_grp_application=dict(type='str', ), protocol=dict(type='str', ), protocol_tag=dict(type='str', choices=['aaa', 'adult-content', 'advertising', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'chat', 'classified-ads', 'cloud-based-services', 'cryptocurrency', 'database', 'disposable-email', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'mobile', 'multimedia-streaming', 'networking', 'news-portal', 'peer-to-peer', 'remote-access', 'scada', 'social-networks', 'software-update', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites', 'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration', 'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions', 'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government', 'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals', 'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers', 'web-ext-real-estate', 'web-ext-reference-and-research', 'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements', 'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service'])),
        src_threat_list=dict(type='str', ),
        cgnv6_policy=dict(type='str', choices=['lsn-lid', 'fixed-nat']),
        src_geoloc_name=dict(type='str', ),
        cgnv6_log=dict(type='bool', ),
        forward_log=dict(type='bool', ),
        lid=dict(type='int', ),
        listen_on_port=dict(type='bool', ),
        move_rule=dict(type='dict', location=dict(type='str', choices=['top', 'before', 'after', 'bottom']), target_rule=dict(type='str', )),
        stats=dict(type='dict', active_session_other=dict(type='str', ), session_icmp=dict(type='str', ), hit_count=dict(type='str', ), active_session_tcp=dict(type='str', ), deny_packets=dict(type='str', ), session_other=dict(type='str', ), name=dict(type='str', required=True, ), session_sctp=dict(type='str', ), active_session_icmp=dict(type='str', ), permit_bytes=dict(type='str', ), reset_packets=dict(type='str', ), hitcount_timestamp=dict(type='str', ), reset_bytes=dict(type='str', ), session_tcp=dict(type='str', ), session_udp=dict(type='str', ), active_session_sctp=dict(type='str', ), active_session_udp=dict(type='str', ), deny_bytes=dict(type='str', ), permit_packets=dict(type='str', )),
        log=dict(type='bool', ),
        dst_geoloc_name=dict(type='str', ),
        idle_timeout=dict(type='int', ),
        listen_on_port_lidlog=dict(type='bool', ),
        src_zone_any=dict(type='str', choices=['any']),
        ip_version=dict(type='str', choices=['v4', 'v6']),
        application_any=dict(type='str', choices=['any']),
        src_zone=dict(type='str', ),
        src_geoloc_list_shared=dict(type='bool', ),
        policy=dict(type='str', choices=['cgnv6', 'forward']),
        source_list=dict(type='list', src_ipv6_subnet=dict(type='str', ), src_obj_network=dict(type='str', ), src_slb_server=dict(type='str', ), src_obj_grp_network=dict(type='str', ), src_ip_subnet=dict(type='str', )),
        dst_zone_any=dict(type='str', choices=['any']),
        status=dict(type='str', choices=['enable', 'disable']),
        lidlog=dict(type='bool', ),
        dst_ipv4_any=dict(type='str', choices=['any']),
        cgnv6_lsn_lid=dict(type='int', ),
        src_geoloc_list=dict(type='str', ),
        src_ipv4_any=dict(type='str', choices=['any']),
        fwlog=dict(type='bool', ),
        dst_zone=dict(type='str', ),
        dst_class_list=dict(type='str', ),
        uuid=dict(type='str', ),
        dst_threat_list=dict(type='str', ),
        remark=dict(type='str', ),
        src_class_list=dict(type='str', ),
        name=dict(type='str', required=True, ),
        src_ipv6_any=dict(type='str', choices=['any']),
        reset_lid=dict(type='int', ),
        dst_geoloc_list=dict(type='str', ),
        track_application=dict(type='bool', ),
        user_tag=dict(type='str', ),
        cgnv6_lsn_log=dict(type='bool', ),
        dst_ipv6_any=dict(type='str', choices=['any']),
        service_any=dict(type='str', choices=['any']),
        service_list=dict(type='list', gtp_template=dict(type='str', ), icmp_type=dict(type='int', ), range_dst_port=dict(type='int', ), icmpv6_code=dict(type='int', ), gt_src_port=dict(type='int', ), lt_src_port=dict(type='int', ), proto_id=dict(type='int', ), lt_dst_port=dict(type='int', ), alg=dict(type='str', choices=['FTP', 'TFTP', 'SIP', 'DNS', 'PPTP', 'RTSP']), obj_grp_service=dict(type='str', ), icmpv6_type=dict(type='int', ), icmp_code=dict(type='int', ), range_src_port=dict(type='int', ), eq_dst_port=dict(type='int', ), sctp_template=dict(type='str', ), icmp=dict(type='bool', ), protocols=dict(type='str', choices=['tcp', 'udp', 'sctp']), gt_dst_port=dict(type='int', ), port_num_end_src=dict(type='int', ), special_v6_type=dict(type='str', choices=['any-type', 'dest-unreachable', 'echo-reply', 'echo-request', 'packet-too-big', 'param-prob', 'time-exceeded']), eq_src_port=dict(type='int', ), special_v6_code=dict(type='str', choices=['any-code', 'addr-unreachable', 'admin-prohibited', 'no-route', 'not-neighbour', 'port-unreachable']), icmpv6=dict(type='bool', ), port_num_end_dst=dict(type='int', ), special_code=dict(type='str', choices=['any-code', 'frag-required', 'host-unreachable', 'network-unreachable', 'port-unreachable', 'proto-unreachable', 'route-failed']), special_type=dict(type='str', choices=['any-type', 'echo-reply', 'echo-request', 'info-reply', 'info-request', 'mask-reply', 'mask-request', 'parameter-problem', 'redirect', 'source-quench', 'time-exceeded', 'timestamp', 'timestamp-reply', 'dest-unreachable'])),
        dst_domain_list=dict(type='str', ),
        dest_list=dict(type='list', dst_obj_network=dict(type='str', ), dst_obj_grp_network=dict(type='str', ), dst_slb_vserver=dict(type='str', ), dst_ip_subnet=dict(type='str', ), dst_ipv6_subnet=dict(type='str', ), dst_slb_server=dict(type='str', )),
        action=dict(type='str', choices=['permit', 'deny', 'reset']),
        fw_log=dict(type='bool', )
    ))
   
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
    url_base = "/axapi/v3/rule-set/{rule_set_name}/rule/{name}"

    f_dict = {}
    f_dict["name"] = ""
    f_dict["rule_set_name"] = module.params["rule_set_name"]

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
        for k, v in payload["rule"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rule"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rule"][k] = v
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
    payload = build_json("rule", module)
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
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
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

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
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