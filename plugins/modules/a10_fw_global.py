#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_global
description:
    - Configure firewall parameters
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
    disable_ip_fw_sessions:
        description:
        - "disable create sessions for non TCP/UDP/ICMP"
        type: bool
        required: False
    disable_undetermined_rule_logs:
        description:
        - "disable logs with undetermined rules"
        type: bool
        required: False
    alg_processing:
        description:
        - "'honor-rule-set'= Honors firewall rule-sets (Default); 'override-rule-set'=
          Override firewall rule-sets;"
        type: str
        required: False
    extended_matching:
        description:
        - "'disable'= Disable extended matching;"
        type: str
        required: False
    permit_default_action:
        description:
        - "'forward'= Forward; 'next-service-mode'= Service to be applied chosen based on
          configuration;"
        type: str
        required: False
    natip_ddos_protection:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    listen_on_port_timeout:
        description:
        - "STUN timeout (default= 2 minutes)"
        type: int
        required: False
    inbound_refresh_full_cone:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    inbound_refresh:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table
          (default= off)"
        type: bool
        required: False
    disable_app_list:
        description:
        - "Field disable_app_list"
        type: list
        required: False
        suboptions:
            disable_application_protocol:
                description:
                - "Disable specific application protocol"
                type: str
            disable_application_category:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and
          Accounting) purposes.; 'adult-content'= Adult content protocol/application.;
          'advertising'= Advertising networks and applications.; 'application-enforcing-
          tls'= Application known to enforce HSTS and thus use of TLS.; 'analytics-and-
          statistics'= User analytics and statistics protocol/application.; 'anonymizers-
          and-proxies'= Traffic-anonymization protocol/application.; 'audio-chat'=
          Protocol/application used for Audio Chat.; 'basic'= Covers all protocols
          required for basic classification, including most networking protocols as well
          as standard protocols like HTTP.; 'blog'= Blogging platform
          protocol/application.; 'cdn'= Protocol/application used for Content-Delivery
          Networks.; 'certification-authority'= Certification Authority for SSL/TLS
          certificate.; 'chat'= Protocol/application used for Text Chat.; 'classified-
          ads'= Protocol/application used for Classified Advertisements.; 'cloud-based-
          services'= SaaS and/or PaaS cloud based services.; 'crowdfunding'= Service for
          funding a project or venture by raising small amounts of money from a large
          number of people, typically via the Internet.; 'cryptocurrency'= Services for
          mining cryptocurrencies, for example a Crypto Web Browser (an application that
          mines crypto currency in the background while its user browses the web).;
          'database'= Database-specific protocols.; 'disposable-email'= Service offering
          Disposable Email Accounts (DEA). DEA is a technique to share temporary email
          address between many users.; 'ebook-reader'= Services for e-book readers, i.e.
          connected devices that display electronic books (typically using e-ink displays
          to reduce glare and eye strain).; 'education'= Protocols offering education
          services and online courses.; 'email'= Native email protocol.; 'enterprise'=
          Protocol/application used in an enterprise network.; 'file-management'=
          Protocol/application designed specifically for file management and exchange.
          This can include bona fide network protocols (like SMB) as well as web/cloud
          services (like Dropbox).; 'file-transfer'= Protocol that offers file
          transferring as a secondary feature. This typically includes IM, WebMail, and
          other protocols that allow file transfers in addition to their principal
          function.; 'forum'= Online forum protocol/application.; 'gaming'=
          Protocol/application used by games.; 'healthcare'= Protocols offering medical
          services, i.e protocols used in medical environment.; 'instant-messaging-and-
          multimedia-conferencing'= Protocol/application used for Instant Messaging or
          Multi-Conferencing.; 'internet-of-things'= Internet Of Things
          protocol/application.; 'map-service'= Digital Maps service (web site and their
          related API).; 'mobile'= Mobile-specific protocol/application.; 'multimedia-
          streaming'= Protocol/application used for multimedia streaming.; 'networking'=
          Protocol used for (inter) networking purpose.; 'news-portal'=
          Protocol/application used for News Portals.; 'payment-service'= Application
          offering online services for accepting electronic payments by a variety of
          payment methods (credit card, bank-based payments such as direct debit, bank
          transfer, etc).; 'peer-to-peer'= Protocol/application used for Peer-to-peer
          purposes.; 'remote-access'= Protocol/application used for remote access.;
          'scada'= SCADA (Supervisory control and data acquisition) protocols, all
          generations.; 'social-networks'= Social networking application.; 'software-
          update'= Auto-update protocol.; 'speedtest'= Speedtest application allowing to
          access quality of Internet connection (upload, download, latency, etc).;
          'standards-based'= Protocol issued from standardized bodies such as IETF, ITU,
          IEEE, ETSI, OIF.; 'transportation'= Transportation services, for example
          smartphone applications that allow users to hail a taxi.; 'video-chat'=
          Protocol/application used for Video Chat.; 'voip'= Application used for Voice-
          Over-IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling
          purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'=
          Protocol/application used for E-commerce websites.; 'web-search-engines'=
          Protocol/application used for Web search portals.; 'web-websites'=
          Protocol/application used for Company Websites.; 'webmails'= Web-based e-mail
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
    disable_application_metrics:
        description:
        - "Disable exporting application protocol/category statistics to Harmony
          Controller"
        type: bool
        required: False
    allow_non_syn_session_create:
        description:
        - "Allow TCP non-syn packets to trigger session creation"
        type: bool
        required: False
    dsr_mode_support:
        description:
        - "'ipv4'= support dsr for ipv4 traffic; 'ipv6'= support dsr for ipv6 traffic;
          'all'= support dsr for both ipv4 and ipv6;"
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
                - "'all'= all; 'tcp_fullcone_created'= TCP Full-cone Created;
          'tcp_fullcone_freed'= TCP Full-cone Freed; 'udp_fullcone_created'= UDP Full-
          cone Created; 'udp_fullcone_freed'= UDP Full-cone Freed;
          'fullcone_creation_failure'= Full-Cone Creation Failure;
          'data_session_created'= Data Session Created; 'data_session_created_local'=
          Data Session Created Local; 'dyn_blist_sess_sp'= Dynamic Blacklist Session
          (Slowpath); 'data_session_freed'= Data Session Freed;
          'data_session_freed_local'= Data Session Freed Local; 'dyn_blist_sess_created'=
          Dynamic Blacklist Session Created; 'dyn_blist_sess_freed'= Dynamic Blacklist
          Freed; 'dyn_blist_pkt_drop'= Dynamic Blacklist - Packet Drop;
          'dyn_blist_pkt_rate_low'= Dynamic Blacklist - Pkt Rate Low;
          'dyn_blist_pkt_rate_high'= Dynamic Blacklist - Pkt Rate High;
          'dyn_blist_version_mismatch'= Dynamic Blacklist - Version Mismatch;
          'dyn_blist_no_active_policy'= Dynamic Blacklist - No Active Policy;
          'fullcone_in_del_q'= Full-cone session found in delete queue;
          'fullcone_retry_lookup'= Full-cone session retry look-up; 'fullcone_not_found'=
          Full-cone session not found; 'fullcone_overflow_eim'= Full-cone Session EIM
          Overflow; 'fullcone_overflow_eif'= Full-cone Session EIF Overflow;
          'udp_fullcone_created_shadow'= Total UDP Full-cone sessions created;
          'tcp_fullcone_created_shadow'= Total TCP Full-cone sessions created;
          'udp_fullcone_freed_shadow'= Total UDP Full-cone sessions freed;
          'tcp_fullcone_freed_shadow'= Total TCP Full-cone sessions freed;
          'fullcone_created'= Total Full-cone sessions created; 'fullcone_freed'= Total
          Full-cone sessions freed; 'fullcone_ext_too_many'= Fullcone Extension Too Many;
          'fullcone_ext_mem_allocated'= Fullcone Extension Memory Allocated;
          'fullcone_ext_mem_alloc_failure'= Fullcone Extension Memory Allocate Failure;
          'fullcone_ext_mem_alloc_init_faulure'= Fullcone Extension Initialization
          Failure; 'fullcone_ext_mem_freed'= Fullcone Extension Memory Freed;
          'fullcone_ext_added'= Fullcone Extension Added; 'ha_fullcone_failure'= HA Full-
          cone Session Failure; 'data_session_created_shadow'= Shadow Data Sessions
          Created; 'data_session_created_shadow_local'= Shadow Data Sessions Created
          Local; 'data_session_freed_shadow'= Shadow Data Sessions Freed;
          'data_session_freed_shadow_local'= Shadow Data Sessions Freed Local;
          'active_fullcone_session'= Total Active Full-cone sessions; 'limit-entry-
          failure'= Limit Entry Creation Failure; 'limit-entry-allocated'= Limit Entry
          Allocated; 'limit-entry-mem-freed'= Limit Entry Freed; 'limit-entry-created'=
          Limit Entry Created; 'limit-entry-found'= Limit Entry Found; 'limit-entry-not-
          in-bucket'= Limit Entry Not in Bucket; 'limit-entry-marked-deleted'= Limit
          Entry Marked Deleted; 'undetermined-rule-counter'= Undetermined rule detected;
          'non_syn_pkt_fwd_allowed'= Non-SYN pkt forward allowed; 'invalid-lid-drop'=
          Invalid Lid Drop; 'src-session-limit-exceeded'= Concurrent Session Limit
          Exceeded; 'uplink-pps-limit-exceeded'= Uplink PPS Limit Exceeded; 'downlink-
          pps-limit-exceeded'= Downlink PPS Limit Exceeded; 'total-pps-limit-exceeded'=
          Total PPS Limit Exceeded; 'uplink-throughput-limit-exceeded'= Uplink Throughput
          Limit Exceeded; 'downlink-throughput-limit-exceeded'= Downlink Throughput Limit
          Exceeded; 'total-throughput-limit-exceeded'= Total Throughput Limit Exceeded;
          'cps-limit-exceeded'= Connections Per Second Limit Exceeded; 'limit-exceeded'=
          Per Second Limit Exceeded (Deprecated); 'limit-entry-per-cpu-mem-allocated'=
          Limit Entry Memory Allocated (Deprecated); 'limit-entry-per-cpu-mem-allocation-
          failed'= Limit Entry Memory Allocation Failed (Deprecated); 'limit-entry-per-
          cpu-mem-freed'= Limit Entry Memory Freed (Deprecated);
          'alg_default_port_disable'= alg_default_port_disable; 'no_fwd_route'= No
          Forward Route; 'no_rev_route'= No Reverse Route; 'no_fwd_l2_dst'= No Forward
          Mac Entry; 'no_rev_l2_dst'= No Reverse Mac Entry; 'l2_dst_in_out_same'= L2
          route to same port as received; 'l2_vlan_changed'= L2 forwarding vlan changed
          after session create; 'urpf_pkt_drop'= URPF check packet drop;
          'fwd_ingress_packets_tcp'= Forward Ingress Packets TCP;
          'fwd_egress_packets_tcp'= Forward Egress Packets TCP;
          'rev_ingress_packets_tcp'= Reverse Ingress Packets TCP;
          'rev_egress_packets_tcp'= Reverse Egress Packets TCP; 'fwd_ingress_bytes_tcp'=
          Forward Ingress Bytes TCP; 'fwd_egress_bytes_tcp'= Forward Egress Bytes TCP;
          'rev_ingress_bytes_tcp'= Reverse Ingress Bytes TCP; 'rev_egress_bytes_tcp'=
          Reverse Egress Bytes TCP; 'fwd_ingress_packets_udp'= Forward Ingress Packets
          UDP; 'fwd_egress_packets_udp'= Forward Egress Packets UDP;
          'rev_ingress_packets_udp'= Reverse Ingress Packets UDP;
          'rev_egress_packets_udp'= Reverse Egress Packets UDP; 'fwd_ingress_bytes_udp'=
          Forward Ingress Bytes UDP; 'fwd_egress_bytes_udp'= Forward Egress Bytes UDP;
          'rev_ingress_bytes_udp'= Reverse Ingress Bytes UDP; 'rev_egress_bytes_udp'=
          Reverse Egress Bytes UDP; 'fwd_ingress_packets_icmp'= Forward Ingress Packets
          ICMP; 'fwd_egress_packets_icmp'= Forward Egress Packets ICMP;
          'rev_ingress_packets_icmp'= Reverse Ingress Packets ICMP;
          'rev_egress_packets_icmp'= Reverse Egress Packets ICMP;
          'fwd_ingress_bytes_icmp'= Forward Ingress Bytes ICMP; 'fwd_egress_bytes_icmp'=
          Forward Egress Bytes ICMP; 'rev_ingress_bytes_icmp'= Reverse Ingress Bytes
          ICMP; 'rev_egress_bytes_icmp'= Reverse Egress Bytes ICMP;
          'fwd_ingress_packets_others'= Forward Ingress Packets OTHERS;
          'fwd_egress_packets_others'= Forward Egress Packets OTHERS;
          'rev_ingress_packets_others'= Reverse Ingress Packets OTHERS;
          'rev_egress_packets_others'= Reverse Egress Packets OTHERS;
          'fwd_ingress_bytes_others'= Forward Ingress Bytes OTHERS;
          'fwd_egress_bytes_others'= Forward Egress Bytes OTHERS;
          'rev_ingress_bytes_others'= Reverse Ingress Bytes OTHERS;
          'rev_egress_bytes_others'= Reverse Egress Bytes OTHERS;
          'fwd_ingress_pkt_size_range1'= Forward Ingress Packet size between 0 and 200;
          'fwd_ingress_pkt_size_range2'= Forward Ingress Packet size between 201 and 800;
          'fwd_ingress_pkt_size_range3'= Forward Ingress Packet size between 801 and
          1550; 'fwd_ingress_pkt_size_range4'= Forward Ingress Packet size between 1551
          and 9000; 'fwd_egress_pkt_size_range1'= Forward Egress Packet size between 0
          and 200; 'fwd_egress_pkt_size_range2'= Forward Egress Packet size between 201
          and 800; 'fwd_egress_pkt_size_range3'= Forward Egress Packet size between 801
          and 1550; 'fwd_egress_pkt_size_range4'= Forward Egress Packet size between 1551
          and 9000; 'rev_ingress_pkt_size_range1'= Reverse Ingress Packet size between 0
          and 200; 'rev_ingress_pkt_size_range2'= Reverse Ingress Packet size between 201
          and 800; 'rev_ingress_pkt_size_range3'= Reverse Ingress Packet size between 801
          and 1550; 'rev_ingress_pkt_size_range4'= Reverse Ingress Packet size between
          1551 and 9000; 'rev_egress_pkt_size_range1'= Reverse Egress Packet size between
          0 and 200; 'rev_egress_pkt_size_range2'= Reverse Egress Packet size between 201
          and 800; 'rev_egress_pkt_size_range3'= Reverse Egress Packet size between 801
          and 1550; 'rev_egress_pkt_size_range4'= Reverse Egress Packet size between 1551
          and 9000;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            tcp_fullcone_created:
                description:
                - "TCP Full-cone Created"
                type: str
            tcp_fullcone_freed:
                description:
                - "TCP Full-cone Freed"
                type: str
            udp_fullcone_created:
                description:
                - "UDP Full-cone Created"
                type: str
            udp_fullcone_freed:
                description:
                - "UDP Full-cone Freed"
                type: str
            fullcone_creation_failure:
                description:
                - "Full-Cone Creation Failure"
                type: str
            data_session_created:
                description:
                - "Data Session Created"
                type: str
            data_session_created_local:
                description:
                - "Data Session Created Local"
                type: str
            data_session_freed:
                description:
                - "Data Session Freed"
                type: str
            data_session_freed_local:
                description:
                - "Data Session Freed Local"
                type: str
            dyn_blist_sess_created:
                description:
                - "Dynamic Blacklist Session Created"
                type: str
            dyn_blist_sess_freed:
                description:
                - "Dynamic Blacklist Freed"
                type: str
            dyn_blist_pkt_drop:
                description:
                - "Dynamic Blacklist - Packet Drop"
                type: str
            active_fullcone_session:
                description:
                - "Total Active Full-cone sessions"
                type: str
            limit_entry_created:
                description:
                - "Limit Entry Created"
                type: str
            limit_entry_marked_deleted:
                description:
                - "Limit Entry Marked Deleted"
                type: str
            undetermined_rule_counter:
                description:
                - "Undetermined rule detected"
                type: str
            non_syn_pkt_fwd_allowed:
                description:
                - "Non-SYN pkt forward allowed"
                type: str
            fwd_ingress_packets_tcp:
                description:
                - "Forward Ingress Packets TCP"
                type: str
            fwd_egress_packets_tcp:
                description:
                - "Forward Egress Packets TCP"
                type: str
            rev_ingress_packets_tcp:
                description:
                - "Reverse Ingress Packets TCP"
                type: str
            rev_egress_packets_tcp:
                description:
                - "Reverse Egress Packets TCP"
                type: str
            fwd_ingress_bytes_tcp:
                description:
                - "Forward Ingress Bytes TCP"
                type: str
            fwd_egress_bytes_tcp:
                description:
                - "Forward Egress Bytes TCP"
                type: str
            rev_ingress_bytes_tcp:
                description:
                - "Reverse Ingress Bytes TCP"
                type: str
            rev_egress_bytes_tcp:
                description:
                - "Reverse Egress Bytes TCP"
                type: str
            fwd_ingress_packets_udp:
                description:
                - "Forward Ingress Packets UDP"
                type: str
            fwd_egress_packets_udp:
                description:
                - "Forward Egress Packets UDP"
                type: str
            rev_ingress_packets_udp:
                description:
                - "Reverse Ingress Packets UDP"
                type: str
            rev_egress_packets_udp:
                description:
                - "Reverse Egress Packets UDP"
                type: str
            fwd_ingress_bytes_udp:
                description:
                - "Forward Ingress Bytes UDP"
                type: str
            fwd_egress_bytes_udp:
                description:
                - "Forward Egress Bytes UDP"
                type: str
            rev_ingress_bytes_udp:
                description:
                - "Reverse Ingress Bytes UDP"
                type: str
            rev_egress_bytes_udp:
                description:
                - "Reverse Egress Bytes UDP"
                type: str
            fwd_ingress_packets_icmp:
                description:
                - "Forward Ingress Packets ICMP"
                type: str
            fwd_egress_packets_icmp:
                description:
                - "Forward Egress Packets ICMP"
                type: str
            rev_ingress_packets_icmp:
                description:
                - "Reverse Ingress Packets ICMP"
                type: str
            rev_egress_packets_icmp:
                description:
                - "Reverse Egress Packets ICMP"
                type: str
            fwd_ingress_bytes_icmp:
                description:
                - "Forward Ingress Bytes ICMP"
                type: str
            fwd_egress_bytes_icmp:
                description:
                - "Forward Egress Bytes ICMP"
                type: str
            rev_ingress_bytes_icmp:
                description:
                - "Reverse Ingress Bytes ICMP"
                type: str
            rev_egress_bytes_icmp:
                description:
                - "Reverse Egress Bytes ICMP"
                type: str
            fwd_ingress_packets_others:
                description:
                - "Forward Ingress Packets OTHERS"
                type: str
            fwd_egress_packets_others:
                description:
                - "Forward Egress Packets OTHERS"
                type: str
            rev_ingress_packets_others:
                description:
                - "Reverse Ingress Packets OTHERS"
                type: str
            rev_egress_packets_others:
                description:
                - "Reverse Egress Packets OTHERS"
                type: str
            fwd_ingress_bytes_others:
                description:
                - "Forward Ingress Bytes OTHERS"
                type: str
            fwd_egress_bytes_others:
                description:
                - "Forward Egress Bytes OTHERS"
                type: str
            rev_ingress_bytes_others:
                description:
                - "Reverse Ingress Bytes OTHERS"
                type: str
            rev_egress_bytes_others:
                description:
                - "Reverse Egress Bytes OTHERS"
                type: str
            fwd_ingress_pkt_size_range1:
                description:
                - "Forward Ingress Packet size between 0 and 200"
                type: str
            fwd_ingress_pkt_size_range2:
                description:
                - "Forward Ingress Packet size between 201 and 800"
                type: str
            fwd_ingress_pkt_size_range3:
                description:
                - "Forward Ingress Packet size between 801 and 1550"
                type: str
            fwd_ingress_pkt_size_range4:
                description:
                - "Forward Ingress Packet size between 1551 and 9000"
                type: str
            fwd_egress_pkt_size_range1:
                description:
                - "Forward Egress Packet size between 0 and 200"
                type: str
            fwd_egress_pkt_size_range2:
                description:
                - "Forward Egress Packet size between 201 and 800"
                type: str
            fwd_egress_pkt_size_range3:
                description:
                - "Forward Egress Packet size between 801 and 1550"
                type: str
            fwd_egress_pkt_size_range4:
                description:
                - "Forward Egress Packet size between 1551 and 9000"
                type: str
            rev_ingress_pkt_size_range1:
                description:
                - "Reverse Ingress Packet size between 0 and 200"
                type: str
            rev_ingress_pkt_size_range2:
                description:
                - "Reverse Ingress Packet size between 201 and 800"
                type: str
            rev_ingress_pkt_size_range3:
                description:
                - "Reverse Ingress Packet size between 801 and 1550"
                type: str
            rev_ingress_pkt_size_range4:
                description:
                - "Reverse Ingress Packet size between 1551 and 9000"
                type: str
            rev_egress_pkt_size_range1:
                description:
                - "Reverse Egress Packet size between 0 and 200"
                type: str
            rev_egress_pkt_size_range2:
                description:
                - "Reverse Egress Packet size between 201 and 800"
                type: str
            rev_egress_pkt_size_range3:
                description:
                - "Reverse Egress Packet size between 801 and 1550"
                type: str
            rev_egress_pkt_size_range4:
                description:
                - "Reverse Egress Packet size between 1551 and 9000"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "alg_processing", "allow_non_syn_session_create", "disable_app_list", "disable_application_metrics", "disable_ip_fw_sessions", "disable_undetermined_rule_logs", "dsr_mode_support", "extended_matching", "inbound_refresh", "inbound_refresh_full_cone", "listen_on_port_timeout", "natip_ddos_protection", "permit_default_action",
    "respond_to_user_mac", "sampling_enable", "stats", "uuid",
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
        'disable_ip_fw_sessions': {
            'type': 'bool',
            },
        'disable_undetermined_rule_logs': {
            'type': 'bool',
            },
        'alg_processing': {
            'type': 'str',
            'choices': ['honor-rule-set', 'override-rule-set']
            },
        'extended_matching': {
            'type': 'str',
            'choices': ['disable']
            },
        'permit_default_action': {
            'type': 'str',
            'choices': ['forward', 'next-service-mode']
            },
        'natip_ddos_protection': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'listen_on_port_timeout': {
            'type': 'int',
            },
        'inbound_refresh_full_cone': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'inbound_refresh': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'respond_to_user_mac': {
            'type': 'bool',
            },
        'disable_app_list': {
            'type': 'list',
            'disable_application_protocol': {
                'type': 'str',
                },
            'disable_application_category': {
                'type':
                'str',
                'choices': [
                    'aaa', 'adult-content', 'advertising', 'application-enforcing-tls', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'certification-authority', 'chat', 'classified-ads', 'cloud-based-services', 'crowdfunding', 'cryptocurrency', 'database', 'disposable-email', 'ebook-reader',
                    'education', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'healthcare', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'map-service', 'mobile', 'multimedia-streaming', 'networking', 'news-portal', 'payment-service', 'peer-to-peer', 'remote-access', 'scada',
                    'social-networks', 'software-update', 'speedtest', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites', 'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration',
                    'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions', 'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government',
                    'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals', 'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers',
                    'web-ext-real-estate', 'web-ext-reference-and-research', 'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements',
                    'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service'
                    ]
                }
            },
        'disable_application_metrics': {
            'type': 'bool',
            },
        'allow_non_syn_session_create': {
            'type': 'bool',
            },
        'dsr_mode_support': {
            'type': 'str',
            'choices': ['ipv4', 'ipv6', 'all']
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
                    'all', 'tcp_fullcone_created', 'tcp_fullcone_freed', 'udp_fullcone_created', 'udp_fullcone_freed', 'fullcone_creation_failure', 'data_session_created', 'data_session_created_local', 'dyn_blist_sess_sp', 'data_session_freed', 'data_session_freed_local', 'dyn_blist_sess_created', 'dyn_blist_sess_freed', 'dyn_blist_pkt_drop',
                    'dyn_blist_pkt_rate_low', 'dyn_blist_pkt_rate_high', 'dyn_blist_version_mismatch', 'dyn_blist_no_active_policy', 'fullcone_in_del_q', 'fullcone_retry_lookup', 'fullcone_not_found', 'fullcone_overflow_eim', 'fullcone_overflow_eif', 'udp_fullcone_created_shadow', 'tcp_fullcone_created_shadow', 'udp_fullcone_freed_shadow',
                    'tcp_fullcone_freed_shadow', 'fullcone_created', 'fullcone_freed', 'fullcone_ext_too_many', 'fullcone_ext_mem_allocated', 'fullcone_ext_mem_alloc_failure', 'fullcone_ext_mem_alloc_init_faulure', 'fullcone_ext_mem_freed', 'fullcone_ext_added', 'ha_fullcone_failure', 'data_session_created_shadow',
                    'data_session_created_shadow_local', 'data_session_freed_shadow', 'data_session_freed_shadow_local', 'active_fullcone_session', 'limit-entry-failure', 'limit-entry-allocated', 'limit-entry-mem-freed', 'limit-entry-created', 'limit-entry-found', 'limit-entry-not-in-bucket', 'limit-entry-marked-deleted',
                    'undetermined-rule-counter', 'non_syn_pkt_fwd_allowed', 'invalid-lid-drop', 'src-session-limit-exceeded', 'uplink-pps-limit-exceeded', 'downlink-pps-limit-exceeded', 'total-pps-limit-exceeded', 'uplink-throughput-limit-exceeded', 'downlink-throughput-limit-exceeded', 'total-throughput-limit-exceeded', 'cps-limit-exceeded',
                    'limit-exceeded', 'limit-entry-per-cpu-mem-allocated', 'limit-entry-per-cpu-mem-allocation-failed', 'limit-entry-per-cpu-mem-freed', 'alg_default_port_disable', 'no_fwd_route', 'no_rev_route', 'no_fwd_l2_dst', 'no_rev_l2_dst', 'l2_dst_in_out_same', 'l2_vlan_changed', 'urpf_pkt_drop', 'fwd_ingress_packets_tcp',
                    'fwd_egress_packets_tcp', 'rev_ingress_packets_tcp', 'rev_egress_packets_tcp', 'fwd_ingress_bytes_tcp', 'fwd_egress_bytes_tcp', 'rev_ingress_bytes_tcp', 'rev_egress_bytes_tcp', 'fwd_ingress_packets_udp', 'fwd_egress_packets_udp', 'rev_ingress_packets_udp', 'rev_egress_packets_udp', 'fwd_ingress_bytes_udp',
                    'fwd_egress_bytes_udp', 'rev_ingress_bytes_udp', 'rev_egress_bytes_udp', 'fwd_ingress_packets_icmp', 'fwd_egress_packets_icmp', 'rev_ingress_packets_icmp', 'rev_egress_packets_icmp', 'fwd_ingress_bytes_icmp', 'fwd_egress_bytes_icmp', 'rev_ingress_bytes_icmp', 'rev_egress_bytes_icmp', 'fwd_ingress_packets_others',
                    'fwd_egress_packets_others', 'rev_ingress_packets_others', 'rev_egress_packets_others', 'fwd_ingress_bytes_others', 'fwd_egress_bytes_others', 'rev_ingress_bytes_others', 'rev_egress_bytes_others', 'fwd_ingress_pkt_size_range1', 'fwd_ingress_pkt_size_range2', 'fwd_ingress_pkt_size_range3', 'fwd_ingress_pkt_size_range4',
                    'fwd_egress_pkt_size_range1', 'fwd_egress_pkt_size_range2', 'fwd_egress_pkt_size_range3', 'fwd_egress_pkt_size_range4', 'rev_ingress_pkt_size_range1', 'rev_ingress_pkt_size_range2', 'rev_ingress_pkt_size_range3', 'rev_ingress_pkt_size_range4', 'rev_egress_pkt_size_range1', 'rev_egress_pkt_size_range2',
                    'rev_egress_pkt_size_range3', 'rev_egress_pkt_size_range4'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'tcp_fullcone_created': {
                'type': 'str',
                },
            'tcp_fullcone_freed': {
                'type': 'str',
                },
            'udp_fullcone_created': {
                'type': 'str',
                },
            'udp_fullcone_freed': {
                'type': 'str',
                },
            'fullcone_creation_failure': {
                'type': 'str',
                },
            'data_session_created': {
                'type': 'str',
                },
            'data_session_created_local': {
                'type': 'str',
                },
            'data_session_freed': {
                'type': 'str',
                },
            'data_session_freed_local': {
                'type': 'str',
                },
            'dyn_blist_sess_created': {
                'type': 'str',
                },
            'dyn_blist_sess_freed': {
                'type': 'str',
                },
            'dyn_blist_pkt_drop': {
                'type': 'str',
                },
            'active_fullcone_session': {
                'type': 'str',
                },
            'limit_entry_created': {
                'type': 'str',
                },
            'limit_entry_marked_deleted': {
                'type': 'str',
                },
            'undetermined_rule_counter': {
                'type': 'str',
                },
            'non_syn_pkt_fwd_allowed': {
                'type': 'str',
                },
            'fwd_ingress_packets_tcp': {
                'type': 'str',
                },
            'fwd_egress_packets_tcp': {
                'type': 'str',
                },
            'rev_ingress_packets_tcp': {
                'type': 'str',
                },
            'rev_egress_packets_tcp': {
                'type': 'str',
                },
            'fwd_ingress_bytes_tcp': {
                'type': 'str',
                },
            'fwd_egress_bytes_tcp': {
                'type': 'str',
                },
            'rev_ingress_bytes_tcp': {
                'type': 'str',
                },
            'rev_egress_bytes_tcp': {
                'type': 'str',
                },
            'fwd_ingress_packets_udp': {
                'type': 'str',
                },
            'fwd_egress_packets_udp': {
                'type': 'str',
                },
            'rev_ingress_packets_udp': {
                'type': 'str',
                },
            'rev_egress_packets_udp': {
                'type': 'str',
                },
            'fwd_ingress_bytes_udp': {
                'type': 'str',
                },
            'fwd_egress_bytes_udp': {
                'type': 'str',
                },
            'rev_ingress_bytes_udp': {
                'type': 'str',
                },
            'rev_egress_bytes_udp': {
                'type': 'str',
                },
            'fwd_ingress_packets_icmp': {
                'type': 'str',
                },
            'fwd_egress_packets_icmp': {
                'type': 'str',
                },
            'rev_ingress_packets_icmp': {
                'type': 'str',
                },
            'rev_egress_packets_icmp': {
                'type': 'str',
                },
            'fwd_ingress_bytes_icmp': {
                'type': 'str',
                },
            'fwd_egress_bytes_icmp': {
                'type': 'str',
                },
            'rev_ingress_bytes_icmp': {
                'type': 'str',
                },
            'rev_egress_bytes_icmp': {
                'type': 'str',
                },
            'fwd_ingress_packets_others': {
                'type': 'str',
                },
            'fwd_egress_packets_others': {
                'type': 'str',
                },
            'rev_ingress_packets_others': {
                'type': 'str',
                },
            'rev_egress_packets_others': {
                'type': 'str',
                },
            'fwd_ingress_bytes_others': {
                'type': 'str',
                },
            'fwd_egress_bytes_others': {
                'type': 'str',
                },
            'rev_ingress_bytes_others': {
                'type': 'str',
                },
            'rev_egress_bytes_others': {
                'type': 'str',
                },
            'fwd_ingress_pkt_size_range1': {
                'type': 'str',
                },
            'fwd_ingress_pkt_size_range2': {
                'type': 'str',
                },
            'fwd_ingress_pkt_size_range3': {
                'type': 'str',
                },
            'fwd_ingress_pkt_size_range4': {
                'type': 'str',
                },
            'fwd_egress_pkt_size_range1': {
                'type': 'str',
                },
            'fwd_egress_pkt_size_range2': {
                'type': 'str',
                },
            'fwd_egress_pkt_size_range3': {
                'type': 'str',
                },
            'fwd_egress_pkt_size_range4': {
                'type': 'str',
                },
            'rev_ingress_pkt_size_range1': {
                'type': 'str',
                },
            'rev_ingress_pkt_size_range2': {
                'type': 'str',
                },
            'rev_ingress_pkt_size_range3': {
                'type': 'str',
                },
            'rev_ingress_pkt_size_range4': {
                'type': 'str',
                },
            'rev_egress_pkt_size_range1': {
                'type': 'str',
                },
            'rev_egress_pkt_size_range2': {
                'type': 'str',
                },
            'rev_egress_pkt_size_range3': {
                'type': 'str',
                },
            'rev_egress_pkt_size_range4': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/global"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/global"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["global"].get(k) != v:
            change_results["changed"] = True
            config_changes["global"][k] = v

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
    payload = utils.build_json("global", module.params, AVAILABLE_PROPERTIES)
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
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["global"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["global-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["global"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
