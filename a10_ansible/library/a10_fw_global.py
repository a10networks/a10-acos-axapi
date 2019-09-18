#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_global
description:
    - Configure firewall parameters
short_description: Configures A10 fw.global
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
    alg_processing:
        description:
        - "'honor-rule-set'= Honors firewall rule-sets (Default); 'override-rule-set'= Override firewall rule-sets; "
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    listen_on_port_timeout:
        description:
        - "STUN timeout (default= 2 minutes)"
        required: False
    disable_ip_fw_sessions:
        description:
        - "disable create sessions for non TCP/UDP/ICMP"
        required: False
    disable_app_list:
        description:
        - "Field disable_app_list"
        required: False
        suboptions:
            disable_application_protocol:
                description:
                - "Disable specific application protocol"
            disable_application_category:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and Accounting) purposes.; 'adult-content'= Adult content.; 'advertising'= Advertising networks and applications.; 'analytics-and-statistics'= user-analytics and statistics.; 'anonymizers-and-proxies'= Traffic-anonymization protocol/application.; 'audio-chat'= Protocol/application used for Audio Chat.; 'basic'= Protocols required for basic classification, e.g., ARP, HTTP; 'blog'= Blogging platform.; 'cdn'= Protocol/application used for Content-Delivery Networks.; 'chat'= Protocol/application used for Text Chat.; 'classified-ads'= Protocol/application used for Classified ads.; 'cloud-based-services'= SaaS and/or PaaS cloud based services.; 'cryptocurrency'= Cryptocurrency.; 'database'= Database-specific protocols.; 'disposable-email'= Disposable email accounts.; 'email'= Native email protocol.; 'enterprise'= Protocol/application used in an enterprise network.; 'file-management'= Protocol/application designed specifically for file management and exchange, e.g., Dropbox, SMB; 'file-transfer'= Protocol that offers file transferring as a functionality as a secondary feature. e.g., Skype, Whatsapp; 'forum'= Online forum.; 'gaming'= Protocol/application used by games.; 'instant-messaging-and-multimedia-conferencing'= Protocol/application used for Instant messaging or multiconferencing.; 'internet-of-things'= Internet Of Things protocol/application.; 'mobile'= Mobile-specific protocol/application.; 'multimedia-streaming'= Protocol/application used for multimedia streaming.; 'networking'= Protocol used for (inter) networking purpose.; 'news-portal'= Protocol/application used for News Portals.; 'peer-to-peer'= Protocol/application used for Peer-to-peer purposes.; 'remote-access'= Protocol/application used for remote access.; 'scada'= SCADA (Supervisory control and data acquisition) protocols, all generations.; 'social-networks'= Social networking application.; 'software-update'= Auto-update protocol.; 'standards-based'= Protocol issued from standardized bodies such as IETF, ITU, IEEE, ETSI, OIF.; 'transportation'= Transportation.; 'video-chat'= Protocol/application used for Video Chat.; 'voip'= Application used for Voice over IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'= Protocol/application used for E-commerce websites.; 'web-search-engines'= Protocol/application used for Web search portals.; 'web-websites'= Protocol/application used for Company Websites.; 'webmails'= Web email application.; 'web-ext-adult'= Web Extension Adult; 'web-ext-auctions'= Web Extension Auctions; 'web-ext-blogs'= Web Extension Blogs; 'web-ext-business-and-economy'= Web Extension Business and Economy; 'web-ext-cdns'= Web Extension CDNs; 'web-ext-collaboration'= Web Extension Collaboration; 'web-ext-computer-and-internet-info'= Web Extension Computer and Internet Info; 'web-ext-computer-and-internet-security'= Web Extension Computer and Internet Security; 'web-ext-dating'= Web Extension Dating; 'web-ext-educational-institutions'= Web Extension Educational Institutions; 'web-ext-entertainment-and-arts'= Web Extension Entertainment and Arts; 'web-ext-fashion-and-beauty'= Web Extension Fashion and Beauty; 'web-ext-file-share'= Web Extension File Share; 'web-ext-financial-services'= Web Extension Financial Services; 'web-ext-gambling'= Web Extension Gambling; 'web-ext-games'= Web Extension Games; 'web-ext-government'= Web Extension Government; 'web-ext-health-and-medicine'= Web Extension Health and Medicine; 'web-ext-individual-stock-advice-and-tools'= Web Extension Individual Stock Advice and Tools; 'web-ext-internet-portals'= Web Extension Internet Portals; 'web-ext-job-search'= Web Extension Job Search; 'web-ext-local-information'= Web Extension Local Information; 'web-ext-malware'= Web Extension Malware; 'web-ext-motor-vehicles'= Web Extension Motor Vehicles; 'web-ext-music'= Web Extension Music; 'web-ext-news'= Web Extension News; 'web-ext-p2p'= Web Extension P2P; 'web-ext-parked-sites'= Web Extension Parked Sites; 'web-ext-proxy-avoid-and-anonymizers'= Web Extension Proxy Avoid and Anonymizers; 'web-ext-real-estate'= Web Extension Real Estate; 'web-ext-reference-and-research'= Web Extension Reference and Research; 'web-ext-search-engines'= Web Extension Search Engines; 'web-ext-shopping'= Web Extension Shopping; 'web-ext-social-network'= Web Extension Social Network; 'web-ext-society'= Web Extension Society; 'web-ext-software'= Web Extension Software; 'web-ext-sports'= Web Extension Sports; 'web-ext-streaming-media'= Web Extension Streaming Media; 'web-ext-training-and-tools'= Web Extension Training and Tools; 'web-ext-translation'= Web Extension Translation; 'web-ext-travel'= Web Extension Travel; 'web-ext-web-advertisements'= Web Extension Web Advertisements; 'web-ext-web-based-email'= Web Extension Web based Email; 'web-ext-web-hosting'= Web Extension Web Hosting; 'web-ext-web-service'= Web Extension Web Service; "
    extended_matching:
        description:
        - "'disable'= Disable extended matching; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'tcp_fullcone_created'= TCP Full-cone Created; 'tcp_fullcone_freed'= TCP Full-cone Freed; 'udp_fullcone_created'= UDP Full-cone Created; 'udp_fullcone_freed'= UDP Full-cone Freed; 'fullcone_creation_failure'= Full-Cone Creation Failure; 'data_session_created'= Data Session Created; 'data_session_freed'= Data Session Freed; 'fullcone_in_del_q'= Full-cone session found in delete queue; 'fullcone_retry_lookup'= Full-cone session retry look-up; 'fullcone_not_found'= Full-cone session not found; 'fullcone_overflow_eim'= Full-cone Session EIM Overflow; 'fullcone_overflow_eif'= Full-cone Session EIF Overflow; 'udp_fullcone_created_shadow'= Total UDP Full-cone sessions created; 'tcp_fullcone_created_shadow'= Total TCP Full-cone sessions created; 'udp_fullcone_freed_shadow'= Total UDP Full-cone sessions freed; 'tcp_fullcone_freed_shadow'= Total TCP Full-cone sessions freed; 'fullcone_created'= Total Full-cone sessions created; 'fullcone_freed'= Total Full-cone sessions freed; 'fullcone_ext_too_many'= Fullcone Extension Too Many; 'fullcone_ext_mem_allocated'= Fullcone Extension Memory Allocated; 'fullcone_ext_mem_alloc_failure'= Fullcone Extension Memory Allocate Failure; 'fullcone_ext_mem_alloc_init_faulure'= Fullcone Extension Initialization Failure; 'fullcone_ext_mem_freed'= Fullcone Extension Memory Freed; 'fullcone_ext_added'= Fullcone Extension Added; 'ha_fullcone_failure'= HA Full-cone Session Failure; 'data_session_created_shadow'= Total Data Sessions Created; 'data_session_freed_shadow'= Total Data Sessions Freed; 'active_fullcone_session'= Total Active Full-cone sessions; 'limit-entry-failure'= Limit Entry Creation Failure; 'limit-entry-allocated'= Limit Entry Allocated; 'limit-entry-mem-freed'= Limit Entry Freed; 'limit-entry-created'= Limit Entry Created; 'limit-entry-not-in-bucket'= Limit Entry Not in Bucket; 'limit-entry-marked-deleted'= Limit Entry Marked Deleted; 'invalid-lid-drop'= Invalid Lid Drop; 'src-session-limit-exceeded'= Source Prefix Session Limit Exceeded; 'limit-exceeded'= Per Second Limit Exceeded; 'limit-entry-per-cpu-mem-allocated'= Limit Entry Memory Allocated; 'limit-entry-per-cpu-mem-allocation-failed'= Limit Entry Memory Allocation Failed; 'limit-entry-per-cpu-mem-freed'= Limit Entry Memory Freed; 'alg_default_port_disable'= Total ALG packets matching Default Port Disable; 'no_fwd_route'= No Forward Route; 'no_rev_route'= No Reverse Route; 'no_fwd_l2_dst'= No Forward Mac Entry; 'no_rev_l2_dst'= No Reverse Mac Entry; 'urpf_pkt_drop'= URPF check packet drop; 'fwd_ingress_packets_tcp'= Forward Ingress Packets TCP; 'fwd_egress_packets_tcp'= Forward Egress Packets TCP; 'rev_ingress_packets_tcp'= Reverse Ingress Packets TCP; 'rev_egress_packets_tcp'= Reverse Egress Packets TCP; 'fwd_ingress_bytes_tcp'= Forward Ingress Bytes TCP; 'fwd_egress_bytes_tcp'= Forward Egress Bytes TCP; 'rev_ingress_bytes_tcp'= Reverse Ingress Bytes TCP; 'rev_egress_bytes_tcp'= Reverse Egress Bytes TCP; 'fwd_ingress_packets_udp'= Forward Ingress Packets UDP; 'fwd_egress_packets_udp'= Forward Egress Packets UDP; 'rev_ingress_packets_udp'= Reverse Ingress Packets UDP; 'rev_egress_packets_udp'= Reverse Egress Packets UDP; 'fwd_ingress_bytes_udp'= Forward Ingress Bytes UDP; 'fwd_egress_bytes_udp'= Forward Egress Bytes UDP; 'rev_ingress_bytes_udp'= Reverse Ingress Bytes UDP; 'rev_egress_bytes_udp'= Reverse Egress Bytes UDP; 'fwd_ingress_packets_icmp'= Forward Ingress Packets ICMP; 'fwd_egress_packets_icmp'= Forward Egress Packets ICMP; 'rev_ingress_packets_icmp'= Reverse Ingress Packets ICMP; 'rev_egress_packets_icmp'= Reverse Egress Packets ICMP; 'fwd_ingress_bytes_icmp'= Forward Ingress Bytes ICMP; 'fwd_egress_bytes_icmp'= Forward Egress Bytes ICMP; 'rev_ingress_bytes_icmp'= Reverse Ingress Bytes ICMP; 'rev_egress_bytes_icmp'= Reverse Egress Bytes ICMP; 'fwd_ingress_packets_others'= Forward Ingress Packets OTHERS; 'fwd_egress_packets_others'= Forward Egress Packets OTHERS; 'rev_ingress_packets_others'= Reverse Ingress Packets OTHERS; 'rev_egress_packets_others'= Reverse Egress Packets OTHERS; 'fwd_ingress_bytes_others'= Forward Ingress Bytes OTHERS; 'fwd_egress_bytes_others'= Forward Egress Bytes OTHERS; 'rev_ingress_bytes_others'= Reverse Ingress Bytes OTHERS; 'rev_egress_bytes_others'= Reverse Egress Bytes OTHERS; 'fwd_ingress_pkt_size_range1'= Forward Ingress Packet size between 0 and 200; 'fwd_ingress_pkt_size_range2'= Forward Ingress Packet size between 201 and 800; 'fwd_ingress_pkt_size_range3'= Forward Ingress Packet size between 801 and 1550; 'fwd_ingress_pkt_size_range4'= Forward Ingress Packet size between 1551 and 9000; 'fwd_egress_pkt_size_range1'= Forward Egress Packet size between 0 and 200; 'fwd_egress_pkt_size_range2'= Forward Egress Packet size between 201 and 800; 'fwd_egress_pkt_size_range3'= Forward Egress Packet size between 801 and 1550; 'fwd_egress_pkt_size_range4'= Forward Egress Packet size between 1551 and 9000; 'rev_ingress_pkt_size_range1'= Reverse Ingress Packet size between 0 and 200; 'rev_ingress_pkt_size_range2'= Reverse Ingress Packet size between 201 and 800; 'rev_ingress_pkt_size_range3'= Reverse Ingress Packet size between 801 and 1550; 'rev_ingress_pkt_size_range4'= Reverse Ingress Packet size between 1551 and 9000; 'rev_egress_pkt_size_range1'= Reverse Egress Packet size between 0 and 200; 'rev_egress_pkt_size_range2'= Reverse Egress Packet size between 201 and 800; 'rev_egress_pkt_size_range3'= Reverse Egress Packet size between 801 and 1550; 'rev_egress_pkt_size_range4'= Reverse Egress Packet size between 1551 and 9000; "
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table (default= off)"
        required: False
    permit_default_action:
        description:
        - "'forward'= Forward; 'next-service-mode'= Service to be applied chosen based on configuration; "
        required: False
    natip_ddos_protection:
        description:
        - "'enable'= Enable; 'disable'= Disable; "
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["alg_processing","disable_app_list","disable_ip_fw_sessions","extended_matching","listen_on_port_timeout","natip_ddos_protection","permit_default_action","respond_to_user_mac","sampling_enable","uuid",]

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
        alg_processing=dict(type='str',choices=['honor-rule-set','override-rule-set']),
        uuid=dict(type='str',),
        listen_on_port_timeout=dict(type='int',),
        disable_ip_fw_sessions=dict(type='bool',),
        disable_app_list=dict(type='list',disable_application_protocol=dict(type='str',),disable_application_category=dict(type='str',choices=['aaa','adult-content','advertising','analytics-and-statistics','anonymizers-and-proxies','audio-chat','basic','blog','cdn','chat','classified-ads','cloud-based-services','cryptocurrency','database','disposable-email','email','enterprise','file-management','file-transfer','forum','gaming','instant-messaging-and-multimedia-conferencing','internet-of-things','mobile','multimedia-streaming','networking','news-portal','peer-to-peer','remote-access','scada','social-networks','software-update','standards-based','transportation','video-chat','voip','vpn-tunnels','web','web-e-commerce','web-search-engines','web-websites','webmails','web-ext-adult','web-ext-auctions','web-ext-blogs','web-ext-business-and-economy','web-ext-cdns','web-ext-collaboration','web-ext-computer-and-internet-info','web-ext-computer-and-internet-security','web-ext-dating','web-ext-educational-institutions','web-ext-entertainment-and-arts','web-ext-fashion-and-beauty','web-ext-file-share','web-ext-financial-services','web-ext-gambling','web-ext-games','web-ext-government','web-ext-health-and-medicine','web-ext-individual-stock-advice-and-tools','web-ext-internet-portals','web-ext-job-search','web-ext-local-information','web-ext-malware','web-ext-motor-vehicles','web-ext-music','web-ext-news','web-ext-p2p','web-ext-parked-sites','web-ext-proxy-avoid-and-anonymizers','web-ext-real-estate','web-ext-reference-and-research','web-ext-search-engines','web-ext-shopping','web-ext-social-network','web-ext-society','web-ext-software','web-ext-sports','web-ext-streaming-media','web-ext-training-and-tools','web-ext-translation','web-ext-travel','web-ext-web-advertisements','web-ext-web-based-email','web-ext-web-hosting','web-ext-web-service'])),
        extended_matching=dict(type='str',choices=['disable']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','tcp_fullcone_created','tcp_fullcone_freed','udp_fullcone_created','udp_fullcone_freed','fullcone_creation_failure','data_session_created','data_session_freed','fullcone_in_del_q','fullcone_retry_lookup','fullcone_not_found','fullcone_overflow_eim','fullcone_overflow_eif','udp_fullcone_created_shadow','tcp_fullcone_created_shadow','udp_fullcone_freed_shadow','tcp_fullcone_freed_shadow','fullcone_created','fullcone_freed','fullcone_ext_too_many','fullcone_ext_mem_allocated','fullcone_ext_mem_alloc_failure','fullcone_ext_mem_alloc_init_faulure','fullcone_ext_mem_freed','fullcone_ext_added','ha_fullcone_failure','data_session_created_shadow','data_session_freed_shadow','active_fullcone_session','limit-entry-failure','limit-entry-allocated','limit-entry-mem-freed','limit-entry-created','limit-entry-not-in-bucket','limit-entry-marked-deleted','invalid-lid-drop','src-session-limit-exceeded','limit-exceeded','limit-entry-per-cpu-mem-allocated','limit-entry-per-cpu-mem-allocation-failed','limit-entry-per-cpu-mem-freed','alg_default_port_disable','no_fwd_route','no_rev_route','no_fwd_l2_dst','no_rev_l2_dst','urpf_pkt_drop','fwd_ingress_packets_tcp','fwd_egress_packets_tcp','rev_ingress_packets_tcp','rev_egress_packets_tcp','fwd_ingress_bytes_tcp','fwd_egress_bytes_tcp','rev_ingress_bytes_tcp','rev_egress_bytes_tcp','fwd_ingress_packets_udp','fwd_egress_packets_udp','rev_ingress_packets_udp','rev_egress_packets_udp','fwd_ingress_bytes_udp','fwd_egress_bytes_udp','rev_ingress_bytes_udp','rev_egress_bytes_udp','fwd_ingress_packets_icmp','fwd_egress_packets_icmp','rev_ingress_packets_icmp','rev_egress_packets_icmp','fwd_ingress_bytes_icmp','fwd_egress_bytes_icmp','rev_ingress_bytes_icmp','rev_egress_bytes_icmp','fwd_ingress_packets_others','fwd_egress_packets_others','rev_ingress_packets_others','rev_egress_packets_others','fwd_ingress_bytes_others','fwd_egress_bytes_others','rev_ingress_bytes_others','rev_egress_bytes_others','fwd_ingress_pkt_size_range1','fwd_ingress_pkt_size_range2','fwd_ingress_pkt_size_range3','fwd_ingress_pkt_size_range4','fwd_egress_pkt_size_range1','fwd_egress_pkt_size_range2','fwd_egress_pkt_size_range3','fwd_egress_pkt_size_range4','rev_ingress_pkt_size_range1','rev_ingress_pkt_size_range2','rev_ingress_pkt_size_range3','rev_ingress_pkt_size_range4','rev_egress_pkt_size_range1','rev_egress_pkt_size_range2','rev_egress_pkt_size_range3','rev_egress_pkt_size_range4'])),
        respond_to_user_mac=dict(type='bool',),
        permit_default_action=dict(type='str',choices=['forward','next-service-mode']),
        natip_ddos_protection=dict(type='str',choices=['enable','disable'])
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/global"

    f_dict = {}

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

def get_oper(module)
    return module.client.get(oper_url(module))

def get_stats(module)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["global"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["global"][k] = v
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
    payload = build_json("global", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("global", module)
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
    if partition:
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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