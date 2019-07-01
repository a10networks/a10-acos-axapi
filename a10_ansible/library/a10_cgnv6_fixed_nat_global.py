#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_fixed_nat_global
description:
    - Fixed NAT Global configuration and Stats
short_description: Configures A10 cgnv6.fixed.nat.global
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
    create_port_mapping_file:
        description:
        - "Create Port Mapping File"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total-nat-in-use'= Total NAT Addresses in-use; 'total-tcp-allocated'= Total TCP Ports Allocated; 'total-tcp-freed'= Total TCP Ports Freed; 'total-udp-allocated'= Total UDP Ports Allocated; 'total-udp-freed'= Total UDP Ports Freed; 'total-icmp-allocated'= Total ICMP Ports Allocated; 'total-icmp-freed'= Total ICMP Ports Freed; 'nat44-data-session-created'= NAT44 Data Sessions Created; 'nat44-data-session-freed'= NAT44 Data Sessions Freed; 'nat64-data-session-created'= NAT64 Data Sessions Created; 'nat64-data-session-freed'= NAT64 Data Sessions Freed; 'dslite-data-session-created'= DS-Lite Data Sessions Created; 'dslite-data-session-freed'= DS-Lite Data Sessions Freed; 'nat-port-unavailable-tcp'= TCP NAT Port Unavailable; 'nat-port-unavailable-udp'= UDP NAT Port Unavailable; 'nat-port-unavailable-icmp'= ICMP NAT Port Unavailable; 'session-user-quota-exceeded'= Sessions User Quota Exceeded; 'nat44-tcp-fullcone-created'= NAT44 TCP Full-Cone Created; 'nat44-tcp-fullcone-freed'= NAT44 TCP Full-Cone Freed; 'nat44-udp-fullcone-created'= NAT44 UDP Full-Cone Created; 'nat44-udp-fullcone-freed'= NAT44 UDP Full-Cone Freed; 'nat44-udp-alg-fullcone-created'= NAT44 UDP ALG Full-Cone Created; 'nat44-udp-alg-fullcone-freed'= NAT44 UDP ALG Full-Cone Freed; 'nat64-tcp-fullcone-created'= NAT64 TCP Full-Cone Created; 'nat64-tcp-fullcone-freed'= NAT64 TCP Full-Cone Freed; 'nat64-udp-fullcone-created'= NAT64 UDP Full-Cone Created; 'nat64-udp-fullcone-freed'= NAT64 UDP Full-Cone Freed; 'nat64-udp-alg-fullcone-created'= NAT64 UDP ALG Full-Cone Created; 'nat64-udp-alg-fullcone-freed'= NAT64 UDP ALG Full-Cone Freed; 'dslite-tcp-fullcone-created'= DS-Lite TCP Full-Cone Created; 'dslite-tcp-fullcone-freed'= DS-Lite TCP Full-Cone Freed; 'dslite-udp-fullcone-created'= DS-Lite UDP Full-Cone Created; 'dslite-udp-fullcone-freed'= DS-Lite UDP Full-Cone Freed; 'dslite-udp-alg-fullcone-created'= DS-Lite UDP ALG Full-Cone Created; 'dslite-udp-alg-fullcone-freed'= DS-Lite UDP ALG Full-Cone Freed; 'fullcone-failure'= Full-Cone Session Creation Failed; 'nat44-eim-match'= NAT44 Endpoint-Independent-Mapping Matched; 'nat64-eim-match'= NAT64 Endpoint-Independent-Mapping Matched; 'dslite-eim-match'= DS-Lite Endpoint-Independent-Mapping Matched; 'nat44-eif-match'= NAT44 Endpoint-Independent-Filtering Matched; 'nat64-eif-match'= NAT64 Endpoint-Independent-Filtering Matched; 'dslite-eif-match'= DS-Lite Endpoint-Independent-Filtering Matched; 'nat44-inbound-filtered'= NAT44 Endpoint-Dependent Filtering Drop; 'nat64-inbound-filtered'= NAT64 Endpoint-Dependent Filtering Drop; 'dslite-inbound-filtered'= DS-Lite Endpoint-Dependent Filtering Drop; 'nat44-eif-limit-exceeded'= NAT44 Endpoint-Independent-Filtering Limit Exceeded; 'nat64-eif-limit-exceeded'= NAT64 Endpoint-Independent-Filtering Limit Exceeded; 'dslite-eif-limit-exceeded'= DS-Lite Endpoint-Independent-Filtering Limit Exceeded; 'nat44-hairpin'= NAT44 Hairpin Session Created; 'nat64-hairpin'= NAT64 Hairpin Session Created; 'dslite-hairpin'= DS-Lite Hairpin Session Created; 'standby-drop'= Fixed NAT LID Standby Drop; 'fixed-nat-fullcone-self-hairpinning-drop'= Self-Hairpinning Drop; '6rd-drop'= Fixed NAT IPv6 in IPv4 Packet Drop; 'dest-rlist-drop'= Fixed NAT Dest Rule List Drop; 'dest-rlist-pass-through'= Fixed NAT Dest Rule List Pass-Through; 'dest-rlist-snat-drop'= Fixed NAT Dest Rules List Source NAT Drop; 'cross-cpu-helper-created'= Cross CPU Helper Session Created; 'cross-cpu-helper-free-retry-lookup'= Cross CPU Helper Session Free Retry Lookup; 'cross-cpu-helper-free-not-found'= Cross CPU Helper Session Free not Found; 'cross-cpu-helper-free'= Cross CPU Helper Session Freed; 'cross-cpu-rcv'= Cross CPU Helper Packets Received; 'cross-cpu-bad-l3'= Cross CPU Unsupported L3; 'cross-cpu-bad-l4'= Cross CPU Unsupported L4; 'cross-cpu-no-session'= Cross CPU no Session Found; 'cross-cpu-helper-deleted'= Cross CPU Helper Session Deleted; 'cross-cpu-helper-fixed-nat-lid-standby'= Cross CPU Helper Fixed NAT LID Standby; 'cross-cpu-helper-cpu-mismatch'= Cross CPU Helper CPU Mismatch; 'cross-cpu-sent'= Cross CPU Helper Packets Sent; 'config-not-found'= Fixed NAT Config not Found; 'fullcone-in-del-q'= Full-Cone Session in Delete Queue; 'fullcone-overflow'= Fell-Cone Session Conn-Count Overflow; 'fullcone-inbound-idx-mismatch'= Full-Cone Session Fixed NAT LID mismatch; 'fullcone-retry-lookup'= Full-cone session retry look-up; 'fullcone-not-found'= Full-cone session not found; 'fullcone-overflow-eim'= Full-cone EIM Overflow; 'fullcone-overflow-eif'= Full-cone EIF Overflow; 'ha-config-mismatch'= HA Fixed NAT Config Mismatch; 'ha-user-quota-exceeded'= HA User Quota Exceeded; 'ha-fullcone-mismatch'= HA Full-Cone Mismatch; 'ha-dnat-mismatch'= HA Destination NAT Config Mismatch; 'ha-nat-port-unavailable'= HA NAT Port Unavailable; 'ha-fullcone-failure'= HA Full-Cone Failure; 'ha-endpoint-indep-map-match'= HA Endpoint-Independent-Mapping Match; 'udp-alg-eim-mismatch'= UDP ALG Endpoint-Independent Mapping Mismatch; 'udp-alg-no-nat-ip'= UDP ALG User-Quota Unknown NAT IP; 'udp-alg-alloc-failure'= UDP ALG Port Allocation Failure; 'mtu-exceeded'= Packet Exceeded MTU; 'frag'= Fragmented Packets; 'frag-icmp'= ICMP Packet Too Big Sent; 'periodic-log-msg-alloc'= Fixed NAT Periodic Log Msg Allocated; 'periodic-log-msg-free'= Fixed NAT Periodic Log Msg Freed; 'disable-log-msg-alloc'= Fixed NAT Disable Log Msg Allocated; 'disable-log-msg-free'= Fixed NAT Disable Log Msg Freed; 'sip-alg-reuse-contact-fullcone'= SIP ALG Reuse Contact Full-cone Session; 'sip-alg-contact-fullcone-mismatch'= SIP ALG Contact Full-cone Session Mismatch; 'sip-alg-create-contact-fullcone-failure'= SIP ALG Create Contact Full-cone Session Failure; 'sip-alg-single-rtp-fullcone'= SIP ALG Single RTP Full-cone Found; 'sip-alg-rtcp-fullcone-mismatch'= SIP ALG RTCP Full-cone NAT Port Mismatch; 'sip-alg-reuse-rtp-rtcp-fullcone'= SIP ALG Reuse RTP/RTCP Full-cone Session; 'sip-alg-single-rtcp-fullcone'= SIP ALG Single RTCP Full-cone Found; 'sip-alg-create-rtp-fullcone-failure'= SIP ALG Create RTP Full-cone Session Failure; 'sip-alg-create-rtcp-fullcone-failure'= SIP ALG Create RTCP Full-cone Session Failure; 'icmp-out-of-state-uqe-admin-filtered-sent'= Total User Quota Exceeded ICMP admin filtered sent; 'icmp-out-of-state-uqe-host-unreachable-sent'= Total User Quota Exceeded ICMP host unreachable sent; 'icmp-out-of-state-uqe-dropped'= Total User Queue Exceeded ICMP notification dropped; 'nat-esp-ip-conflicts'= Fixed NAT ESP IP Conflicts; 'total-tcp-allocated-shadow'= Total TCP Ports Allocated; 'total-tcp-freed-shadow'= Total TCP Ports Freed; 'total-udp-allocated-shadow'= Total UDP Ports Allocated; 'total-udp-freed-shadow'= Total UDP Ports Freed; 'total-icmp-allocated-shadow'= Total ICMP Ports Allocated; 'total-icmp-freed-shadow'= Total ICMP Ports Freed; 'nat44-data-session-created-shadow'= NAT44 Data Sessions Created; 'nat44-data-session-freed-shadow'= NAT44 Data Sessions Freed; 'nat64-data-session-created-shadow'= NAT64 Data Sessions Created; 'nat64-data-session-freed-shadow'= NAT64 Data Sessions Freed; 'dslite-data-session-created-shadow'= DS-Lite Data Sessions Created; 'dslite-data-session-freed-shadow'= DS-Lite Data Sessions Freed; 'nat44-tcp-fullcone-created-shadow'= NAT44 TCP Full-Cone Created; 'nat44-tcp-fullcone-freed-shadow'= NAT44 TCP Full-Cone Freed; 'nat44-udp-fullcone-created-shadow'= NAT44 UDP Full-Cone Created; 'nat44-udp-fullcone-freed-shadow'= NAT44 UDP Full-Cone Freed; 'nat44-udp-alg-fullcone-created-shadow'= NAT44 UDP ALG Full-Cone Created; "
            counters2:
                description:
                - "'nat44-udp-alg-fullcone-freed-shadow'= NAT44 UDP ALG Full-Cone Freed; 'nat64-tcp-fullcone-created-shadow'= NAT64 TCP Full-Cone Created; 'nat64-tcp-fullcone-freed-shadow'= NAT64 TCP Full-Cone Freed; 'nat64-udp-fullcone-created-shadow'= NAT64 UDP Full-Cone Created; 'nat64-udp-fullcone-freed-shadow'= NAT64 UDP Full-Cone Freed; 'nat64-udp-alg-fullcone-created-shadow'= NAT64 UDP ALG Full-Cone Created; 'nat64-udp-alg-fullcone-freed-shadow'= NAT64 UDP ALG Full-Cone Freed; 'dslite-tcp-fullcone-created-shadow'= DS-Lite TCP Full-Cone Created; 'dslite-tcp-fullcone-freed-shadow'= DS-Lite TCP Full-Cone Freed; 'dslite-udp-fullcone-created-shadow'= DS-Lite UDP Full-Cone Created; 'dslite-udp-fullcone-freed-shadow'= DS-Lite UDP Full-Cone Freed; 'dslite-udp-alg-fullcone-created-shadow'= DS-Lite UDP ALG Full-Cone Created; 'dslite-udp-alg-fullcone-freed-shadow'= DS-Lite UDP ALG Full-Cone Freed; 'h323-alg-reuse-fullcone'= H323 ALG Reuse Full-cone Session; 'h323-alg-fullcone-mismatch'= H323 ALG Full-cone Session Mismatch; 'h323-alg-create-fullcone-failure'= H323 ALG Create Full-cone Session Failure; 'h323-alg-single-rtp-fullcone'= H323 ALG Single RTP Full-cone Found; 'h323-alg-rtcp-fullcone-mismatch'= H323 ALG RTCP Full-cone NAT Port Mismatch; 'h323-alg-reuse-rtp-rtcp-fullcone'= H323 ALG Reuse RTP/RTCP Full-cone Session; 'h323-alg-single-rtcp-fullcone'= H323 ALG Single RTCP Full-cone Found; 'h323-alg-create-rtp-fullcone-failure'= H323 ALG Create RTP Full-cone Session Failure; 'h323-alg-create-rtcp-fullcone-failure'= H323 ALG Create RTCP Full-cone Session Failure; 'mgcp-alg-reuse-fullcone'= MGCP ALG Reuse Full-cone Session; 'mgcp-alg-fullcone-mismatch'= MGCP ALG Full-cone Session Mismatch; 'mgcp-alg-create-fullcone-failure'= MGCP ALG Create Full-cone Session Failure; 'mgcp-alg-single-rtp-fullcone'= MGCP ALG Single RTP Full-cone Found; 'mgcp-alg-rtcp-fullcone-mismatch'= MGCP ALG RTCP Full-cone NAT Port Mismatch; 'mgcp-alg-reuse-rtp-rtcp-fullcone'= MGCP ALG Reuse RTP/RTCP Full-cone Session; 'mgcp-alg-single-rtcp-fullcone'= MGCP ALG Single RTCP Full-cone Found; 'mgcp-alg-create-rtp-fullcone-failure'= MGCP ALG Create RTP Full-cone Session Failure; 'mgcp-alg-create-rtcp-fullcone-failure'= MGCP ALG Create RTCP Full-cone Session Failure; 'user-unusable-drop'= Fixed NAT User Unusable Drop; 'ipv4-user-unusable'= Fixed NAT IPv4 User Marked Unusable; 'ipv6-user-unusable'= Fixed NAT IPv6 User Marked Unusable; 'ipd-disabled'= Fixed NAT IPD disabled; "
    port_mapping_files_count:
        description:
        - "Number of old fixed_nat files to store"
        required: False
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["create_port_mapping_file","port_mapping_files_count","sampling_enable","uuid",]

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
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        create_port_mapping_file=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total-nat-in-use','total-tcp-allocated','total-tcp-freed','total-udp-allocated','total-udp-freed','total-icmp-allocated','total-icmp-freed','nat44-data-session-created','nat44-data-session-freed','nat64-data-session-created','nat64-data-session-freed','dslite-data-session-created','dslite-data-session-freed','nat-port-unavailable-tcp','nat-port-unavailable-udp','nat-port-unavailable-icmp','session-user-quota-exceeded','nat44-tcp-fullcone-created','nat44-tcp-fullcone-freed','nat44-udp-fullcone-created','nat44-udp-fullcone-freed','nat44-udp-alg-fullcone-created','nat44-udp-alg-fullcone-freed','nat64-tcp-fullcone-created','nat64-tcp-fullcone-freed','nat64-udp-fullcone-created','nat64-udp-fullcone-freed','nat64-udp-alg-fullcone-created','nat64-udp-alg-fullcone-freed','dslite-tcp-fullcone-created','dslite-tcp-fullcone-freed','dslite-udp-fullcone-created','dslite-udp-fullcone-freed','dslite-udp-alg-fullcone-created','dslite-udp-alg-fullcone-freed','fullcone-failure','nat44-eim-match','nat64-eim-match','dslite-eim-match','nat44-eif-match','nat64-eif-match','dslite-eif-match','nat44-inbound-filtered','nat64-inbound-filtered','dslite-inbound-filtered','nat44-eif-limit-exceeded','nat64-eif-limit-exceeded','dslite-eif-limit-exceeded','nat44-hairpin','nat64-hairpin','dslite-hairpin','standby-drop','fixed-nat-fullcone-self-hairpinning-drop','6rd-drop','dest-rlist-drop','dest-rlist-pass-through','dest-rlist-snat-drop','cross-cpu-helper-created','cross-cpu-helper-free-retry-lookup','cross-cpu-helper-free-not-found','cross-cpu-helper-free','cross-cpu-rcv','cross-cpu-bad-l3','cross-cpu-bad-l4','cross-cpu-no-session','cross-cpu-helper-deleted','cross-cpu-helper-fixed-nat-lid-standby','cross-cpu-helper-cpu-mismatch','cross-cpu-sent','config-not-found','fullcone-in-del-q','fullcone-overflow','fullcone-inbound-idx-mismatch','fullcone-retry-lookup','fullcone-not-found','fullcone-overflow-eim','fullcone-overflow-eif','ha-config-mismatch','ha-user-quota-exceeded','ha-fullcone-mismatch','ha-dnat-mismatch','ha-nat-port-unavailable','ha-fullcone-failure','ha-endpoint-indep-map-match','udp-alg-eim-mismatch','udp-alg-no-nat-ip','udp-alg-alloc-failure','mtu-exceeded','frag','frag-icmp','periodic-log-msg-alloc','periodic-log-msg-free','disable-log-msg-alloc','disable-log-msg-free','sip-alg-reuse-contact-fullcone','sip-alg-contact-fullcone-mismatch','sip-alg-create-contact-fullcone-failure','sip-alg-single-rtp-fullcone','sip-alg-rtcp-fullcone-mismatch','sip-alg-reuse-rtp-rtcp-fullcone','sip-alg-single-rtcp-fullcone','sip-alg-create-rtp-fullcone-failure','sip-alg-create-rtcp-fullcone-failure','icmp-out-of-state-uqe-admin-filtered-sent','icmp-out-of-state-uqe-host-unreachable-sent','icmp-out-of-state-uqe-dropped','nat-esp-ip-conflicts','total-tcp-allocated-shadow','total-tcp-freed-shadow','total-udp-allocated-shadow','total-udp-freed-shadow','total-icmp-allocated-shadow','total-icmp-freed-shadow','nat44-data-session-created-shadow','nat44-data-session-freed-shadow','nat64-data-session-created-shadow','nat64-data-session-freed-shadow','dslite-data-session-created-shadow','dslite-data-session-freed-shadow','nat44-tcp-fullcone-created-shadow','nat44-tcp-fullcone-freed-shadow','nat44-udp-fullcone-created-shadow','nat44-udp-fullcone-freed-shadow','nat44-udp-alg-fullcone-created-shadow']),counters2=dict(type='str',choices=['nat44-udp-alg-fullcone-freed-shadow','nat64-tcp-fullcone-created-shadow','nat64-tcp-fullcone-freed-shadow','nat64-udp-fullcone-created-shadow','nat64-udp-fullcone-freed-shadow','nat64-udp-alg-fullcone-created-shadow','nat64-udp-alg-fullcone-freed-shadow','dslite-tcp-fullcone-created-shadow','dslite-tcp-fullcone-freed-shadow','dslite-udp-fullcone-created-shadow','dslite-udp-fullcone-freed-shadow','dslite-udp-alg-fullcone-created-shadow','dslite-udp-alg-fullcone-freed-shadow','h323-alg-reuse-fullcone','h323-alg-fullcone-mismatch','h323-alg-create-fullcone-failure','h323-alg-single-rtp-fullcone','h323-alg-rtcp-fullcone-mismatch','h323-alg-reuse-rtp-rtcp-fullcone','h323-alg-single-rtcp-fullcone','h323-alg-create-rtp-fullcone-failure','h323-alg-create-rtcp-fullcone-failure','mgcp-alg-reuse-fullcone','mgcp-alg-fullcone-mismatch','mgcp-alg-create-fullcone-failure','mgcp-alg-single-rtp-fullcone','mgcp-alg-rtcp-fullcone-mismatch','mgcp-alg-reuse-rtp-rtcp-fullcone','mgcp-alg-single-rtcp-fullcone','mgcp-alg-create-rtp-fullcone-failure','mgcp-alg-create-rtcp-fullcone-failure','user-unusable-drop','ipv4-user-unusable','ipv6-user-unusable','ipd-disabled'])),
        port_mapping_files_count=dict(type='int',),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/global"

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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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
        return False

def create(module, result):
    payload = build_json("global", module)
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

def update(module, result, existing_config):
    payload = build_json("global", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
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
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()