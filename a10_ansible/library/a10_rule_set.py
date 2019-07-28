#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_rule_set
description:
    - Configure Security policy Rule Set
short_description: Configures A10 rule-set
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
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
        required: False
    name:
        description:
        - "Rule set name"
        required: True
    app:
        description:
        - "Field app"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    track_app_rule_list:
        description:
        - "Field track_app_rule_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    user_tag:
        description:
        - "Customized tag"
        required: False
    application:
        description:
        - "Field application"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'unmatched-drops'= Unmatched drops counter; 'permit'= Permitted counter; 'deny'= Denied counter; 'reset'= Reset counter; "
    tag:
        description:
        - "Field tag"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    rule_list:
        description:
        - "Field rule_list"
        required: False
        suboptions:
            cgnv6_fixed_nat_log:
                description:
                - "Enable logging"
            dst_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
            sampling_enable:
                description:
                - "Field sampling_enable"
            forward_listen_on_port:
                description:
                - "Listen on port"
            listen_on_port_lid:
                description:
                - "Apply a Template LID"
            app_list:
                description:
                - "Field app_list"
            src_threat_list:
                description:
                - "Bind threat-list for source IP based filtering"
            cgnv6_policy:
                description:
                - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT; "
            src_geoloc_name:
                description:
                - "Single geolocation name"
            cgnv6_log:
                description:
                - "Enable logging"
            forward_log:
                description:
                - "Enable logging"
            lid:
                description:
                - "Apply a Template LID"
            listen_on_port:
                description:
                - "Listen on port"
            move_rule:
                description:
                - "Field move_rule"
            log:
                description:
                - "Enable logging"
            dst_geoloc_name:
                description:
                - "Single geolocation name"
            idle_timeout:
                description:
                - "TCP/UDP idle-timeout"
            listen_on_port_lidlog:
                description:
                - "Enable logging"
            src_zone_any:
                description:
                - "'any'= any; "
            ip_version:
                description:
                - "'v4'= IPv4 rule; 'v6'= IPv6 rule; "
            application_any:
                description:
                - "'any'= any; "
            src_zone:
                description:
                - "Zone name"
            src_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
            policy:
                description:
                - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet; "
            source_list:
                description:
                - "Field source_list"
            dst_zone_any:
                description:
                - "'any'= any; "
            status:
                description:
                - "'enable'= Enable rule; 'disable'= Disable rule; "
            lidlog:
                description:
                - "Enable logging"
            dst_ipv4_any:
                description:
                - "'any'= Any IPv4 address; "
            cgnv6_lsn_lid:
                description:
                - "LSN LID"
            src_geoloc_list:
                description:
                - "Geolocation name list"
            src_ipv4_any:
                description:
                - "'any'= Any IPv4 address; "
            fwlog:
                description:
                - "Enable logging"
            dst_zone:
                description:
                - "Zone name"
            dst_class_list:
                description:
                - "Match destination IP against class-list"
            uuid:
                description:
                - "uuid of the object"
            dst_threat_list:
                description:
                - "Bind threat-list for destination IP based filtering"
            remark:
                description:
                - "Rule entry comment (Notes for this rule)"
            src_class_list:
                description:
                - "Match source IP against class-list"
            name:
                description:
                - "Rule name"
            src_ipv6_any:
                description:
                - "'any'= Any IPv6 address; "
            reset_lid:
                description:
                - "Apply a Template LID"
            dst_geoloc_list:
                description:
                - "Geolocation name list"
            track_application:
                description:
                - "Enable application statistic"
            user_tag:
                description:
                - "Customized tag"
            cgnv6_lsn_log:
                description:
                - "Enable logging"
            dst_ipv6_any:
                description:
                - "'any'= Any IPv6 address; "
            service_any:
                description:
                - "'any'= any; "
            service_list:
                description:
                - "Field service_list"
            dst_domain_list:
                description:
                - "Match destination IP against domain-list"
            dest_list:
                description:
                - "Field dest_list"
            action:
                description:
                - "'permit'= permit; 'deny'= deny; 'reset'= reset; "
            fw_log:
                description:
                - "Enable logging"
    session_statistic:
        description:
        - "'enable'= Enable session based statistic (Default); 'disable'= Disable session based statistic; "
        required: False
    rules_by_zone:
        description:
        - "Field rules_by_zone"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["app","application","name","remark","rule_list","rules_by_zone","sampling_enable","session_statistic","tag","track_app_rule_list","user_tag","uuid",]

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
        remark=dict(type='str',),
        name=dict(type='str',required=True,),
        app=dict(type='dict',uuid=dict(type='str',)),
        track_app_rule_list=dict(type='dict',uuid=dict(type='str',)),
        user_tag=dict(type='str',),
        application=dict(type='dict',uuid=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','unmatched-drops','permit','deny','reset'])),
        tag=dict(type='dict',uuid=dict(type='str',)),
        rule_list=dict(type='list',cgnv6_fixed_nat_log=dict(type='bool',),dst_geoloc_list_shared=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hit-count','permit-bytes','deny-bytes','reset-bytes','permit-packets','deny-packets','reset-packets','active-session-tcp','active-session-udp','active-session-icmp','active-session-other','session-tcp','session-udp','session-icmp','session-other','active-session-sctp','session-sctp','hitcount-timestamp'])),forward_listen_on_port=dict(type='bool',),listen_on_port_lid=dict(type='int',),app_list=dict(type='list',obj_grp_application=dict(type='str',),protocol=dict(type='str',),protocol_tag=dict(type='str',choices=['aaa','adult-content','advertising','analytics-and-statistics','anonymizers-and-proxies','audio-chat','basic','blog','cdn','chat','classified-ads','cloud-based-services','database','email','enterprise','file-management','file-transfer','forum','gaming','instant-messaging-and-multimedia-conferencing','internet-of-things','mobile','multimedia-streaming','networking','news-portal','peer-to-peer','remote-access','scada','social-networks','software-update','standards-based','video-chat','voip','vpn-tunnels','web','web-e-commerce','web-search-engines','web-websites','webmails','web-ext-adult','web-ext-auctions','web-ext-blogs','web-ext-business-and-economy','web-ext-cdns','web-ext-collaboration','web-ext-computer-and-internet-info','web-ext-computer-and-internet-security','web-ext-dating','web-ext-educational-institutions','web-ext-entertainment-and-arts','web-ext-fashion-and-beauty','web-ext-file-share','web-ext-financial-services','web-ext-gambling','web-ext-games','web-ext-government','web-ext-health-and-medicine','web-ext-individual-stock-advice-and-tools','web-ext-internet-portals','web-ext-job-search','web-ext-local-information','web-ext-malware','web-ext-motor-vehicles','web-ext-music','web-ext-news','web-ext-p2p','web-ext-parked-sites','web-ext-proxy-avoid-and-anonymizers','web-ext-real-estate','web-ext-reference-and-research','web-ext-search-engines','web-ext-shopping','web-ext-social-network','web-ext-society','web-ext-software','web-ext-sports','web-ext-streaming-media','web-ext-training-and-tools','web-ext-translation','web-ext-travel','web-ext-web-advertisements','web-ext-web-based-email','web-ext-web-hosting','web-ext-web-service'])),src_threat_list=dict(type='str',),cgnv6_policy=dict(type='str',choices=['lsn-lid','fixed-nat']),src_geoloc_name=dict(type='str',),cgnv6_log=dict(type='bool',),forward_log=dict(type='bool',),lid=dict(type='int',),listen_on_port=dict(type='bool',),move_rule=dict(type='dict',location=dict(type='str',choices=['top','before','after','bottom']),target_rule=dict(type='str',)),log=dict(type='bool',),dst_geoloc_name=dict(type='str',),idle_timeout=dict(type='int',),listen_on_port_lidlog=dict(type='bool',),src_zone_any=dict(type='str',choices=['any']),ip_version=dict(type='str',choices=['v4','v6']),application_any=dict(type='str',choices=['any']),src_zone=dict(type='str',),src_geoloc_list_shared=dict(type='bool',),policy=dict(type='str',choices=['cgnv6','forward']),source_list=dict(type='list',src_ipv6_subnet=dict(type='str',),src_obj_network=dict(type='str',),src_slb_server=dict(type='str',),src_obj_grp_network=dict(type='str',),src_ip_subnet=dict(type='str',)),dst_zone_any=dict(type='str',choices=['any']),status=dict(type='str',choices=['enable','disable']),lidlog=dict(type='bool',),dst_ipv4_any=dict(type='str',choices=['any']),cgnv6_lsn_lid=dict(type='int',),src_geoloc_list=dict(type='str',),src_ipv4_any=dict(type='str',choices=['any']),fwlog=dict(type='bool',),dst_zone=dict(type='str',),dst_class_list=dict(type='str',),uuid=dict(type='str',),dst_threat_list=dict(type='str',),remark=dict(type='str',),src_class_list=dict(type='str',),name=dict(type='str',required=True,),src_ipv6_any=dict(type='str',choices=['any']),reset_lid=dict(type='int',),dst_geoloc_list=dict(type='str',),track_application=dict(type='bool',),user_tag=dict(type='str',),cgnv6_lsn_log=dict(type='bool',),dst_ipv6_any=dict(type='str',choices=['any']),service_any=dict(type='str',choices=['any']),service_list=dict(type='list',gtp_template=dict(type='str',),icmp_type=dict(type='int',),range_dst_port=dict(type='int',),icmpv6_code=dict(type='int',),gt_src_port=dict(type='int',),lt_src_port=dict(type='int',),proto_id=dict(type='int',),lt_dst_port=dict(type='int',),alg=dict(type='str',choices=['FTP','TFTP','SIP','DNS','PPTP','RTSP']),obj_grp_service=dict(type='str',),icmpv6_type=dict(type='int',),icmp_code=dict(type='int',),range_src_port=dict(type='int',),eq_dst_port=dict(type='int',),sctp_template=dict(type='str',),icmp=dict(type='bool',),protocols=dict(type='str',choices=['tcp','udp','sctp']),gt_dst_port=dict(type='int',),port_num_end_src=dict(type='int',),special_v6_type=dict(type='str',choices=['any-type','dest-unreachable','echo-reply','echo-request','packet-too-big','param-prob','time-exceeded']),eq_src_port=dict(type='int',),special_v6_code=dict(type='str',choices=['any-code','addr-unreachable','admin-prohibited','no-route','not-neighbour','port-unreachable']),icmpv6=dict(type='bool',),port_num_end_dst=dict(type='int',),special_code=dict(type='str',choices=['any-code','frag-required','host-unreachable','network-unreachable','port-unreachable','proto-unreachable','route-failed']),special_type=dict(type='str',choices=['any-type','echo-reply','echo-request','info-reply','info-request','mask-reply','mask-request','parameter-problem','redirect','source-quench','time-exceeded','timestamp','timestamp-reply','dest-unreachable'])),dst_domain_list=dict(type='str',),dest_list=dict(type='list',dst_obj_network=dict(type='str',),dst_obj_grp_network=dict(type='str',),dst_slb_vserver=dict(type='str',),dst_ip_subnet=dict(type='str',),dst_ipv6_subnet=dict(type='str',),dst_slb_server=dict(type='str',)),action=dict(type='str',choices=['permit','deny','reset']),fw_log=dict(type='bool',)),
        session_statistic=dict(type='str',choices=['enable','disable']),
        rules_by_zone=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dummy'])),uuid=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    payload = build_json("rule-set", module)
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
    payload = build_json("rule-set", module)
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
    payload = build_json("rule-set", module)
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