#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            total_active_icmp:
                description:
                - "Field total_active_icmp"
            policy_deny:
                description:
                - "Field policy_deny"
            total_deny_bytes:
                description:
                - "Field total_deny_bytes"
            total_hit:
                description:
                - "Field total_hit"
            policy_status:
                description:
                - "Field policy_status"
            total_packets:
                description:
                - "Field total_packets"
            total_deny_packets:
                description:
                - "Field total_deny_packets"
            total_permit_bytes:
                description:
                - "Field total_permit_bytes"
            rule_list:
                description:
                - "Field rule_list"
            total_active_tcp:
                description:
                - "Field total_active_tcp"
            application:
                description:
                - "Field application"
            total_active_others:
                description:
                - "Field total_active_others"
            total_permit_packets:
                description:
                - "Field total_permit_packets"
            rule_stats:
                description:
                - "Field rule_stats"
            total_active_udp:
                description:
                - "Field total_active_udp"
            policy_rule_count:
                description:
                - "Field policy_rule_count"
            policy_reset:
                description:
                - "Field policy_reset"
            total_reset_packets:
                description:
                - "Field total_reset_packets"
            total_reset_bytes:
                description:
                - "Field total_reset_bytes"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
            name:
                description:
                - "Rule set name"
            total_bytes:
                description:
                - "Field total_bytes"
            topn_rules:
                description:
                - "Field topn_rules"
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
            policy_unmatched_drop:
                description:
                - "Field policy_unmatched_drop"
            show_total_stats:
                description:
                - "Field show_total_stats"
            policy_permit:
                description:
                - "Field policy_permit"
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            reset:
                description:
                - "Reset counter"
            deny:
                description:
                - "Denied counter"
            name:
                description:
                - "Rule set name"
            app:
                description:
                - "Field app"
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
            rule_list:
                description:
                - "Field rule_list"
            tag:
                description:
                - "Field tag"
            permit:
                description:
                - "Permitted counter"
            unmatched_drops:
                description:
                - "Unmatched drops counter"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
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
            reset_lidlog:
                description:
                - "Enable logging"
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


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["app","application","name","oper","remark","rule_list","rules_by_zone","sampling_enable","session_statistic","stats","tag","track_app_rule_list","user_tag","uuid",]

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
        oper=dict(type='dict',total_active_icmp=dict(type='int',),policy_deny=dict(type='int',),total_deny_bytes=dict(type='int',),total_hit=dict(type='int',),policy_status=dict(type='str',),total_packets=dict(type='int',),total_deny_packets=dict(type='int',),total_permit_bytes=dict(type='int',),rule_list=dict(type='list',oper=dict(type='dict',denybytes=dict(type='int',),activesessiontcp=dict(type='int',),permitbytes=dict(type='int',),sessiontcp=dict(type='int',),resetpackets=dict(type='int',),sessionsctp=dict(type='int',),sessionother=dict(type='int',),totalbytes=dict(type='int',),activesessionicmp=dict(type='int',),denypackets=dict(type='int',),hitcount=dict(type='int',),status=dict(type='str',),activesessionother=dict(type='int',),sessionudp=dict(type='int',),sessionicmp=dict(type='int',),sessiontotal=dict(type='int',),totalpackets=dict(type='int',),activesessionudp=dict(type='int',),permitpackets=dict(type='int',),last_hitcount_time=dict(type='str',),activesessiontotal=dict(type='int',),resetbytes=dict(type='int',),action=dict(type='str',),activesessionsctp=dict(type='int',)),name=dict(type='str',required=True,)),total_active_tcp=dict(type='int',),application=dict(type='dict',oper=dict(type='dict',app_stat=dict(type='str',),category_stat=dict(type='str',),rule=dict(type='str',),rule_list=dict(type='list',stat_list=dict(type='list',category=dict(type='str',),conns=dict(type='int',),bytes=dict(type='int',),name=dict(type='str',),ntype=dict(type='str',)),name=dict(type='str',)))),total_active_others=dict(type='int',),total_permit_packets=dict(type='int',),rule_stats=dict(type='list',rule_hitcount=dict(type='int',),rule_action=dict(type='str',),rule_status=dict(type='str',),rule_name=dict(type='str',)),total_active_udp=dict(type='int',),policy_rule_count=dict(type='int',),policy_reset=dict(type='int',),total_reset_packets=dict(type='int',),total_reset_bytes=dict(type='int',),rules_by_zone=dict(type='dict',oper=dict(type='dict',group_list=dict(type='list',to=dict(type='str',),from=dict(type='str',),rule_list=dict(type='list',dest_list=dict(type='list',dest=dict(type='str',)),action=dict(type='str',),source_list=dict(type='list',source=dict(type='str',)),name=dict(type='str',),service_list=dict(type='list',service=dict(type='str',)))))),name=dict(type='str',required=True,),total_bytes=dict(type='int',),topn_rules=dict(type='str',),track_app_rule_list=dict(type='dict',oper=dict(type='dict',rule_list=dict(type='list',name=dict(type='str',)))),policy_unmatched_drop=dict(type='int',),show_total_stats=dict(type='str',),policy_permit=dict(type='int',)),
        remark=dict(type='str',),
        stats=dict(type='dict',reset=dict(type='str',),deny=dict(type='str',),name=dict(type='str',required=True,),app=dict(type='dict',stats=dict(type='dict',appstat249=dict(type='str',),appstat248=dict(type='str',),appstat245=dict(type='str',),appstat244=dict(type='str',),appstat247=dict(type='str',),appstat246=dict(type='str',),appstat241=dict(type='str',),appstat240=dict(type='str',),appstat243=dict(type='str',),appstat242=dict(type='str',),appstat489=dict(type='str',),appstat488=dict(type='str',),appstat487=dict(type='str',),appstat486=dict(type='str',),appstat485=dict(type='str',),appstat484=dict(type='str',),appstat483=dict(type='str',),appstat482=dict(type='str',),appstat481=dict(type='str',),appstat480=dict(type='str',),appstat91=dict(type='str',),appstat90=dict(type='str',),appstat93=dict(type='str',),appstat92=dict(type='str',),appstat95=dict(type='str',),appstat94=dict(type='str',),appstat97=dict(type='str',),appstat96=dict(type='str',),appstat99=dict(type='str',),appstat98=dict(type='str',),appstat182=dict(type='str',),appstat183=dict(type='str',),appstat180=dict(type='str',),appstat181=dict(type='str',),appstat186=dict(type='str',),appstat187=dict(type='str',),appstat184=dict(type='str',),appstat185=dict(type='str',),appstat188=dict(type='str',),appstat189=dict(type='str',),appstat348=dict(type='str',),appstat349=dict(type='str',),appstat344=dict(type='str',),appstat345=dict(type='str',),appstat346=dict(type='str',),appstat347=dict(type='str',),appstat340=dict(type='str',),appstat341=dict(type='str',),appstat342=dict(type='str',),appstat343=dict(type='str',),appstat119=dict(type='str',),appstat118=dict(type='str',),appstat111=dict(type='str',),appstat110=dict(type='str',),appstat113=dict(type='str',),appstat112=dict(type='str',),appstat115=dict(type='str',),appstat114=dict(type='str',),appstat117=dict(type='str',),appstat116=dict(type='str',),appstat449=dict(type='str',),appstat448=dict(type='str',),appstat443=dict(type='str',),appstat442=dict(type='str',),appstat441=dict(type='str',),appstat440=dict(type='str',),appstat447=dict(type='str',),appstat446=dict(type='str',),appstat445=dict(type='str',),appstat444=dict(type='str',),appstat298=dict(type='str',),appstat234=dict(type='str',),appstat235=dict(type='str',),appstat236=dict(type='str',),appstat299=dict(type='str',),appstat230=dict(type='str',),appstat231=dict(type='str',),appstat232=dict(type='str',),appstat233=dict(type='str',),appstat238=dict(type='str',),appstat239=dict(type='str',),appstat46=dict(type='str',),appstat47=dict(type='str',),appstat44=dict(type='str',),appstat45=dict(type='str',),appstat42=dict(type='str',),appstat43=dict(type='str',),appstat40=dict(type='str',),appstat41=dict(type='str',),appstat290=dict(type='str',),appstat48=dict(type='str',),appstat49=dict(type='str',),appstat358=dict(type='str',),appstat308=dict(type='str',),appstat309=dict(type='str',),appstat300=dict(type='str',),appstat301=dict(type='str',),appstat302=dict(type='str',),appstat303=dict(type='str',),appstat304=dict(type='str',),appstat305=dict(type='str',),appstat306=dict(type='str',),appstat307=dict(type='str',),appstat155=dict(type='str',),appstat154=dict(type='str',),appstat157=dict(type='str',),appstat156=dict(type='str',),appstat151=dict(type='str',),appstat150=dict(type='str',),appstat153=dict(type='str',),appstat152=dict(type='str',),appstat159=dict(type='str',),appstat158=dict(type='str',),appstat9=dict(type='str',),appstat8=dict(type='str',),appstat405=dict(type='str',),appstat404=dict(type='str',),appstat403=dict(type='str',),appstat402=dict(type='str',),appstat401=dict(type='str',),appstat400=dict(type='str',),appstat1=dict(type='str',),appstat3=dict(type='str',),appstat2=dict(type='str',),appstat5=dict(type='str',),appstat4=dict(type='str',),appstat7=dict(type='str',),appstat6=dict(type='str',),appstat270=dict(type='str',),appstat271=dict(type='str',),appstat272=dict(type='str',),appstat273=dict(type='str',),appstat274=dict(type='str',),appstat275=dict(type='str',),appstat276=dict(type='str',),appstat277=dict(type='str',),appstat278=dict(type='str',),appstat279=dict(type='str',),appstat472=dict(type='str',),appstat473=dict(type='str',),appstat470=dict(type='str',),appstat471=dict(type='str',),appstat476=dict(type='str',),appstat477=dict(type='str',),appstat474=dict(type='str',),appstat475=dict(type='str',),appstat478=dict(type='str',),appstat479=dict(type='str',),appstat82=dict(type='str',),appstat83=dict(type='str',),appstat80=dict(type='str',),appstat81=dict(type='str',),appstat86=dict(type='str',),appstat87=dict(type='str',),appstat84=dict(type='str',),appstat85=dict(type='str',),appstat88=dict(type='str',),appstat89=dict(type='str',),appstat204=dict(type='str',),appstat258=dict(type='str',),appstat259=dict(type='str',),appstat39=dict(type='str',),appstat38=dict(type='str',),appstat37=dict(type='str',),appstat36=dict(type='str',),appstat35=dict(type='str',),appstat34=dict(type='str',),appstat33=dict(type='str',),appstat32=dict(type='str',),appstat31=dict(type='str',),appstat30=dict(type='str',),appstat191=dict(type='str',),appstat190=dict(type='str',),appstat193=dict(type='str',),appstat192=dict(type='str',),appstat195=dict(type='str',),appstat194=dict(type='str',),appstat197=dict(type='str',),appstat196=dict(type='str',),appstat199=dict(type='str',),appstat198=dict(type='str',),appstat251=dict(type='str',),appstat353=dict(type='str',),appstat352=dict(type='str',),appstat351=dict(type='str',),appstat350=dict(type='str',),appstat357=dict(type='str',),appstat356=dict(type='str',),appstat355=dict(type='str',),appstat354=dict(type='str',),appstat292=dict(type='str',),appstat293=dict(type='str',),appstat359=dict(type='str',),appstat291=dict(type='str',),appstat296=dict(type='str',),appstat297=dict(type='str',),appstat294=dict(type='str',),appstat295=dict(type='str',),appstat128=dict(type='str',),appstat129=dict(type='str',),appstat124=dict(type='str',),appstat125=dict(type='str',),appstat126=dict(type='str',),appstat127=dict(type='str',),appstat120=dict(type='str',),appstat121=dict(type='str',),appstat122=dict(type='str',),appstat123=dict(type='str',),appstat438=dict(type='str',),appstat439=dict(type='str',),appstat436=dict(type='str',),appstat437=dict(type='str',),appstat434=dict(type='str',),appstat435=dict(type='str',),appstat432=dict(type='str',),appstat433=dict(type='str',),appstat430=dict(type='str',),appstat431=dict(type='str',),appstat500=dict(type='str',),appstat501=dict(type='str',),appstat380=dict(type='str',),appstat381=dict(type='str',),appstat382=dict(type='str',),appstat228=dict(type='str',),appstat384=dict(type='str',),appstat385=dict(type='str',),appstat386=dict(type='str',),appstat387=dict(type='str',),appstat223=dict(type='str',),appstat222=dict(type='str',),appstat221=dict(type='str',),appstat220=dict(type='str',),appstat227=dict(type='str',),appstat226=dict(type='str',),appstat225=dict(type='str',),appstat224=dict(type='str',),appstat79=dict(type='str',),appstat78=dict(type='str',),appstat73=dict(type='str',),appstat72=dict(type='str',),appstat71=dict(type='str',),appstat70=dict(type='str',),appstat77=dict(type='str',),appstat76=dict(type='str',),appstat75=dict(type='str',),appstat74=dict(type='str',),appstat319=dict(type='str',),appstat318=dict(type='str',),appstat317=dict(type='str',),appstat316=dict(type='str',),appstat315=dict(type='str',),appstat314=dict(type='str',),appstat313=dict(type='str',),appstat312=dict(type='str',),appstat311=dict(type='str',),appstat310=dict(type='str',),appstat407=dict(type='str',),appstat406=dict(type='str',),appstat168=dict(type='str',),appstat169=dict(type='str',),appstat160=dict(type='str',),appstat161=dict(type='str',),appstat162=dict(type='str',),appstat163=dict(type='str',),appstat164=dict(type='str',),appstat165=dict(type='str',),appstat166=dict(type='str',),appstat167=dict(type='str',),appstat368=dict(type='str',),appstat369=dict(type='str',),appstat362=dict(type='str',),appstat363=dict(type='str',),appstat360=dict(type='str',),appstat361=dict(type='str',),appstat366=dict(type='str',),appstat367=dict(type='str',),appstat364=dict(type='str',),appstat365=dict(type='str',),appstat409=dict(type='str',),appstat408=dict(type='str',),appstat267=dict(type='str',),appstat266=dict(type='str',),appstat265=dict(type='str',),appstat264=dict(type='str',),appstat263=dict(type='str',),appstat262=dict(type='str',),appstat261=dict(type='str',),appstat260=dict(type='str',),appstat506=dict(type='str',),appstat507=dict(type='str',),appstat504=dict(type='str',),appstat505=dict(type='str',),appstat502=dict(type='str',),appstat503=dict(type='str',),appstat269=dict(type='str',),appstat268=dict(type='str',),appstat461=dict(type='str',),appstat460=dict(type='str',),appstat463=dict(type='str',),appstat462=dict(type='str',),appstat465=dict(type='str',),appstat464=dict(type='str',),appstat467=dict(type='str',),appstat466=dict(type='str',),appstat469=dict(type='str',),appstat468=dict(type='str',),appstat212=dict(type='str',),appstat213=dict(type='str',),appstat210=dict(type='str',),appstat211=dict(type='str',),appstat216=dict(type='str',),appstat217=dict(type='str',),appstat214=dict(type='str',),appstat215=dict(type='str',),appstat218=dict(type='str',),appstat219=dict(type='str',),appstat20=dict(type='str',),appstat21=dict(type='str',),appstat22=dict(type='str',),appstat23=dict(type='str',),appstat24=dict(type='str',),appstat25=dict(type='str',),appstat26=dict(type='str',),appstat27=dict(type='str',),appstat28=dict(type='str',),appstat29=dict(type='str',),appstat229=dict(type='str',),appstat383=dict(type='str',),appstat326=dict(type='str',),appstat327=dict(type='str',),appstat324=dict(type='str',),appstat325=dict(type='str',),appstat322=dict(type='str',),appstat323=dict(type='str',),appstat320=dict(type='str',),appstat321=dict(type='str',),appstat281=dict(type='str',),appstat280=dict(type='str',),appstat283=dict(type='str',),appstat282=dict(type='str',),appstat285=dict(type='str',),appstat284=dict(type='str',),appstat287=dict(type='str',),appstat329=dict(type='str',),appstat388=dict(type='str',),appstat389=dict(type='str',),appstat250=dict(type='str',),appstat133=dict(type='str',),appstat132=dict(type='str',),appstat131=dict(type='str',),appstat130=dict(type='str',),appstat137=dict(type='str',),appstat136=dict(type='str',),appstat135=dict(type='str',),appstat134=dict(type='str',),appstat139=dict(type='str',),appstat138=dict(type='str',),appstat429=dict(type='str',),appstat428=dict(type='str',),appstat425=dict(type='str',),appstat424=dict(type='str',),appstat427=dict(type='str',),appstat426=dict(type='str',),appstat421=dict(type='str',),appstat420=dict(type='str',),appstat423=dict(type='str',),appstat422=dict(type='str',),appstat508=dict(type='str',),appstat509=dict(type='str',),appstat397=dict(type='str',),appstat396=dict(type='str',),appstat395=dict(type='str',),appstat394=dict(type='str',),appstat393=dict(type='str',),appstat392=dict(type='str',),appstat391=dict(type='str',),appstat390=dict(type='str',),appstat256=dict(type='str',),appstat257=dict(type='str',),appstat254=dict(type='str',),appstat255=dict(type='str',),appstat252=dict(type='str',),appstat253=dict(type='str',),appstat399=dict(type='str',),appstat398=dict(type='str',),appstat498=dict(type='str',),appstat499=dict(type='str',),appstat490=dict(type='str',),appstat491=dict(type='str',),appstat492=dict(type='str',),appstat493=dict(type='str',),appstat494=dict(type='str',),appstat495=dict(type='str',),appstat496=dict(type='str',),appstat497=dict(type='str',),appstat68=dict(type='str',),appstat69=dict(type='str',),appstat64=dict(type='str',),appstat65=dict(type='str',),appstat66=dict(type='str',),appstat67=dict(type='str',),appstat60=dict(type='str',),appstat61=dict(type='str',),appstat62=dict(type='str',),appstat63=dict(type='str',),appstat19=dict(type='str',),appstat18=dict(type='str',),appstat11=dict(type='str',),appstat10=dict(type='str',),appstat13=dict(type='str',),appstat12=dict(type='str',),appstat15=dict(type='str',),appstat14=dict(type='str',),appstat17=dict(type='str',),appstat16=dict(type='str',),appstat179=dict(type='str',),appstat178=dict(type='str',),appstat177=dict(type='str',),appstat176=dict(type='str',),appstat175=dict(type='str',),appstat174=dict(type='str',),appstat173=dict(type='str',),appstat172=dict(type='str',),appstat171=dict(type='str',),appstat170=dict(type='str',),appstat379=dict(type='str',),appstat378=dict(type='str',),appstat371=dict(type='str',),appstat370=dict(type='str',),appstat373=dict(type='str',),appstat372=dict(type='str',),appstat375=dict(type='str',),appstat374=dict(type='str',),appstat377=dict(type='str',),appstat376=dict(type='str',),appstat108=dict(type='str',),appstat109=dict(type='str',),appstat102=dict(type='str',),appstat103=dict(type='str',),appstat100=dict(type='str',),appstat101=dict(type='str',),appstat106=dict(type='str',),appstat107=dict(type='str',),appstat104=dict(type='str',),appstat105=dict(type='str',),appstat289=dict(type='str',),appstat288=dict(type='str',),appstat511=dict(type='str',),appstat510=dict(type='str',),appstat454=dict(type='str',),appstat455=dict(type='str',),appstat456=dict(type='str',),appstat457=dict(type='str',),appstat450=dict(type='str',),appstat451=dict(type='str',),appstat452=dict(type='str',),appstat453=dict(type='str',),appstat458=dict(type='str',),appstat459=dict(type='str',),appstat201=dict(type='str',),appstat200=dict(type='str',),appstat203=dict(type='str',),appstat202=dict(type='str',),appstat205=dict(type='str',),appstat328=dict(type='str',),appstat207=dict(type='str',),appstat206=dict(type='str',),appstat209=dict(type='str',),appstat208=dict(type='str',),appstat286=dict(type='str',),appstat55=dict(type='str',),appstat54=dict(type='str',),appstat57=dict(type='str',),appstat56=dict(type='str',),appstat51=dict(type='str',),appstat50=dict(type='str',),appstat53=dict(type='str',),appstat52=dict(type='str',),appstat59=dict(type='str',),appstat58=dict(type='str',),appstat335=dict(type='str',),appstat334=dict(type='str',),appstat337=dict(type='str',),appstat336=dict(type='str',),appstat331=dict(type='str',),appstat330=dict(type='str',),appstat333=dict(type='str',),appstat332=dict(type='str',),appstat339=dict(type='str',),appstat338=dict(type='str',),appstat146=dict(type='str',),appstat147=dict(type='str',),appstat144=dict(type='str',),appstat145=dict(type='str',),appstat142=dict(type='str',),appstat143=dict(type='str',),appstat140=dict(type='str',),appstat141=dict(type='str',),appstat148=dict(type='str',),appstat149=dict(type='str',),appstat410=dict(type='str',),appstat411=dict(type='str',),appstat412=dict(type='str',),appstat413=dict(type='str',),appstat414=dict(type='str',),appstat415=dict(type='str',),appstat416=dict(type='str',),appstat417=dict(type='str',),appstat418=dict(type='str',),appstat419=dict(type='str',),appstat237=dict(type='str',))),track_app_rule_list=dict(type='dict',stats=dict(type='dict',dummy=dict(type='str',))),rule_list=dict(type='list',stats=dict(type='dict',active_session_other=dict(type='str',),session_icmp=dict(type='str',),hit_count=dict(type='str',),active_session_tcp=dict(type='str',),deny_packets=dict(type='str',),session_other=dict(type='str',),session_sctp=dict(type='str',),active_session_icmp=dict(type='str',),permit_bytes=dict(type='str',),reset_packets=dict(type='str',),hitcount_timestamp=dict(type='str',),reset_bytes=dict(type='str',),session_tcp=dict(type='str',),session_udp=dict(type='str',),active_session_sctp=dict(type='str',),active_session_udp=dict(type='str',),deny_bytes=dict(type='str',),permit_packets=dict(type='str',)),name=dict(type='str',required=True,)),tag=dict(type='dict',stats=dict(type='dict',categorystat54=dict(type='str',),categorystat84=dict(type='str',),categorystat85=dict(type='str',),categorystat26=dict(type='str',),categorystat27=dict(type='str',),categorystat24=dict(type='str',),categorystat25=dict(type='str',),categorystat22=dict(type='str',),categorystat23=dict(type='str',),categorystat20=dict(type='str',),categorystat21=dict(type='str',),categorystat28=dict(type='str',),categorystat29=dict(type='str',),categorystat7=dict(type='str',),categorystat168=dict(type='str',),categorystat169=dict(type='str',),categorystat6=dict(type='str',),categorystat162=dict(type='str',),categorystat163=dict(type='str',),categorystat160=dict(type='str',),categorystat161=dict(type='str',),categorystat166=dict(type='str',),categorystat167=dict(type='str',),categorystat164=dict(type='str',),categorystat165=dict(type='str',),categorystat4=dict(type='str',),categorystat210=dict(type='str',),categorystat3=dict(type='str',),categorystat109=dict(type='str',),categorystat1=dict(type='str',),categorystat35=dict(type='str',),categorystat34=dict(type='str',),categorystat37=dict(type='str',),categorystat36=dict(type='str',),categorystat31=dict(type='str',),categorystat30=dict(type='str',),categorystat33=dict(type='str',),categorystat32=dict(type='str',),categorystat39=dict(type='str',),categorystat38=dict(type='str',),categorystat197=dict(type='str',),categorystat196=dict(type='str',),categorystat195=dict(type='str',),categorystat194=dict(type='str',),categorystat193=dict(type='str',),categorystat192=dict(type='str',),categorystat191=dict(type='str',),categorystat190=dict(type='str',),categorystat100=dict(type='str',),categorystat199=dict(type='str',),categorystat198=dict(type='str',),categorystat207=dict(type='str',),categorystat206=dict(type='str',),categorystat205=dict(type='str',),categorystat204=dict(type='str',),categorystat203=dict(type='str',),categorystat9=dict(type='str',),categorystat119=dict(type='str',),categorystat118=dict(type='str',),categorystat117=dict(type='str',),categorystat116=dict(type='str',),categorystat115=dict(type='str',),categorystat114=dict(type='str',),categorystat113=dict(type='str',),categorystat112=dict(type='str',),categorystat111=dict(type='str',),categorystat110=dict(type='str',),categorystat52=dict(type='str',),categorystat202=dict(type='str',),categorystat184=dict(type='str',),categorystat88=dict(type='str',),categorystat89=dict(type='str',),categorystat186=dict(type='str',),categorystat187=dict(type='str',),categorystat180=dict(type='str',),categorystat181=dict(type='str',),categorystat182=dict(type='str',),categorystat183=dict(type='str',),categorystat80=dict(type='str',),categorystat81=dict(type='str',),categorystat82=dict(type='str',),categorystat83=dict(type='str',),categorystat188=dict(type='str',),categorystat189=dict(type='str',),categorystat86=dict(type='str',),categorystat87=dict(type='str',),categorystat214=dict(type='str',),categorystat215=dict(type='str',),categorystat216=dict(type='str',),categorystat217=dict(type='str',),categorystat108=dict(type='str',),categorystat211=dict(type='str',),categorystat212=dict(type='str',),categorystat213=dict(type='str',),categorystat104=dict(type='str',),categorystat105=dict(type='str',),categorystat106=dict(type='str',),categorystat107=dict(type='str',),categorystat218=dict(type='str',),categorystat219=dict(type='str',),categorystat102=dict(type='str',),categorystat103=dict(type='str',),categorystat201=dict(type='str',),categorystat19=dict(type='str',),categorystat18=dict(type='str',),categorystat17=dict(type='str',),categorystat16=dict(type='str',),categorystat15=dict(type='str',),categorystat14=dict(type='str',),categorystat13=dict(type='str',),categorystat12=dict(type='str',),categorystat11=dict(type='str',),categorystat10=dict(type='str',),categorystat97=dict(type='str',),categorystat96=dict(type='str',),categorystat95=dict(type='str',),categorystat94=dict(type='str',),categorystat93=dict(type='str',),categorystat92=dict(type='str',),categorystat91=dict(type='str',),categorystat90=dict(type='str',),categorystat8=dict(type='str',),categorystat99=dict(type='str',),categorystat98=dict(type='str',),categorystat139=dict(type='str',),categorystat138=dict(type='str',),categorystat223=dict(type='str',),categorystat222=dict(type='str',),categorystat225=dict(type='str',),categorystat209=dict(type='str',),categorystat227=dict(type='str',),categorystat226=dict(type='str',),categorystat131=dict(type='str',),categorystat228=dict(type='str',),categorystat133=dict(type='str',),categorystat208=dict(type='str',),categorystat135=dict(type='str',),categorystat134=dict(type='str',),categorystat137=dict(type='str',),categorystat136=dict(type='str',),categorystat68=dict(type='str',),categorystat69=dict(type='str',),categorystat62=dict(type='str',),categorystat63=dict(type='str',),categorystat60=dict(type='str',),categorystat61=dict(type='str',),categorystat66=dict(type='str',),categorystat67=dict(type='str',),categorystat64=dict(type='str',),categorystat65=dict(type='str',),categorystat238=dict(type='str',),categorystat239=dict(type='str',),categorystat236=dict(type='str',),categorystat237=dict(type='str',),categorystat234=dict(type='str',),categorystat200=dict(type='str',),categorystat232=dict(type='str',),categorystat233=dict(type='str',),categorystat230=dict(type='str',),categorystat231=dict(type='str',),categorystat126=dict(type='str',),categorystat127=dict(type='str',),categorystat124=dict(type='str',),categorystat125=dict(type='str',),categorystat122=dict(type='str',),categorystat123=dict(type='str',),categorystat120=dict(type='str',),categorystat121=dict(type='str',),categorystat128=dict(type='str',),categorystat129=dict(type='str',),categorystat79=dict(type='str',),categorystat78=dict(type='str',),categorystat71=dict(type='str',),categorystat70=dict(type='str',),categorystat73=dict(type='str',),categorystat72=dict(type='str',),categorystat75=dict(type='str',),categorystat74=dict(type='str',),categorystat77=dict(type='str',),categorystat76=dict(type='str',),categorystat249=dict(type='str',),categorystat248=dict(type='str',),categorystat5=dict(type='str',),categorystat243=dict(type='str',),categorystat242=dict(type='str',),categorystat241=dict(type='str',),categorystat240=dict(type='str',),categorystat247=dict(type='str',),categorystat246=dict(type='str',),categorystat245=dict(type='str',),categorystat244=dict(type='str',),categorystat153=dict(type='str',),categorystat152=dict(type='str',),categorystat151=dict(type='str',),categorystat150=dict(type='str',),categorystat157=dict(type='str',),categorystat156=dict(type='str',),categorystat155=dict(type='str',),categorystat154=dict(type='str',),categorystat235=dict(type='str',),categorystat159=dict(type='str',),categorystat158=dict(type='str',),categorystat44=dict(type='str',),categorystat45=dict(type='str',),categorystat46=dict(type='str',),categorystat47=dict(type='str',),categorystat40=dict(type='str',),categorystat41=dict(type='str',),categorystat42=dict(type='str',),categorystat43=dict(type='str',),categorystat48=dict(type='str',),categorystat49=dict(type='str',),categorystat221=dict(type='str',),categorystat220=dict(type='str',),categorystat250=dict(type='str',),categorystat251=dict(type='str',),categorystat252=dict(type='str',),categorystat253=dict(type='str',),categorystat254=dict(type='str',),categorystat255=dict(type='str',),categorystat256=dict(type='str',),categorystat140=dict(type='str',),categorystat141=dict(type='str',),categorystat142=dict(type='str',),categorystat143=dict(type='str',),categorystat144=dict(type='str',),categorystat145=dict(type='str',),categorystat146=dict(type='str',),categorystat147=dict(type='str',),categorystat148=dict(type='str',),categorystat149=dict(type='str',),categorystat224=dict(type='str',),categorystat53=dict(type='str',),categorystat2=dict(type='str',),categorystat51=dict(type='str',),categorystat50=dict(type='str',),categorystat57=dict(type='str',),categorystat56=dict(type='str',),categorystat55=dict(type='str',),categorystat185=dict(type='str',),categorystat59=dict(type='str',),categorystat58=dict(type='str',),categorystat229=dict(type='str',),categorystat130=dict(type='str',),categorystat101=dict(type='str',),categorystat132=dict(type='str',),categorystat179=dict(type='str',),categorystat178=dict(type='str',),categorystat175=dict(type='str',),categorystat174=dict(type='str',),categorystat177=dict(type='str',),categorystat176=dict(type='str',),categorystat171=dict(type='str',),categorystat170=dict(type='str',),categorystat173=dict(type='str',),categorystat172=dict(type='str',))),permit=dict(type='str',),unmatched_drops=dict(type='str',),rules_by_zone=dict(type='dict',stats=dict(type='dict',dummy=dict(type='str',)))),
        name=dict(type='str',required=True,),
        app=dict(type='dict',uuid=dict(type='str',)),
        track_app_rule_list=dict(type='dict',uuid=dict(type='str',)),
        user_tag=dict(type='str',),
        application=dict(type='dict',uuid=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','unmatched-drops','permit','deny','reset'])),
        tag=dict(type='dict',uuid=dict(type='str',)),
        rule_list=dict(type='list',cgnv6_fixed_nat_log=dict(type='bool',),dst_geoloc_list_shared=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hit-count','permit-bytes','deny-bytes','reset-bytes','permit-packets','deny-packets','reset-packets','active-session-tcp','active-session-udp','active-session-icmp','active-session-other','session-tcp','session-udp','session-icmp','session-other','active-session-sctp','session-sctp','hitcount-timestamp'])),forward_listen_on_port=dict(type='bool',),reset_lidlog=dict(type='bool',),listen_on_port_lid=dict(type='int',),app_list=dict(type='list',obj_grp_application=dict(type='str',),protocol=dict(type='str',),protocol_tag=dict(type='str',choices=['aaa','adult-content','advertising','analytics-and-statistics','anonymizers-and-proxies','audio-chat','basic','blog','cdn','chat','classified-ads','cloud-based-services','cryptocurrency','database','disposable-email','email','enterprise','file-management','file-transfer','forum','gaming','instant-messaging-and-multimedia-conferencing','internet-of-things','mobile','multimedia-streaming','networking','news-portal','peer-to-peer','remote-access','scada','social-networks','software-update','standards-based','transportation','video-chat','voip','vpn-tunnels','web','web-e-commerce','web-search-engines','web-websites','webmails','web-ext-adult','web-ext-auctions','web-ext-blogs','web-ext-business-and-economy','web-ext-cdns','web-ext-collaboration','web-ext-computer-and-internet-info','web-ext-computer-and-internet-security','web-ext-dating','web-ext-educational-institutions','web-ext-entertainment-and-arts','web-ext-fashion-and-beauty','web-ext-file-share','web-ext-financial-services','web-ext-gambling','web-ext-games','web-ext-government','web-ext-health-and-medicine','web-ext-individual-stock-advice-and-tools','web-ext-internet-portals','web-ext-job-search','web-ext-local-information','web-ext-malware','web-ext-motor-vehicles','web-ext-music','web-ext-news','web-ext-p2p','web-ext-parked-sites','web-ext-proxy-avoid-and-anonymizers','web-ext-real-estate','web-ext-reference-and-research','web-ext-search-engines','web-ext-shopping','web-ext-social-network','web-ext-society','web-ext-software','web-ext-sports','web-ext-streaming-media','web-ext-training-and-tools','web-ext-translation','web-ext-travel','web-ext-web-advertisements','web-ext-web-based-email','web-ext-web-hosting','web-ext-web-service'])),src_threat_list=dict(type='str',),cgnv6_policy=dict(type='str',choices=['lsn-lid','fixed-nat']),src_geoloc_name=dict(type='str',),cgnv6_log=dict(type='bool',),forward_log=dict(type='bool',),lid=dict(type='int',),listen_on_port=dict(type='bool',),move_rule=dict(type='dict',location=dict(type='str',choices=['top','before','after','bottom']),target_rule=dict(type='str',)),log=dict(type='bool',),dst_geoloc_name=dict(type='str',),idle_timeout=dict(type='int',),listen_on_port_lidlog=dict(type='bool',),src_zone_any=dict(type='str',choices=['any']),ip_version=dict(type='str',choices=['v4','v6']),application_any=dict(type='str',choices=['any']),src_zone=dict(type='str',),src_geoloc_list_shared=dict(type='bool',),policy=dict(type='str',choices=['cgnv6','forward']),source_list=dict(type='list',src_ipv6_subnet=dict(type='str',),src_obj_network=dict(type='str',),src_slb_server=dict(type='str',),src_obj_grp_network=dict(type='str',),src_ip_subnet=dict(type='str',)),dst_zone_any=dict(type='str',choices=['any']),status=dict(type='str',choices=['enable','disable']),lidlog=dict(type='bool',),dst_ipv4_any=dict(type='str',choices=['any']),cgnv6_lsn_lid=dict(type='int',),src_geoloc_list=dict(type='str',),src_ipv4_any=dict(type='str',choices=['any']),fwlog=dict(type='bool',),dst_zone=dict(type='str',),dst_class_list=dict(type='str',),uuid=dict(type='str',),dst_threat_list=dict(type='str',),remark=dict(type='str',),src_class_list=dict(type='str',),name=dict(type='str',required=True,),src_ipv6_any=dict(type='str',choices=['any']),reset_lid=dict(type='int',),dst_geoloc_list=dict(type='str',),track_application=dict(type='bool',),user_tag=dict(type='str',),cgnv6_lsn_log=dict(type='bool',),dst_ipv6_any=dict(type='str',choices=['any']),service_any=dict(type='str',choices=['any']),service_list=dict(type='list',gtp_template=dict(type='str',),icmp_type=dict(type='int',),range_dst_port=dict(type='int',),icmpv6_code=dict(type='int',),gt_src_port=dict(type='int',),lt_src_port=dict(type='int',),proto_id=dict(type='int',),lt_dst_port=dict(type='int',),alg=dict(type='str',choices=['FTP','TFTP','SIP','DNS','PPTP','RTSP']),obj_grp_service=dict(type='str',),icmpv6_type=dict(type='int',),icmp_code=dict(type='int',),range_src_port=dict(type='int',),eq_dst_port=dict(type='int',),sctp_template=dict(type='str',),icmp=dict(type='bool',),protocols=dict(type='str',choices=['tcp','udp','sctp']),gt_dst_port=dict(type='int',),port_num_end_src=dict(type='int',),special_v6_type=dict(type='str',choices=['any-type','dest-unreachable','echo-reply','echo-request','packet-too-big','param-prob','time-exceeded']),eq_src_port=dict(type='int',),special_v6_code=dict(type='str',choices=['any-code','addr-unreachable','admin-prohibited','no-route','not-neighbour','port-unreachable']),icmpv6=dict(type='bool',),port_num_end_dst=dict(type='int',),special_code=dict(type='str',choices=['any-code','frag-required','host-unreachable','network-unreachable','port-unreachable','proto-unreachable','route-failed']),special_type=dict(type='str',choices=['any-type','echo-reply','echo-request','info-reply','info-request','mask-reply','mask-request','parameter-problem','redirect','source-quench','time-exceeded','timestamp','timestamp-reply','dest-unreachable'])),dst_domain_list=dict(type='str',),dest_list=dict(type='list',dst_obj_network=dict(type='str',),dst_obj_grp_network=dict(type='str',),dst_slb_vserver=dict(type='str',),dst_ip_subnet=dict(type='str',),dst_ipv6_subnet=dict(type='str',),dst_slb_server=dict(type='str',)),action=dict(type='str',choices=['permit','deny','reset']),fw_log=dict(type='bool',)),
        session_statistic=dict(type='str',choices=['enable','disable']),
        rules_by_zone=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dummy'])),uuid=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["rule-set"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rule-set"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rule-set"][k] = v
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
    payload = build_json("rule-set", module)
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