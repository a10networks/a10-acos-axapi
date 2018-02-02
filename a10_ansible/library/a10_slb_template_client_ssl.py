#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_client_ssl
description:
    - None
short_description: Configures A10 slb.template.client-ssl
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
    name:
        description:
        - "None"
        required: True
    auth_username:
        description:
        - "None"
        required: False
    ca_certs:
        description:
        - "Field ca_certs"
        required: False
        suboptions:
            ca_cert:
                description:
                - "None"
            client_ocsp:
                description:
                - "None"
            client_ocsp_srvr:
                description:
                - "None"
            client_ocsp_sg:
                description:
                - "None"
    chain_cert:
        description:
        - "None"
        required: False
    cert:
        description:
        - "None"
        required: False
    dh_type:
        description:
        - "None"
        required: False
    ec_list:
        description:
        - "Field ec_list"
        required: False
        suboptions:
            ec:
                description:
                - "None"
    local_logging:
        description:
        - "None"
        required: False
    ocsp_stapling:
        description:
        - "None"
        required: False
    ocspst_ca_cert:
        description:
        - "None"
        required: False
    ocspst_ocsp:
        description:
        - "None"
        required: False
    ocspst_srvr:
        description:
        - "None"
        required: False
    ocspst_srvr_days:
        description:
        - "None"
        required: False
    ocspst_srvr_hours:
        description:
        - "None"
        required: False
    ocspst_srvr_minutes:
        description:
        - "None"
        required: False
    ocspst_srvr_timeout:
        description:
        - "None"
        required: False
    ocspst_sg:
        description:
        - "None"
        required: False
    ocspst_sg_days:
        description:
        - "None"
        required: False
    ocspst_sg_hours:
        description:
        - "None"
        required: False
    ocspst_sg_minutes:
        description:
        - "None"
        required: False
    ocspst_sg_timeout:
        description:
        - "None"
        required: False
    ssli_logging:
        description:
        - "None"
        required: False
    sslilogging:
        description:
        - "None"
        required: False
    client_certificate:
        description:
        - "None"
        required: False
    req_ca_lists:
        description:
        - "Field req_ca_lists"
        required: False
        suboptions:
            client_certificate_Request_CA:
                description:
                - "None"
    close_notify:
        description:
        - "None"
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        required: False
        suboptions:
            crl:
                description:
                - "None"
    forward_proxy_ca_cert:
        description:
        - "None"
        required: False
    forward_proxy_ca_key:
        description:
        - "None"
        required: False
    forward_passphrase:
        description:
        - "None"
        required: False
    forward_encrypted:
        description:
        - "None"
        required: False
    forward_proxy_alt_sign:
        description:
        - "None"
        required: False
    fp_alt_cert:
        description:
        - "None"
        required: False
    fp_alt_key:
        description:
        - "None"
        required: False
    fp_alt_passphrase:
        description:
        - "None"
        required: False
    fp_alt_encrypted:
        description:
        - "None"
        required: False
    forward_proxy_trusted_ca_lists:
        description:
        - "Field forward_proxy_trusted_ca_lists"
        required: False
        suboptions:
            forward_proxy_trusted_ca:
                description:
                - "None"
    forward_proxy_decrypted_dscp:
        description:
        - "None"
        required: False
    forward_proxy_decrypted_dscp_bypass:
        description:
        - "None"
        required: False
    enable_tls_alert_logging:
        description:
        - "None"
        required: False
    alert_type:
        description:
        - "None"
        required: False
    forward_proxy_verify_cert_fail_action:
        description:
        - "None"
        required: False
    verify_cert_fail_action:
        description:
        - "None"
        required: False
    forward_proxy_cert_revoke_action:
        description:
        - "None"
        required: False
    cert_revoke_action:
        description:
        - "None"
        required: False
    forward_proxy_cert_unknown_action:
        description:
        - "None"
        required: False
    cert_unknown_action:
        description:
        - "None"
        required: False
    cache_persistence_list_name:
        description:
        - "None"
        required: False
    fp_cert_ext_crldp:
        description:
        - "None"
        required: False
    fp_cert_ext_aia_ocsp:
        description:
        - "None"
        required: False
    fp_cert_ext_aia_ca_issuers:
        description:
        - "None"
        required: False
    notbefore:
        description:
        - "None"
        required: False
    notbeforeday:
        description:
        - "None"
        required: False
    notbeforemonth:
        description:
        - "None"
        required: False
    notbeforeyear:
        description:
        - "None"
        required: False
    notafter:
        description:
        - "None"
        required: False
    notafterday:
        description:
        - "None"
        required: False
    notaftermonth:
        description:
        - "None"
        required: False
    notafteryear:
        description:
        - "None"
        required: False
    forward_proxy_ssl_version:
        description:
        - "None"
        required: False
    forward_proxy_ocsp_disable:
        description:
        - "None"
        required: False
    forward_proxy_crl_disable:
        description:
        - "None"
        required: False
    forward_proxy_cert_cache_timeout:
        description:
        - "None"
        required: False
    forward_proxy_cert_cache_limit:
        description:
        - "None"
        required: False
    forward_proxy_cert_expiry:
        description:
        - "None"
        required: False
    expire_hours:
        description:
        - "None"
        required: False
    forward_proxy_enable:
        description:
        - "None"
        required: False
    handshake_logging_enable:
        description:
        - "None"
        required: False
    forward_proxy_selfsign_redir:
        description:
        - "None"
        required: False
    forward_proxy_failsafe_disable:
        description:
        - "None"
        required: False
    forward_proxy_log_disable:
        description:
        - "None"
        required: False
    fp_cert_fetch_natpool_name:
        description:
        - "None"
        required: False
    fp_cert_fetch_natpool_precedence:
        description:
        - "None"
        required: False
    fp_cert_fetch_autonat:
        description:
        - "None"
        required: False
    fp_cert_fetch_autonat_precedence:
        description:
        - "None"
        required: False
    case_insensitive:
        description:
        - "None"
        required: False
    class_list_name:
        description:
        - "None"
        required: False
    multi_class_list:
        description:
        - "Field multi_class_list"
        required: False
        suboptions:
            multi_clist_name:
                description:
                - "None"
    exception_class_list:
        description:
        - "None"
        required: False
    inspect_list_name:
        description:
        - "None"
        required: False
    contains_list:
        description:
        - "Field contains_list"
        required: False
        suboptions:
            contains:
                description:
                - "None"
    ends_with_list:
        description:
        - "Field ends_with_list"
        required: False
        suboptions:
            ends_with:
                description:
                - "None"
    equals_list:
        description:
        - "Field equals_list"
        required: False
        suboptions:
            equals:
                description:
                - "None"
    starts_with_list:
        description:
        - "Field starts_with_list"
        required: False
        suboptions:
            starts_with:
                description:
                - "None"
    client_auth_case_insensitive:
        description:
        - "None"
        required: False
    client_auth_class_list:
        description:
        - "None"
        required: False
    client_auth_contains_list:
        description:
        - "Field client_auth_contains_list"
        required: False
        suboptions:
            client_auth_contains:
                description:
                - "None"
    client_auth_ends_with_list:
        description:
        - "Field client_auth_ends_with_list"
        required: False
        suboptions:
            client_auth_ends_with:
                description:
                - "None"
    client_auth_equals_list:
        description:
        - "Field client_auth_equals_list"
        required: False
        suboptions:
            client_auth_equals:
                description:
                - "None"
    client_auth_starts_with_list:
        description:
        - "Field client_auth_starts_with_list"
        required: False
        suboptions:
            client_auth_starts_with:
                description:
                - "None"
    forward_proxy_cert_not_ready_action:
        description:
        - "None"
        required: False
    web_category:
        description:
        - "Field web_category"
        required: False
        suboptions:
            uncategorized:
                description:
                - "None"
            real_estate:
                description:
                - "None"
            computer_and_internet_security:
                description:
                - "None"
            financial_services:
                description:
                - "None"
            business_and_economy:
                description:
                - "None"
            computer_and_internet_info:
                description:
                - "None"
            auctions:
                description:
                - "None"
            shopping:
                description:
                - "None"
            cult_and_occult:
                description:
                - "None"
            travel:
                description:
                - "None"
            drugs:
                description:
                - "None"
            adult_and_pornography:
                description:
                - "None"
            home_and_garden:
                description:
                - "None"
            military:
                description:
                - "None"
            social_network:
                description:
                - "None"
            dead_sites:
                description:
                - "None"
            stock_advice_and_tools:
                description:
                - "None"
            training_and_tools:
                description:
                - "None"
            dating:
                description:
                - "None"
            sex_education:
                description:
                - "None"
            religion:
                description:
                - "None"
            entertainment_and_arts:
                description:
                - "None"
            personal_sites_and_blogs:
                description:
                - "None"
            legal:
                description:
                - "None"
            local_information:
                description:
                - "None"
            streaming_media:
                description:
                - "None"
            job_search:
                description:
                - "None"
            gambling:
                description:
                - "None"
            translation:
                description:
                - "None"
            reference_and_research:
                description:
                - "None"
            shareware_and_freeware:
                description:
                - "None"
            peer_to_peer:
                description:
                - "None"
            marijuana:
                description:
                - "None"
            hacking:
                description:
                - "None"
            games:
                description:
                - "None"
            philosophy_and_politics:
                description:
                - "None"
            weapons:
                description:
                - "None"
            pay_to_surf:
                description:
                - "None"
            hunting_and_fishing:
                description:
                - "None"
            society:
                description:
                - "None"
            educational_institutions:
                description:
                - "None"
            online_greeting_cards:
                description:
                - "None"
            sports:
                description:
                - "None"
            swimsuits_and_intimate_apparel:
                description:
                - "None"
            questionable:
                description:
                - "None"
            kids:
                description:
                - "None"
            hate_and_racism:
                description:
                - "None"
            personal_storage:
                description:
                - "None"
            violence:
                description:
                - "None"
            keyloggers_and_monitoring:
                description:
                - "None"
            search_engines:
                description:
                - "None"
            internet_portals:
                description:
                - "None"
            web_advertisements:
                description:
                - "None"
            cheating:
                description:
                - "None"
            gross:
                description:
                - "None"
            web_based_email:
                description:
                - "None"
            malware_sites:
                description:
                - "None"
            phishing_and_other_fraud:
                description:
                - "None"
            proxy_avoid_and_anonymizers:
                description:
                - "None"
            spyware_and_adware:
                description:
                - "None"
            music:
                description:
                - "None"
            government:
                description:
                - "None"
            nudity:
                description:
                - "None"
            news_and_media:
                description:
                - "None"
            illegal:
                description:
                - "None"
            cdns:
                description:
                - "None"
            internet_communications:
                description:
                - "None"
            bot_nets:
                description:
                - "None"
            abortion:
                description:
                - "None"
            health_and_medicine:
                description:
                - "None"
            confirmed_spam_sources:
                description:
                - "None"
            spam_urls:
                description:
                - "None"
            unconfirmed_spam_sources:
                description:
                - "None"
            open_http_proxies:
                description:
                - "None"
            dynamic_comment:
                description:
                - "None"
            parked_domains:
                description:
                - "None"
            alcohol_and_tobacco:
                description:
                - "None"
            private_ip_addresses:
                description:
                - "None"
            image_and_video_search:
                description:
                - "None"
            fashion_and_beauty:
                description:
                - "None"
            recreation_and_hobbies:
                description:
                - "None"
            motor_vehicles:
                description:
                - "None"
            web_hosting_sites:
                description:
                - "None"
            food_and_dining:
                description:
                - "None"
    key:
        description:
        - "None"
        required: False
    key_passphrase:
        description:
        - "None"
        required: False
    key_encrypted:
        description:
        - "None"
        required: False
    template_cipher:
        description:
        - "None"
        required: False
    template_hsm:
        description:
        - "None"
        required: False
    hsm_type:
        description:
        - "None"
        required: False
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "None"
    server_name_list:
        description:
        - "Field server_name_list"
        required: False
        suboptions:
            server_name:
                description:
                - "None"
            server_cert:
                description:
                - "None"
            server_key:
                description:
                - "None"
            server_passphrase:
                description:
                - "None"
            server_encrypted:
                description:
                - "None"
            server_name_regex:
                description:
                - "None"
            server_cert_regex:
                description:
                - "None"
            server_key_regex:
                description:
                - "None"
            server_passphrase_regex:
                description:
                - "None"
            server_encrypted_regex:
                description:
                - "None"
    server_name_auto_map:
        description:
        - "None"
        required: False
    sni_enable_log:
        description:
        - "None"
        required: False
    session_cache_size:
        description:
        - "None"
        required: False
    session_cache_timeout:
        description:
        - "None"
        required: False
    session_ticket_lifetime:
        description:
        - "None"
        required: False
    ssl_false_start_disable:
        description:
        - "None"
        required: False
    disable_sslv3:
        description:
        - "None"
        required: False
    version:
        description:
        - "None"
        required: False
    dgversion:
        description:
        - "None"
        required: False
    renegotiation_disable:
        description:
        - "None"
        required: False
    sslv2_bypass_service_group:
        description:
        - "None"
        required: False
    authorization:
        description:
        - "None"
        required: False
    authen_name:
        description:
        - "None"
        required: False
    ldap_base_dn_from_cert:
        description:
        - "None"
        required: False
    ldap_search_filter:
        description:
        - "None"
        required: False
    auth_sg:
        description:
        - "None"
        required: False
    auth_sg_dn:
        description:
        - "None"
        required: False
    auth_sg_filter:
        description:
        - "None"
        required: False
    auth_username_attribute:
        description:
        - "None"
        required: False
    non_ssl_bypass_service_group:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["alert_type","auth_sg","auth_sg_dn","auth_sg_filter","auth_username","auth_username_attribute","authen_name","authorization","ca_certs","cache_persistence_list_name","case_insensitive","cert","cert_revoke_action","cert_unknown_action","chain_cert","cipher_without_prio_list","class_list_name","client_auth_case_insensitive","client_auth_class_list","client_auth_contains_list","client_auth_ends_with_list","client_auth_equals_list","client_auth_starts_with_list","client_certificate","close_notify","contains_list","crl_certs","dgversion","dh_type","disable_sslv3","ec_list","enable_tls_alert_logging","ends_with_list","equals_list","exception_class_list","expire_hours","forward_encrypted","forward_passphrase","forward_proxy_alt_sign","forward_proxy_ca_cert","forward_proxy_ca_key","forward_proxy_cert_cache_limit","forward_proxy_cert_cache_timeout","forward_proxy_cert_expiry","forward_proxy_cert_not_ready_action","forward_proxy_cert_revoke_action","forward_proxy_cert_unknown_action","forward_proxy_crl_disable","forward_proxy_decrypted_dscp","forward_proxy_decrypted_dscp_bypass","forward_proxy_enable","forward_proxy_failsafe_disable","forward_proxy_log_disable","forward_proxy_ocsp_disable","forward_proxy_selfsign_redir","forward_proxy_ssl_version","forward_proxy_trusted_ca_lists","forward_proxy_verify_cert_fail_action","fp_alt_cert","fp_alt_encrypted","fp_alt_key","fp_alt_passphrase","fp_cert_ext_aia_ca_issuers","fp_cert_ext_aia_ocsp","fp_cert_ext_crldp","fp_cert_fetch_autonat","fp_cert_fetch_autonat_precedence","fp_cert_fetch_natpool_name","fp_cert_fetch_natpool_precedence","handshake_logging_enable","hsm_type","inspect_list_name","key","key_encrypted","key_passphrase","ldap_base_dn_from_cert","ldap_search_filter","local_logging","multi_class_list","name","non_ssl_bypass_service_group","notafter","notafterday","notaftermonth","notafteryear","notbefore","notbeforeday","notbeforemonth","notbeforeyear","ocsp_stapling","ocspst_ca_cert","ocspst_ocsp","ocspst_sg","ocspst_sg_days","ocspst_sg_hours","ocspst_sg_minutes","ocspst_sg_timeout","ocspst_srvr","ocspst_srvr_days","ocspst_srvr_hours","ocspst_srvr_minutes","ocspst_srvr_timeout","renegotiation_disable","req_ca_lists","server_name_auto_map","server_name_list","session_cache_size","session_cache_timeout","session_ticket_lifetime","sni_enable_log","ssl_false_start_disable","ssli_logging","sslilogging","sslv2_bypass_service_group","starts_with_list","template_cipher","template_hsm","user_tag","uuid","verify_cert_fail_action","version","web_category",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        name=dict(type='str',required=True,),
        auth_username=dict(type='str',),
        ca_certs=dict(type='list',ca_cert=dict(type='str',),client_ocsp=dict(type='bool',),client_ocsp_srvr=dict(type='str',),client_ocsp_sg=dict(type='str',)),
        chain_cert=dict(type='str',),
        cert=dict(type='str',),
        dh_type=dict(type='str',choices=['1024','1024-dsa','2048']),
        ec_list=dict(type='list',ec=dict(type='str',choices=['secp256r1','secp384r1'])),
        local_logging=dict(type='bool',),
        ocsp_stapling=dict(type='bool',),
        ocspst_ca_cert=dict(type='str',),
        ocspst_ocsp=dict(type='bool',),
        ocspst_srvr=dict(type='str',),
        ocspst_srvr_days=dict(type='int',),
        ocspst_srvr_hours=dict(type='int',),
        ocspst_srvr_minutes=dict(type='int',),
        ocspst_srvr_timeout=dict(type='int',),
        ocspst_sg=dict(type='str',),
        ocspst_sg_days=dict(type='int',),
        ocspst_sg_hours=dict(type='int',),
        ocspst_sg_minutes=dict(type='int',),
        ocspst_sg_timeout=dict(type='int',),
        ssli_logging=dict(type='bool',),
        sslilogging=dict(type='str',choices=['disable','all']),
        client_certificate=dict(type='str',choices=['Ignore','Require','Request']),
        req_ca_lists=dict(type='list',client_certificate_Request_CA=dict(type='str',)),
        close_notify=dict(type='bool',),
        crl_certs=dict(type='list',crl=dict(type='str',)),
        forward_proxy_ca_cert=dict(type='str',),
        forward_proxy_ca_key=dict(type='str',),
        forward_passphrase=dict(type='str',),
        forward_encrypted=dict(type='str',),
        forward_proxy_alt_sign=dict(type='bool',),
        fp_alt_cert=dict(type='str',),
        fp_alt_key=dict(type='str',),
        fp_alt_passphrase=dict(type='str',),
        fp_alt_encrypted=dict(type='str',),
        forward_proxy_trusted_ca_lists=dict(type='list',forward_proxy_trusted_ca=dict(type='str',)),
        forward_proxy_decrypted_dscp=dict(type='int',),
        forward_proxy_decrypted_dscp_bypass=dict(type='int',),
        enable_tls_alert_logging=dict(type='bool',),
        alert_type=dict(type='str',choices=['fatal']),
        forward_proxy_verify_cert_fail_action=dict(type='bool',),
        verify_cert_fail_action=dict(type='str',choices=['bypass','continue','drop']),
        forward_proxy_cert_revoke_action=dict(type='bool',),
        cert_revoke_action=dict(type='str',choices=['bypass','continue','drop']),
        forward_proxy_cert_unknown_action=dict(type='bool',),
        cert_unknown_action=dict(type='str',choices=['bypass','continue','drop']),
        cache_persistence_list_name=dict(type='str',),
        fp_cert_ext_crldp=dict(type='str',),
        fp_cert_ext_aia_ocsp=dict(type='str',),
        fp_cert_ext_aia_ca_issuers=dict(type='str',),
        notbefore=dict(type='bool',),
        notbeforeday=dict(type='int',),
        notbeforemonth=dict(type='int',),
        notbeforeyear=dict(type='int',),
        notafter=dict(type='bool',),
        notafterday=dict(type='int',),
        notaftermonth=dict(type='int',),
        notafteryear=dict(type='int',),
        forward_proxy_ssl_version=dict(type='int',),
        forward_proxy_ocsp_disable=dict(type='bool',),
        forward_proxy_crl_disable=dict(type='bool',),
        forward_proxy_cert_cache_timeout=dict(type='int',),
        forward_proxy_cert_cache_limit=dict(type='int',),
        forward_proxy_cert_expiry=dict(type='bool',),
        expire_hours=dict(type='int',),
        forward_proxy_enable=dict(type='bool',),
        handshake_logging_enable=dict(type='bool',),
        forward_proxy_selfsign_redir=dict(type='bool',),
        forward_proxy_failsafe_disable=dict(type='bool',),
        forward_proxy_log_disable=dict(type='bool',),
        fp_cert_fetch_natpool_name=dict(type='str',),
        fp_cert_fetch_natpool_precedence=dict(type='bool',),
        fp_cert_fetch_autonat=dict(type='str',choices=['auto']),
        fp_cert_fetch_autonat_precedence=dict(type='bool',),
        case_insensitive=dict(type='bool',),
        class_list_name=dict(type='str',),
        multi_class_list=dict(type='list',multi_clist_name=dict(type='str',)),
        exception_class_list=dict(type='str',),
        inspect_list_name=dict(type='str',),
        contains_list=dict(type='list',contains=dict(type='str',)),
        ends_with_list=dict(type='list',ends_with=dict(type='str',)),
        equals_list=dict(type='list',equals=dict(type='str',)),
        starts_with_list=dict(type='list',starts_with=dict(type='str',)),
        client_auth_case_insensitive=dict(type='bool',),
        client_auth_class_list=dict(type='str',),
        client_auth_contains_list=dict(type='list',client_auth_contains=dict(type='str',)),
        client_auth_ends_with_list=dict(type='list',client_auth_ends_with=dict(type='str',)),
        client_auth_equals_list=dict(type='list',client_auth_equals=dict(type='str',)),
        client_auth_starts_with_list=dict(type='list',client_auth_starts_with=dict(type='str',)),
        forward_proxy_cert_not_ready_action=dict(type='str',choices=['bypass','reset']),
        web_category=dict(type='dict',uncategorized=dict(type='bool',),real_estate=dict(type='bool',),computer_and_internet_security=dict(type='bool',),financial_services=dict(type='bool',),business_and_economy=dict(type='bool',),computer_and_internet_info=dict(type='bool',),auctions=dict(type='bool',),shopping=dict(type='bool',),cult_and_occult=dict(type='bool',),travel=dict(type='bool',),drugs=dict(type='bool',),adult_and_pornography=dict(type='bool',),home_and_garden=dict(type='bool',),military=dict(type='bool',),social_network=dict(type='bool',),dead_sites=dict(type='bool',),stock_advice_and_tools=dict(type='bool',),training_and_tools=dict(type='bool',),dating=dict(type='bool',),sex_education=dict(type='bool',),religion=dict(type='bool',),entertainment_and_arts=dict(type='bool',),personal_sites_and_blogs=dict(type='bool',),legal=dict(type='bool',),local_information=dict(type='bool',),streaming_media=dict(type='bool',),job_search=dict(type='bool',),gambling=dict(type='bool',),translation=dict(type='bool',),reference_and_research=dict(type='bool',),shareware_and_freeware=dict(type='bool',),peer_to_peer=dict(type='bool',),marijuana=dict(type='bool',),hacking=dict(type='bool',),games=dict(type='bool',),philosophy_and_politics=dict(type='bool',),weapons=dict(type='bool',),pay_to_surf=dict(type='bool',),hunting_and_fishing=dict(type='bool',),society=dict(type='bool',),educational_institutions=dict(type='bool',),online_greeting_cards=dict(type='bool',),sports=dict(type='bool',),swimsuits_and_intimate_apparel=dict(type='bool',),questionable=dict(type='bool',),kids=dict(type='bool',),hate_and_racism=dict(type='bool',),personal_storage=dict(type='bool',),violence=dict(type='bool',),keyloggers_and_monitoring=dict(type='bool',),search_engines=dict(type='bool',),internet_portals=dict(type='bool',),web_advertisements=dict(type='bool',),cheating=dict(type='bool',),gross=dict(type='bool',),web_based_email=dict(type='bool',),malware_sites=dict(type='bool',),phishing_and_other_fraud=dict(type='bool',),proxy_avoid_and_anonymizers=dict(type='bool',),spyware_and_adware=dict(type='bool',),music=dict(type='bool',),government=dict(type='bool',),nudity=dict(type='bool',),news_and_media=dict(type='bool',),illegal=dict(type='bool',),cdns=dict(type='bool',),internet_communications=dict(type='bool',),bot_nets=dict(type='bool',),abortion=dict(type='bool',),health_and_medicine=dict(type='bool',),confirmed_spam_sources=dict(type='bool',),spam_urls=dict(type='bool',),unconfirmed_spam_sources=dict(type='bool',),open_http_proxies=dict(type='bool',),dynamic_comment=dict(type='bool',),parked_domains=dict(type='bool',),alcohol_and_tobacco=dict(type='bool',),private_ip_addresses=dict(type='bool',),image_and_video_search=dict(type='bool',),fashion_and_beauty=dict(type='bool',),recreation_and_hobbies=dict(type='bool',),motor_vehicles=dict(type='bool',),web_hosting_sites=dict(type='bool',),food_and_dining=dict(type='bool',)),
        key=dict(type='str',),
        key_passphrase=dict(type='str',),
        key_encrypted=dict(type='str',),
        template_cipher=dict(type='str',),
        template_hsm=dict(type='str',),
        hsm_type=dict(type='str',choices=['thales-embed','thales-hwcrhk']),
        cipher_without_prio_list=dict(type='list',cipher_wo_prio=dict(type='str',choices=['SSL3_RSA_DES_192_CBC3_SHA','SSL3_RSA_RC4_128_MD5','SSL3_RSA_RC4_128_SHA','TLS1_RSA_AES_128_SHA','TLS1_RSA_AES_256_SHA','TLS1_RSA_AES_128_SHA256','TLS1_RSA_AES_256_SHA256','TLS1_DHE_RSA_AES_128_GCM_SHA256','TLS1_DHE_RSA_AES_128_SHA','TLS1_DHE_RSA_AES_128_SHA256','TLS1_DHE_RSA_AES_256_GCM_SHA384','TLS1_DHE_RSA_AES_256_SHA','TLS1_DHE_RSA_AES_256_SHA256','TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256','TLS1_ECDHE_ECDSA_AES_128_SHA','TLS1_ECDHE_ECDSA_AES_128_SHA256','TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA','TLS1_ECDHE_RSA_AES_128_GCM_SHA256','TLS1_ECDHE_RSA_AES_128_SHA','TLS1_ECDHE_RSA_AES_128_SHA256','TLS1_ECDHE_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA','TLS1_RSA_AES_128_GCM_SHA256','TLS1_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA384'])),
        server_name_list=dict(type='list',server_name=dict(type='str',),server_cert=dict(type='str',),server_key=dict(type='str',),server_passphrase=dict(type='str',),server_encrypted=dict(type='str',),server_name_regex=dict(type='str',),server_cert_regex=dict(type='str',),server_key_regex=dict(type='str',),server_passphrase_regex=dict(type='str',),server_encrypted_regex=dict(type='str',)),
        server_name_auto_map=dict(type='bool',),
        sni_enable_log=dict(type='bool',),
        session_cache_size=dict(type='int',),
        session_cache_timeout=dict(type='int',),
        session_ticket_lifetime=dict(type='int',),
        ssl_false_start_disable=dict(type='bool',),
        disable_sslv3=dict(type='bool',),
        version=dict(type='int',),
        dgversion=dict(type='int',),
        renegotiation_disable=dict(type='bool',),
        sslv2_bypass_service_group=dict(type='str',),
        authorization=dict(type='bool',),
        authen_name=dict(type='str',),
        ldap_base_dn_from_cert=dict(type='bool',),
        ldap_search_filter=dict(type='str',),
        auth_sg=dict(type='str',),
        auth_sg_dn=dict(type='bool',),
        auth_sg_filter=dict(type='str',),
        auth_username_attribute=dict(type='str',),
        non_ssl_bypass_service_group=dict(type='str',),
        uuid=dict(type='str',),
        user_tag=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/client-ssl/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/client-ssl/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("client-ssl", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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

def update(module, result):
    payload = build_json("client-ssl", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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