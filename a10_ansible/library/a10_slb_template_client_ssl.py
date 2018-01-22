#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_client-ssl
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Client SSL Template Name
    
    auth-username:
        description:
            - Specify the Username Field in the Client Certificate(If multi-fields are specificed, prior one has higher priority)
    
    ca-certs:
        
    
    chain-cert:
        description:
            - Chain Certificate (Chain Certificate Name)
    
    cert:
        description:
            - Server Certificate (Certificate Name)
    
    dh-type:
        description:
            - '1024': 1024; '1024-dsa': 1024-dsa; '2048': 2048; choices:['1024', '1024-dsa', '2048']
    
    ec-list:
        
    
    local-logging:
        description:
            - Enable local logging
    
    ocsp-stapling:
        description:
            - Config OCSP stapling support
    
    ocspst-ca-cert:
        description:
            - CA certificate
    
    ocspst-ocsp:
        description:
            - Specify OCSP Authentication
    
    ocspst-srvr:
        description:
            - Specify OCSP authentication server
    
    ocspst-srvr-days:
        description:
            - Specify update period, in days
    
    ocspst-srvr-hours:
        description:
            - Specify update period, in hours
    
    ocspst-srvr-minutes:
        description:
            - Specify update period, in minutes
    
    ocspst-srvr-timeout:
        description:
            - Specify retry timeout (Default is 30 mins)
    
    ocspst-sg:
        description:
            - Specify authentication service group
    
    ocspst-sg-days:
        description:
            - Specify update period, in days
    
    ocspst-sg-hours:
        description:
            - Specify update period, in hours
    
    ocspst-sg-minutes:
        description:
            - Specify update period, in minutes
    
    ocspst-sg-timeout:
        description:
            - Specify retry timeout (Default is 30 mins)
    
    ssli-logging:
        description:
            - SSLi logging level, default is error logging only
    
    sslilogging:
        description:
            - 'disable': Disable all logging; 'all': enable all logging(error, info); choices:['disable', 'all']
    
    client-certificate:
        description:
            - 'Ignore': Don't request client certificate; 'Require': Require client certificate; 'Request': Request client certificate; choices:['Ignore', 'Require', 'Request']
    
    req-ca-lists:
        
    
    close-notify:
        description:
            - Send close notification when terminate connection
    
    crl-certs:
        
    
    forward-proxy-ca-cert:
        description:
            - CA Certificate for forward proxy (SSL forward proxy CA Certificate Name)
    
    forward-proxy-ca-key:
        description:
            - CA Private Key for forward proxy (SSL forward proxy CA Key Name)
    
    forward-passphrase:
        description:
            - Password Phrase
    
    forward-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)
    
    forward-proxy-alt-sign:
        description:
            - Forward proxy alternate signing cert and key
    
    fp-alt-cert:
        description:
            - CA Certificate for forward proxy alternate signing (Certificate name)
    
    fp-alt-key:
        description:
            - CA Private Key for forward proxy alternate signing (Key name)
    
    fp-alt-passphrase:
        description:
            - Password Phrase
    
    fp-alt-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)
    
    forward-proxy-trusted-ca-lists:
        
    
    forward-proxy-decrypted-dscp:
        description:
            - Apply a DSCP to decrypted and bypassed traffic (DSCP to apply to decrypted traffic)
    
    forward-proxy-decrypted-dscp-bypass:
        description:
            - DSCP to apply to bypassed traffic
    
    enable-tls-alert-logging:
        description:
            - Enable TLS alert logging
    
    alert-type:
        description:
            - 'fatal': Log fatal alerts; choices:['fatal']
    
    forward-proxy-verify-cert-fail-action:
        description:
            - Action taken if certificate verification fails, close the connection by default
    
    verify-cert-fail-action:
        description:
            - 'bypass': bypass SSLi processing; 'continue': continue the connection; 'drop': close the connection; choices:['bypass', 'continue', 'drop']
    
    forward-proxy-cert-revoke-action:
        description:
            - Action taken if a certificate is irreversibly revoked, bypass SSLi processing by default
    
    cert-revoke-action:
        description:
            - 'bypass': bypass SSLi processing; 'continue': continue the connection; 'drop': close the connection; choices:['bypass', 'continue', 'drop']
    
    forward-proxy-cert-unknown-action:
        description:
            - Action taken if a certificate revocation status is unknown, bypass SSLi processing by default
    
    cert-unknown-action:
        description:
            - 'bypass': bypass SSLi processing; 'continue': continue the connection; 'drop': close the connection; choices:['bypass', 'continue', 'drop']
    
    cache-persistence-list-name:
        description:
            - Class List Name
    
    fp-cert-ext-crldp:
        description:
            - CRL Distribution Point (CRL Distribution Point URI)
    
    fp-cert-ext-aia-ocsp:
        description:
            - OCSP (Authority Information Access URI)
    
    fp-cert-ext-aia-ca-issuers:
        description:
            - CA Issuers (Authority Information Access URI)
    
    notbefore:
        description:
            - notBefore date
    
    notbeforeday:
        description:
            - Day
    
    notbeforemonth:
        description:
            - Month
    
    notbeforeyear:
        description:
            - Year
    
    notafter:
        description:
            - notAfter date
    
    notafterday:
        description:
            - Day
    
    notaftermonth:
        description:
            - Month
    
    notafteryear:
        description:
            - Year
    
    forward-proxy-ssl-version:
        description:
            - TLS/SSL version, default is TLS1.2 (TLS/SSL version: 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)
    
    forward-proxy-ocsp-disable:
        description:
            - Disable ocsp-stapling for forward proxy
    
    forward-proxy-crl-disable:
        description:
            - Disable Certificate Revocation List checking for forward proxy
    
    forward-proxy-cert-cache-timeout:
        description:
            - Certificate cache timeout, default is 1 hour (seconds, set to 0 for never timeout)
    
    forward-proxy-cert-cache-limit:
        description:
            - Certificate cache size limit, default is 524288 (set to 0 for unlimited size)
    
    forward-proxy-cert-expiry:
        description:
            - Adjust certificate expiry relative to the time when it is created on the device
    
    expire-hours:
        description:
            - Certificate lifetime in hours
    
    forward-proxy-enable:
        description:
            - Enable SSL forward proxy
    
    handshake-logging-enable:
        description:
            - Enable SSL handshake logging
    
    forward-proxy-selfsign-redir:
        description:
            - Redirect connections to pages with self signed certs to a warning page
    
    forward-proxy-failsafe-disable:
        description:
            - Disable Failsafe for SSL forward proxy
    
    forward-proxy-log-disable:
        description:
            - Disable SSL forward proxy logging
    
    fp-cert-fetch-natpool-name:
        description:
            - Specify NAT pool or pool group
    
    fp-cert-fetch-natpool-precedence:
        description:
            - Set this NAT pool as higher precedence than other source NAT like configued under template policy
    
    fp-cert-fetch-autonat:
        description:
            - 'auto': Configure auto NAT for server certificate fetching; choices:['auto']
    
    fp-cert-fetch-autonat-precedence:
        description:
            - Set this NAT pool as higher precedence than other source NAT like configued under template policy
    
    case-insensitive:
        description:
            - Case insensitive forward proxy bypass
    
    class-list-name:
        description:
            - Class List Name
    
    multi-class-list:
        
    
    exception-class-list:
        description:
            - Exceptions to forward-proxy-bypass
    
    inspect-list-name:
        description:
            - Class List Name
    
    contains-list:
        
    
    ends-with-list:
        
    
    equals-list:
        
    
    starts-with-list:
        
    
    client-auth-case-insensitive:
        description:
            - Case insensitive forward proxy client auth bypass
    
    client-auth-class-list:
        description:
            - Forward proxy client auth bypass if SNI string matches class-list (Class List Name)
    
    client-auth-contains-list:
        
    
    client-auth-ends-with-list:
        
    
    client-auth-equals-list:
        
    
    client-auth-starts-with-list:
        
    
    forward-proxy-cert-not-ready-action:
        description:
            - 'bypass': bypass the connection; 'reset': reset the connection; choices:['bypass', 'reset']
    
    web-category:
        
    
    key:
        description:
            - Server Private Key (Key Name)
    
    key-passphrase:
        description:
            - Password Phrase
    
    key-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)
    
    template-cipher:
        description:
            - Cipher Template (Cipher Config Name)
    
    template-hsm:
        description:
            - HSM Template (HSM Template Name)
    
    hsm-type:
        description:
            - 'thales-embed': Thales embed key; 'thales-hwcrhk': Thales hwcrhk Key; choices:['thales-embed', 'thales-hwcrhk']
    
    cipher-without-prio-list:
        
    
    server-name-list:
        
    
    server-name-auto-map:
        description:
            - Enable automatic mapping of server name indication in Client hello extension
    
    sni-enable-log:
        description:
            - Enable logging of sni-auto-map failures. Disable by default
    
    session-cache-size:
        description:
            - Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse disabled))
    
    session-cache-timeout:
        description:
            - Session Cache Timeout (Timeout value, in seconds. Default value 0 (Session cache timeout disabled))
    
    session-ticket-lifetime:
        description:
            - Session ticket lifetime in seconds from stateless session resumption (Lifetime value in seconds. Default value 0 (Session ticket lifetime limit disabled))
    
    ssl-false-start-disable:
        description:
            - disable SSL False Start
    
    disable-sslv3:
        description:
            - Reject Client requests for SSL version 3
    
    version:
        description:
            - TLS/SSL version, default is the highest number supported (TLS/SSL version: 30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)
    
    dgversion:
        description:
            - Lower TLS/SSL version can be downgraded
    
    renegotiation-disable:
        description:
            - Disable SSL renegotiation
    
    sslv2-bypass-service-group:
        description:
            - Service Group for Bypass SSLV2 (Service Group Name)
    
    authorization:
        description:
            - Specify LDAP server for client SSL authorizaiton
    
    authen-name:
        description:
            - Specify authorization LDAP server name
    
    ldap-base-dn-from-cert:
        description:
            - Use Subject DN as LDAP search base DN
    
    ldap-search-filter:
        description:
            - Specify LDAP search filter
    
    auth-sg:
        description:
            - Specify authorization LDAP service group
    
    auth-sg-dn:
        description:
            - Use Subject DN as LDAP search base DN
    
    auth-sg-filter:
        description:
            - Specify LDAP search filter
    
    auth-username-attribute:
        description:
            - Specify attribute name of username for client SSL authorization
    
    non-ssl-bypass-service-group:
        description:
            - Service Group for Bypass non-ssl traffic (Service Group Name)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"alert_type","auth_sg","auth_sg_dn","auth_sg_filter","auth_username","auth_username_attribute","authen_name","authorization","ca_certs","cache_persistence_list_name","case_insensitive","cert","cert_revoke_action","cert_unknown_action","chain_cert","cipher_without_prio_list","class_list_name","client_auth_case_insensitive","client_auth_class_list","client_auth_contains_list","client_auth_ends_with_list","client_auth_equals_list","client_auth_starts_with_list","client_certificate","close_notify","contains_list","crl_certs","dgversion","dh_type","disable_sslv3","ec_list","enable_tls_alert_logging","ends_with_list","equals_list","exception_class_list","expire_hours","forward_encrypted","forward_passphrase","forward_proxy_alt_sign","forward_proxy_ca_cert","forward_proxy_ca_key","forward_proxy_cert_cache_limit","forward_proxy_cert_cache_timeout","forward_proxy_cert_expiry","forward_proxy_cert_not_ready_action","forward_proxy_cert_revoke_action","forward_proxy_cert_unknown_action","forward_proxy_crl_disable","forward_proxy_decrypted_dscp","forward_proxy_decrypted_dscp_bypass","forward_proxy_enable","forward_proxy_failsafe_disable","forward_proxy_log_disable","forward_proxy_ocsp_disable","forward_proxy_selfsign_redir","forward_proxy_ssl_version","forward_proxy_trusted_ca_lists","forward_proxy_verify_cert_fail_action","fp_alt_cert","fp_alt_encrypted","fp_alt_key","fp_alt_passphrase","fp_cert_ext_aia_ca_issuers","fp_cert_ext_aia_ocsp","fp_cert_ext_crldp","fp_cert_fetch_autonat","fp_cert_fetch_autonat_precedence","fp_cert_fetch_natpool_name","fp_cert_fetch_natpool_precedence","handshake_logging_enable","hsm_type","inspect_list_name","key","key_encrypted","key_passphrase","ldap_base_dn_from_cert","ldap_search_filter","local_logging","multi_class_list","name","non_ssl_bypass_service_group","notafter","notafterday","notaftermonth","notafteryear","notbefore","notbeforeday","notbeforemonth","notbeforeyear","ocsp_stapling","ocspst_ca_cert","ocspst_ocsp","ocspst_sg","ocspst_sg_days","ocspst_sg_hours","ocspst_sg_minutes","ocspst_sg_timeout","ocspst_srvr","ocspst_srvr_days","ocspst_srvr_hours","ocspst_srvr_minutes","ocspst_srvr_timeout","renegotiation_disable","req_ca_lists","server_name_auto_map","server_name_list","session_cache_size","session_cache_timeout","session_ticket_lifetime","sni_enable_log","ssl_false_start_disable","ssli_logging","sslilogging","sslv2_bypass_service_group","starts_with_list","template_cipher","template_hsm","user_tag","uuid","verify_cert_fail_action","version","web_category",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

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
        
        alert_type=dict(
            type='enum' , choices=['fatal']
        ),
        auth_sg=dict(
            type='str' 
        ),
        auth_sg_dn=dict(
            type='str' 
        ),
        auth_sg_filter=dict(
            type='str' 
        ),
        auth_username=dict(
            type='str' 
        ),
        auth_username_attribute=dict(
            type='str' 
        ),
        authen_name=dict(
            type='str' 
        ),
        authorization=dict(
            type='str' 
        ),
        ca_certs=dict(
            type='str' 
        ),
        cache_persistence_list_name=dict(
            type='str' 
        ),
        case_insensitive=dict(
            type='str' 
        ),
        cert=dict(
            type='str' 
        ),
        cert_revoke_action=dict(
            type='enum' , choices=['bypass', 'continue', 'drop']
        ),
        cert_unknown_action=dict(
            type='enum' , choices=['bypass', 'continue', 'drop']
        ),
        chain_cert=dict(
            type='str' 
        ),
        cipher_without_prio_list=dict(
            type='str' 
        ),
        class_list_name=dict(
            type='str' 
        ),
        client_auth_case_insensitive=dict(
            type='str' 
        ),
        client_auth_class_list=dict(
            type='str' 
        ),
        client_auth_contains_list=dict(
            type='str' 
        ),
        client_auth_ends_with_list=dict(
            type='str' 
        ),
        client_auth_equals_list=dict(
            type='str' 
        ),
        client_auth_starts_with_list=dict(
            type='str' 
        ),
        client_certificate=dict(
            type='enum' , choices=['Ignore', 'Require', 'Request']
        ),
        close_notify=dict(
            type='str' 
        ),
        contains_list=dict(
            type='str' 
        ),
        crl_certs=dict(
            type='str' 
        ),
        dgversion=dict(
            type='str' 
        ),
        dh_type=dict(
            type='enum' , choices=['1024', '1024-dsa', '2048']
        ),
        disable_sslv3=dict(
            type='str' 
        ),
        ec_list=dict(
            type='str' 
        ),
        enable_tls_alert_logging=dict(
            type='str' 
        ),
        ends_with_list=dict(
            type='str' 
        ),
        equals_list=dict(
            type='str' 
        ),
        exception_class_list=dict(
            type='str' 
        ),
        expire_hours=dict(
            type='str' 
        ),
        forward_encrypted=dict(
            type='str' 
        ),
        forward_passphrase=dict(
            type='str' 
        ),
        forward_proxy_alt_sign=dict(
            type='str' 
        ),
        forward_proxy_ca_cert=dict(
            type='str' 
        ),
        forward_proxy_ca_key=dict(
            type='str' 
        ),
        forward_proxy_cert_cache_limit=dict(
            type='str' 
        ),
        forward_proxy_cert_cache_timeout=dict(
            type='str' 
        ),
        forward_proxy_cert_expiry=dict(
            type='str' 
        ),
        forward_proxy_cert_not_ready_action=dict(
            type='enum' , choices=['bypass', 'reset']
        ),
        forward_proxy_cert_revoke_action=dict(
            type='str' 
        ),
        forward_proxy_cert_unknown_action=dict(
            type='str' 
        ),
        forward_proxy_crl_disable=dict(
            type='str' 
        ),
        forward_proxy_decrypted_dscp=dict(
            type='str' 
        ),
        forward_proxy_decrypted_dscp_bypass=dict(
            type='str' 
        ),
        forward_proxy_enable=dict(
            type='str' 
        ),
        forward_proxy_failsafe_disable=dict(
            type='str' 
        ),
        forward_proxy_log_disable=dict(
            type='str' 
        ),
        forward_proxy_ocsp_disable=dict(
            type='str' 
        ),
        forward_proxy_selfsign_redir=dict(
            type='str' 
        ),
        forward_proxy_ssl_version=dict(
            type='str' 
        ),
        forward_proxy_trusted_ca_lists=dict(
            type='str' 
        ),
        forward_proxy_verify_cert_fail_action=dict(
            type='str' 
        ),
        fp_alt_cert=dict(
            type='str' 
        ),
        fp_alt_encrypted=dict(
            type='str' 
        ),
        fp_alt_key=dict(
            type='str' 
        ),
        fp_alt_passphrase=dict(
            type='str' 
        ),
        fp_cert_ext_aia_ca_issuers=dict(
            type='str' 
        ),
        fp_cert_ext_aia_ocsp=dict(
            type='str' 
        ),
        fp_cert_ext_crldp=dict(
            type='str' 
        ),
        fp_cert_fetch_autonat=dict(
            type='enum' , choices=['auto']
        ),
        fp_cert_fetch_autonat_precedence=dict(
            type='str' 
        ),
        fp_cert_fetch_natpool_name=dict(
            type='str' 
        ),
        fp_cert_fetch_natpool_precedence=dict(
            type='str' 
        ),
        handshake_logging_enable=dict(
            type='str' 
        ),
        hsm_type=dict(
            type='enum' , choices=['thales-embed', 'thales-hwcrhk']
        ),
        inspect_list_name=dict(
            type='str' 
        ),
        key=dict(
            type='str' 
        ),
        key_encrypted=dict(
            type='str' 
        ),
        key_passphrase=dict(
            type='str' 
        ),
        ldap_base_dn_from_cert=dict(
            type='str' 
        ),
        ldap_search_filter=dict(
            type='str' 
        ),
        local_logging=dict(
            type='str' 
        ),
        multi_class_list=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        non_ssl_bypass_service_group=dict(
            type='str' 
        ),
        notafter=dict(
            type='str' 
        ),
        notafterday=dict(
            type='str' 
        ),
        notaftermonth=dict(
            type='str' 
        ),
        notafteryear=dict(
            type='str' 
        ),
        notbefore=dict(
            type='str' 
        ),
        notbeforeday=dict(
            type='str' 
        ),
        notbeforemonth=dict(
            type='str' 
        ),
        notbeforeyear=dict(
            type='str' 
        ),
        ocsp_stapling=dict(
            type='str' 
        ),
        ocspst_ca_cert=dict(
            type='str' 
        ),
        ocspst_ocsp=dict(
            type='str' 
        ),
        ocspst_sg=dict(
            type='str' 
        ),
        ocspst_sg_days=dict(
            type='str' 
        ),
        ocspst_sg_hours=dict(
            type='str' 
        ),
        ocspst_sg_minutes=dict(
            type='str' 
        ),
        ocspst_sg_timeout=dict(
            type='str' 
        ),
        ocspst_srvr=dict(
            type='str' 
        ),
        ocspst_srvr_days=dict(
            type='str' 
        ),
        ocspst_srvr_hours=dict(
            type='str' 
        ),
        ocspst_srvr_minutes=dict(
            type='str' 
        ),
        ocspst_srvr_timeout=dict(
            type='str' 
        ),
        renegotiation_disable=dict(
            type='str' 
        ),
        req_ca_lists=dict(
            type='str' 
        ),
        server_name_auto_map=dict(
            type='str' 
        ),
        server_name_list=dict(
            type='str' 
        ),
        session_cache_size=dict(
            type='str' 
        ),
        session_cache_timeout=dict(
            type='str' 
        ),
        session_ticket_lifetime=dict(
            type='str' 
        ),
        sni_enable_log=dict(
            type='str' 
        ),
        ssl_false_start_disable=dict(
            type='str' 
        ),
        ssli_logging=dict(
            type='str' 
        ),
        sslilogging=dict(
            type='enum' , choices=['disable', 'all']
        ),
        sslv2_bypass_service_group=dict(
            type='str' 
        ),
        starts_with_list=dict(
            type='str' 
        ),
        template_cipher=dict(
            type='str' 
        ),
        template_hsm=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        verify_cert_fail_action=dict(
            type='enum' , choices=['bypass', 'continue', 'drop']
        ),
        version=dict(
            type='str' 
        ),
        web_category=dict(
            type='str' 
        ), 
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

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
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