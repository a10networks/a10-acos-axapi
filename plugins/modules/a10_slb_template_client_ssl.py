#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_client_ssl
description:
    - Client SSL Template
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
    name:
        description:
        - "Client SSL Template Name"
        type: str
        required: True
    auth_username:
        description:
        - "Specify the Username Field in the Client Certificate(If multi-fields are
          specificed, prior one has higher priority)"
        type: str
        required: False
    ca_certs:
        description:
        - "Field ca_certs"
        type: list
        required: False
        suboptions:
            ca_cert:
                description:
                - "CA Certificate (CA Certificate Name)"
                type: str
            ca_shared:
                description:
                - "CA Certificate Partition Shared"
                type: bool
            client_ocsp:
                description:
                - "Specify ocsp authentication server(s) for client certificate verification"
                type: bool
            client_ocsp_srvr:
                description:
                - "Specify authentication server"
                type: str
            client_ocsp_sg:
                description:
                - "Specify service-group (Service group name)"
                type: str
    chain_cert:
        description:
        - "Chain Certificate Name"
        type: str
        required: False
    chain_cert_shared_str:
        description:
        - "Chain Certificate Name"
        type: str
        required: False
    dh_type:
        description:
        - "'1024'= 1024; '1024-dsa'= 1024-dsa; '2048'= 2048;"
        type: str
        required: False
    ec_list:
        description:
        - "Field ec_list"
        type: list
        required: False
        suboptions:
            ec:
                description:
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1; 'secp521r1'= secp521r1;
          'x25519'= x25519;"
                type: str
    local_logging:
        description:
        - "Enable local logging"
        type: bool
        required: False
    ocsp_stapling:
        description:
        - "Config OCSP stapling support"
        type: bool
        required: False
    ocspst_ca_cert:
        description:
        - "CA certificate"
        type: str
        required: False
    ocspst_ocsp:
        description:
        - "Specify OCSP Authentication"
        type: bool
        required: False
    ocspst_srvr:
        description:
        - "Specify OCSP authentication server"
        type: str
        required: False
    ocspst_srvr_days:
        description:
        - "Specify update period, in days"
        type: int
        required: False
    ocspst_srvr_hours:
        description:
        - "Specify update period, in hours"
        type: int
        required: False
    ocspst_srvr_minutes:
        description:
        - "Specify update period, in minutes"
        type: int
        required: False
    ocspst_srvr_timeout:
        description:
        - "Specify retry timeout (Default is 30 mins)"
        type: int
        required: False
    ocspst_sg:
        description:
        - "Specify authentication service group"
        type: str
        required: False
    ocspst_sg_days:
        description:
        - "Specify update period, in days"
        type: int
        required: False
    ocspst_sg_hours:
        description:
        - "Specify update period, in hours"
        type: int
        required: False
    ocspst_sg_minutes:
        description:
        - "Specify update period, in minutes"
        type: int
        required: False
    ocspst_sg_timeout:
        description:
        - "Specify retry timeout (Default is 30 mins)"
        type: int
        required: False
    ssli_inbound_enable:
        description:
        - "Enable inbound SSLi"
        type: bool
        required: False
    ssli_logging:
        description:
        - "SSLi logging level, default is error logging only"
        type: bool
        required: False
    sslilogging:
        description:
        - "'disable'= Disable all logging; 'all'= enable all logging(error, info);"
        type: str
        required: False
    client_certificate:
        description:
        - "'Ignore'= Don't request client certificate; 'Require'= Require client
          certificate; 'Request'= Request client certificate;"
        type: str
        required: False
    req_ca_lists:
        description:
        - "Field req_ca_lists"
        type: list
        required: False
        suboptions:
            client_certificate_Request_CA:
                description:
                - "Send CA lists in certificate request (CA Certificate Name)"
                type: str
            client_cert_req_ca_shared:
                description:
                - "CA Certificate Partition Shared"
                type: bool
    close_notify:
        description:
        - "Send close notification when terminate connection"
        type: bool
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        type: list
        required: False
        suboptions:
            crl:
                description:
                - "Certificate Revocation Lists (Certificate Revocation Lists file name)"
                type: str
            crl_shared:
                description:
                - "Certificate Revocation Lists Partition Shared"
                type: bool
    forward_proxy_ca_cert:
        description:
        - "CA Certificate for forward proxy (SSL forward proxy CA Certificate Name)"
        type: str
        required: False
    fp_ca_shared:
        description:
        - "CA Certificate Partition Shared"
        type: bool
        required: False
    forward_proxy_ca_key:
        description:
        - "CA Private Key for forward proxy (SSL forward proxy CA Key Name)"
        type: str
        required: False
    forward_passphrase:
        description:
        - "Password Phrase"
        type: str
        required: False
    forward_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
    fp_ca_key_shared:
        description:
        - "CA Private Key Partition Shared"
        type: bool
        required: False
    fp_ca_certificate:
        description:
        - "CA Certificate for forward proxy (SSL forward proxy CA Certificate Name)"
        type: str
        required: False
    fp_ca_key:
        description:
        - "CA Private Key for forward proxy (SSL forward proxy CA Key Name)"
        type: str
        required: False
    fp_ca_key_passphrase:
        description:
        - "Password Phrase"
        type: str
        required: False
    fp_ca_key_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
    fp_ca_chain_cert:
        description:
        - "Chain Certificate (Chain Certificate Name)"
        type: str
        required: False
    fp_ca_certificate_shared:
        description:
        - "CA Private Key Partition Shared"
        type: bool
        required: False
    forward_proxy_alt_sign:
        description:
        - "Forward proxy alternate signing cert and key"
        type: bool
        required: False
    fp_alt_cert:
        description:
        - "CA Certificate for forward proxy alternate signing (Certificate name)"
        type: str
        required: False
    fp_alt_key:
        description:
        - "CA Private Key for forward proxy alternate signing (Key name)"
        type: str
        required: False
    fp_alt_passphrase:
        description:
        - "Password Phrase"
        type: str
        required: False
    fp_alt_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
    fp_alt_chain_cert:
        description:
        - "Chain Certificate (Chain Certificate Name)"
        type: str
        required: False
    fp_alt_shared:
        description:
        - "Alternate CA Certificate and Private Key Partition Shared"
        type: bool
        required: False
    forward_proxy_trusted_ca_lists:
        description:
        - "Field forward_proxy_trusted_ca_lists"
        type: list
        required: False
        suboptions:
            forward_proxy_trusted_ca:
                description:
                - "Forward proxy trusted CA file (CA file name)"
                type: str
            fp_trusted_ca_shared:
                description:
                - "Trusted CA Certificate Partition Shared"
                type: bool
    forward_proxy_decrypted_dscp:
        description:
        - "Apply a DSCP to decrypted and bypassed traffic (DSCP to apply to decrypted
          traffic)"
        type: int
        required: False
    forward_proxy_decrypted_dscp_bypass:
        description:
        - "DSCP to apply to bypassed traffic"
        type: int
        required: False
    enable_tls_alert_logging:
        description:
        - "Enable TLS alert logging"
        type: bool
        required: False
    alert_type:
        description:
        - "'fatal'= Log fatal alerts;"
        type: str
        required: False
    forward_proxy_verify_cert_fail_action:
        description:
        - "Action taken if certificate verification fails, close the connection by default"
        type: bool
        required: False
    verify_cert_fail_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        type: str
        required: False
    forward_proxy_cert_revoke_action:
        description:
        - "Action taken if a certificate is irreversibly revoked, bypass SSLi processing
          by default"
        type: bool
        required: False
    cert_revoke_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        type: str
        required: False
    forward_proxy_no_shared_cipher_action:
        description:
        - "Action taken if handshake fails due to no shared ciper, close the connection by
          default"
        type: bool
        required: False
    no_shared_cipher_action:
        description:
        - "'bypass'= bypass SSLi processing; 'drop'= close the connection;"
        type: str
        required: False
    forward_proxy_esni_action:
        description:
        - "Action taken if receiving encrypted server name indication extension in client
          hello MSG, bypass the connection by default"
        type: bool
        required: False
    fp_esni_action:
        description:
        - "'bypass'= bypass SSLi processing; 'drop'= close the connection;"
        type: str
        required: False
    forward_proxy_cert_unknown_action:
        description:
        - "Action taken if a certificate revocation status is unknown, bypass SSLi
          processing by default"
        type: bool
        required: False
    cert_unknown_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        type: str
        required: False
    forward_proxy_block_message:
        description:
        - "Message to be included on the block page (Message, enclose in quotes if spaces
          are present)"
        type: str
        required: False
    cache_persistence_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    fp_cert_ext_crldp:
        description:
        - "CRL Distribution Point (CRL Distribution Point URI)"
        type: str
        required: False
    fp_cert_ext_aia_ocsp:
        description:
        - "OCSP (Authority Information Access URI)"
        type: str
        required: False
    fp_cert_ext_aia_ca_issuers:
        description:
        - "CA Issuers (Authority Information Access URI)"
        type: str
        required: False
    notbefore:
        description:
        - "notBefore date"
        type: bool
        required: False
    notbeforeday:
        description:
        - "Day"
        type: int
        required: False
    notbeforemonth:
        description:
        - "Month"
        type: int
        required: False
    notbeforeyear:
        description:
        - "Year"
        type: int
        required: False
    notafter:
        description:
        - "notAfter date"
        type: bool
        required: False
    notafterday:
        description:
        - "Day"
        type: int
        required: False
    notaftermonth:
        description:
        - "Month"
        type: int
        required: False
    notafteryear:
        description:
        - "Year"
        type: int
        required: False
    forward_proxy_hash_persistence_interval:
        description:
        - "Set the time interval to save the hash persistence certs (Interval value, in
          minutes)"
        type: int
        required: False
    forward_proxy_ssl_version:
        description:
        - "TLS/SSL version, default is TLS1.2 (TLS/SSL version= 31-TLSv1.0, 32-TLSv1.1,
          33-TLSv1.2 and 34-TLSv1.3)"
        type: int
        required: False
    forward_proxy_ocsp_disable:
        description:
        - "Disable ocsp-stapling for forward proxy"
        type: bool
        required: False
    forward_proxy_crl_disable:
        description:
        - "Disable Certificate Revocation List checking for forward proxy"
        type: bool
        required: False
    forward_proxy_cert_cache_timeout:
        description:
        - "Certificate cache timeout, default is 1 hour (seconds, set to 0 for never
          timeout)"
        type: int
        required: False
    forward_proxy_cert_cache_limit:
        description:
        - "Certificate cache size limit, default is 524288 (set to 0 for unlimited size)"
        type: int
        required: False
    forward_proxy_cert_expiry:
        description:
        - "Adjust certificate expiry relative to the time when it is created on the device"
        type: bool
        required: False
    expire_hours:
        description:
        - "Certificate lifetime in hours"
        type: int
        required: False
    forward_proxy_enable:
        description:
        - "Enable SSL forward proxy"
        type: bool
        required: False
    handshake_logging_enable:
        description:
        - "Enable SSL handshake logging"
        type: bool
        required: False
    session_key_logging_enable:
        description:
        - "Enable SSL session key logging"
        type: bool
        required: False
    forward_proxy_selfsign_redir:
        description:
        - "Redirect connections to pages with self signed certs to a warning page"
        type: bool
        required: False
    forward_proxy_failsafe_disable:
        description:
        - "Disable Failsafe for SSL forward proxy"
        type: bool
        required: False
    forward_proxy_log_disable:
        description:
        - "Disable SSL forward proxy logging"
        type: bool
        required: False
    fp_cert_fetch_natpool_name:
        description:
        - "Specify NAT pool or pool group"
        type: str
        required: False
    shared_partition_pool:
        description:
        - "Reference a NAT pool or pool group from shared partition"
        type: bool
        required: False
    fp_cert_fetch_natpool_name_shared:
        description:
        - "Specify NAT pool or pool group"
        type: str
        required: False
    fp_cert_fetch_natpool_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued
          under template policy"
        type: bool
        required: False
    fp_cert_fetch_autonat:
        description:
        - "'auto'= Configure auto NAT for server certificate fetching;"
        type: str
        required: False
    fp_cert_fetch_autonat_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued
          under template policy"
        type: bool
        required: False
    forward_proxy_no_sni_action:
        description:
        - "'intercept'= intercept in no SNI case; 'bypass'= bypass in no SNI case;
          'reset'= reset in no SNI case;"
        type: str
        required: False
    case_insensitive:
        description:
        - "Case insensitive forward proxy bypass"
        type: bool
        required: False
    class_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    multi_class_list:
        description:
        - "Field multi_class_list"
        type: list
        required: False
        suboptions:
            multi_clist_name:
                description:
                - "Class List Name"
                type: str
    user_name_list:
        description:
        - "Forward proxy bypass if user-name matches class-list"
        type: str
        required: False
    ad_group_list:
        description:
        - "Forward proxy bypass if ad-group matches class-list"
        type: str
        required: False
    exception_user_name_list:
        description:
        - "Exceptions to forward proxy bypass if user-name matches class-list"
        type: str
        required: False
    exception_ad_group_list:
        description:
        - "Exceptions to forward proxy bypass if ad-group matches class-list"
        type: str
        required: False
    exception_sni_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        type: str
        required: False
    inspect_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    inspect_certificate_subject_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject matches class-list"
        type: str
        required: False
    inspect_certificate_issuer_cl_name:
        description:
        - "Forward proxy Inspect if Certificate issuer matches class-list"
        type: str
        required: False
    inspect_certificate_san_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject Alternative Name matches class-
          list"
        type: str
        required: False
    contains_list:
        description:
        - "Field contains_list"
        type: list
        required: False
        suboptions:
            contains:
                description:
                - "Forward proxy bypass if SNI string contains another string"
                type: str
    ends_with_list:
        description:
        - "Field ends_with_list"
        type: list
        required: False
        suboptions:
            ends_with:
                description:
                - "Forward proxy bypass if SNI string ends with another string"
                type: str
    equals_list:
        description:
        - "Field equals_list"
        type: list
        required: False
        suboptions:
            equals:
                description:
                - "Forward proxy bypass if SNI string equals another string"
                type: str
    starts_with_list:
        description:
        - "Field starts_with_list"
        type: list
        required: False
        suboptions:
            starts_with:
                description:
                - "Forward proxy bypass if SNI string starts with another string"
                type: str
    certificate_subject_contains_list:
        description:
        - "Field certificate_subject_contains_list"
        type: list
        required: False
        suboptions:
            certificate_subject_contains:
                description:
                - "Forward proxy bypass if Certificate Subject contains another string"
                type: str
    bypass_cert_subject_class_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    bypass_cert_subject_multi_class_list:
        description:
        - "Field bypass_cert_subject_multi_class_list"
        type: list
        required: False
        suboptions:
            bypass_cert_subject_multi_class_list_name:
                description:
                - "Class List Name"
                type: str
    exception_certificate_subject_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        type: str
        required: False
    certificate_subject_ends_with_list:
        description:
        - "Field certificate_subject_ends_with_list"
        type: list
        required: False
        suboptions:
            certificate_subject_ends_with:
                description:
                - "Forward proxy bypass if Certificate Subject ends with another string"
                type: str
    certificate_subject_equals_list:
        description:
        - "Field certificate_subject_equals_list"
        type: list
        required: False
        suboptions:
            certificate_subject_equals:
                description:
                - "Forward proxy bypass if Certificate Subject equals another string"
                type: str
    certificate_subject_starts_with_list:
        description:
        - "Field certificate_subject_starts_with_list"
        type: list
        required: False
        suboptions:
            certificate_subject_starts:
                description:
                - "Forward proxy bypass if Certificate Subject starts with another string"
                type: str
    certificate_issuer_contains_list:
        description:
        - "Field certificate_issuer_contains_list"
        type: list
        required: False
        suboptions:
            certificate_issuer_contains:
                description:
                - "Forward proxy bypass if Certificate  issuer contains another string
          (Certificate issuer)"
                type: str
    bypass_cert_issuer_class_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    bypass_cert_issuer_multi_class_list:
        description:
        - "Field bypass_cert_issuer_multi_class_list"
        type: list
        required: False
        suboptions:
            bypass_cert_issuer_multi_class_list_name:
                description:
                - "Class List Name"
                type: str
    exception_certificate_issuer_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        type: str
        required: False
    certificate_issuer_ends_with_list:
        description:
        - "Field certificate_issuer_ends_with_list"
        type: list
        required: False
        suboptions:
            certificate_issuer_ends_with:
                description:
                - "Forward proxy bypass if Certificate issuer ends with another string"
                type: str
    certificate_issuer_equals_list:
        description:
        - "Field certificate_issuer_equals_list"
        type: list
        required: False
        suboptions:
            certificate_issuer_equals:
                description:
                - "Forward proxy bypass if Certificate issuer equals another string"
                type: str
    certificate_issuer_starts_with_list:
        description:
        - "Field certificate_issuer_starts_with_list"
        type: list
        required: False
        suboptions:
            certificate_issuer_starts:
                description:
                - "Forward proxy bypass if Certificate issuer starts with another string"
                type: str
    certificate_san_contains_list:
        description:
        - "Field certificate_san_contains_list"
        type: list
        required: False
        suboptions:
            certificate_san_contains:
                description:
                - "Forward proxy bypass if Certificate SAN contains another string"
                type: str
    bypass_cert_san_class_list_name:
        description:
        - "Class List Name"
        type: str
        required: False
    bypass_cert_san_multi_class_list:
        description:
        - "Field bypass_cert_san_multi_class_list"
        type: list
        required: False
        suboptions:
            bypass_cert_san_multi_class_list_name:
                description:
                - "Class List Name"
                type: str
    exception_certificate_san_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        type: str
        required: False
    certificate_san_ends_with_list:
        description:
        - "Field certificate_san_ends_with_list"
        type: list
        required: False
        suboptions:
            certificate_san_ends_with:
                description:
                - "Forward proxy bypass if Certificate SAN ends with another string"
                type: str
    certificate_san_equals_list:
        description:
        - "Field certificate_san_equals_list"
        type: list
        required: False
        suboptions:
            certificate_san_equals:
                description:
                - "Forward proxy bypass if Certificate SAN equals another string"
                type: str
    certificate_san_starts_with_list:
        description:
        - "Field certificate_san_starts_with_list"
        type: list
        required: False
        suboptions:
            certificate_san_starts:
                description:
                - "Forward proxy bypass if Certificate SAN starts with another string"
                type: str
    client_auth_case_insensitive:
        description:
        - "Case insensitive forward proxy client auth bypass"
        type: bool
        required: False
    client_auth_class_list:
        description:
        - "Forward proxy client auth bypass if SNI string matches class-list (Class List
          Name)"
        type: str
        required: False
    client_auth_contains_list:
        description:
        - "Field client_auth_contains_list"
        type: list
        required: False
        suboptions:
            client_auth_contains:
                description:
                - "Forward proxy bypass if SNI string contains another string"
                type: str
    client_auth_ends_with_list:
        description:
        - "Field client_auth_ends_with_list"
        type: list
        required: False
        suboptions:
            client_auth_ends_with:
                description:
                - "Forward proxy bypass if SNI string ends with another string"
                type: str
    client_auth_equals_list:
        description:
        - "Field client_auth_equals_list"
        type: list
        required: False
        suboptions:
            client_auth_equals:
                description:
                - "Forward proxy bypass if SNI string equals another string"
                type: str
    client_auth_starts_with_list:
        description:
        - "Field client_auth_starts_with_list"
        type: list
        required: False
        suboptions:
            client_auth_starts_with:
                description:
                - "Forward proxy bypass if SNI string starts with another string"
                type: str
    forward_proxy_cert_not_ready_action:
        description:
        - "'bypass'= bypass the connection; 'reset'= reset the connection; 'intercept'=
          wait for cert and then inspect the connection;"
        type: str
        required: False
    web_reputation:
        description:
        - "Field web_reputation"
        type: dict
        required: False
        suboptions:
            bypass_trustworthy:
                description:
                - "Bypass when reputation score is greater than or equal to 81"
                type: bool
            bypass_low_risk:
                description:
                - "Bypass when reputation score is greater than or equal to 61"
                type: bool
            bypass_moderate_risk:
                description:
                - "Bypass when reputation score is greater than or equal to 41"
                type: bool
            bypass_suspicious:
                description:
                - "Bypass when reputation score is greater than or equal to 21"
                type: bool
            bypass_malicious:
                description:
                - "Bypass when reputation score is greater than or equal to 1"
                type: bool
            bypass_threshold:
                description:
                - "Bypass when reputation score is greater than or equal to the customized score
          (1-100)"
                type: int
    exception_web_reputation:
        description:
        - "Field exception_web_reputation"
        type: dict
        required: False
        suboptions:
            exception_trustworthy:
                description:
                - "Intercept when reputation score is less than or equal to 100"
                type: bool
            exception_low_risk:
                description:
                - "Intercept when reputation score is less than or equal to 80"
                type: bool
            exception_moderate_risk:
                description:
                - "Intercept when reputation score is less than or equal to 60"
                type: bool
            exception_suspicious:
                description:
                - "Intercept when reputation score is less than or equal to 40"
                type: bool
            exception_malicious:
                description:
                - "Intercept when reputation score is less than or equal to 20"
                type: bool
            exception_threshold:
                description:
                - "Intercept when reputation score is less than or equal to a customized value
          (1-100)"
                type: int
    web_category:
        description:
        - "Field web_category"
        type: dict
        required: False
        suboptions:
            bypassed_category:
                description:
                - "'uncategorized'= Uncategorized URLs; 'real-estate'= Category Real Estate;
          'computer-and-internet-security'= Category Computer and Internet Security;
          'financial-services'= Category Financial Services; 'business-and-economy'=
          Category Business and Economy; 'computer-and-internet-info'= Category Computer
          and Internet Info; 'auctions'= Category Auctions; 'shopping'= Category
          Shopping; 'cult-and-occult'= Category Cult and Occult; 'travel'= Category
          Travel; 'drugs'= Category Abused Drugs; 'adult-and-pornography'= Category Adult
          and Pornography; 'home-and-garden'= Category Home and Garden; 'military'=
          Category Military; 'social-network'= Category Social Network; 'dead-sites'=
          Category Dead Sites (db Ops only); 'stock-advice-and-tools'= Category Stock
          Advice and Tools; 'training-and-tools'= Category Training and Tools; 'dating'=
          Category Dating; 'sex-education'= Category Sex Education; 'religion'= Category
          Religion; 'entertainment-and-arts'= Category Entertainment and Arts; 'personal-
          sites-and-blogs'= Category Personal sites and Blogs; 'legal'= Category Legal;
          'local-information'= Category Local Information; 'streaming-media'= Category
          Streaming Media; 'job-search'= Category Job Search; 'gambling'= Category
          Gambling; 'translation'= Category Translation; 'reference-and-research'=
          Category Reference and Research; 'shareware-and-freeware'= Category Shareware
          and Freeware; 'peer-to-peer'= Category Peer to Peer; 'marijuana'= Category
          Marijuana; 'hacking'= Category Hacking; 'games'= Category Games; 'philosophy-
          and-politics'= Category Philosophy and Political Advocacy; 'weapons'= Category
          Weapons; 'pay-to-surf'= Category Pay to Surf; 'hunting-and-fishing'= Category
          Hunting and Fishing; 'society'= Category Society; 'educational-institutions'=
          Category Educational Institutions; 'online-greeting-cards'= Category Online
          Greeting cards; 'sports'= Category Sports; 'swimsuits-and-intimate-apparel'=
          Category Swimsuits and Intimate Apparel; 'questionable'= Category Questionable;
          'kids'= Category Kids; 'hate-and-racism'= Category Hate and Racism; 'personal-
          storage'= Category Personal Storage; 'violence'= Category Violence;
          'keyloggers-and-monitoring'= Category Keyloggers and Monitoring; 'search-
          engines'= Category Search Engines; 'internet-portals'= Category Internet
          Portals; 'web-advertisements'= Category Web Advertisements; 'cheating'=
          Category Cheating; 'gross'= Category Gross; 'web-based-email'= Category Web
          based email; 'malware-sites'= Category Malware Sites; 'phishing-and-other-
          fraud'= Category Phishing and Other Frauds; 'proxy-avoid-and-anonymizers'=
          Category Proxy Avoid and Anonymizers; 'spyware-and-adware'= Category Spyware
          and Adware; 'music'= Category Music; 'government'= Category Government;
          'nudity'= Category Nudity; 'news-and-media'= Category News and Media;
          'illegal'= Category Illegal; 'cdns'= Category CDNs; 'internet-communications'=
          Category Internet Communications; 'bot-nets'= Category Bot Nets; 'abortion'=
          Category Abortion; 'health-and-medicine'= Category Health and Medicine; 'spam-
          urls'= Category SPAM URLs; 'dynamically-generated-content'= Category
          Dynamically Generated Content; 'parked-domains'= Category Parked Domains;
          'alcohol-and-tobacco'= Category Alcohol and Tobacco; 'image-and-video-search'=
          Category Image and Video Search; 'fashion-and-beauty'= Category Fashion and
          Beauty; 'recreation-and-hobbies'= Category Recreation and Hobbies; 'motor-
          vehicles'= Category Motor Vehicles; 'web-hosting-sites'= Category Web Hosting
          Sites; 'self-harm'= Category Self Harm; 'dns-over-https'= Category DNS over
          HTTPs; 'low-thc-cannabis-products'= Category Low-THC Cannabis Products;
          'generative-ai'= Category Generative AI; 'nudity-artistic'= Category Artistic
          Nudity; 'illegal-pornography'= Category Illegal Pornography eg. Child Sexual
          Abuse;"
                type: str
    exception_web_category:
        description:
        - "Field exception_web_category"
        type: dict
        required: False
        suboptions:
            exception_category:
                description:
                - "'uncategorized'= Uncategorized URLs; 'real-estate'= Category Real Estate;
          'computer-and-internet-security'= Category Computer and Internet Security;
          'financial-services'= Category Financial Services; 'business-and-economy'=
          Category Business and Economy; 'computer-and-internet-info'= Category Computer
          and Internet Info; 'auctions'= Category Auctions; 'shopping'= Category
          Shopping; 'cult-and-occult'= Category Cult and Occult; 'travel'= Category
          Travel; 'drugs'= Category Abused Drugs; 'adult-and-pornography'= Category Adult
          and Pornography; 'home-and-garden'= Category Home and Garden; 'military'=
          Category Military; 'social-network'= Category Social Network; 'dead-sites'=
          Category Dead Sites (db Ops only); 'stock-advice-and-tools'= Category Stock
          Advice and Tools; 'training-and-tools'= Category Training and Tools; 'dating'=
          Category Dating; 'sex-education'= Category Sex Education; 'religion'= Category
          Religion; 'entertainment-and-arts'= Category Entertainment and Arts; 'personal-
          sites-and-blogs'= Category Personal sites and Blogs; 'legal'= Category Legal;
          'local-information'= Category Local Information; 'streaming-media'= Category
          Streaming Media; 'job-search'= Category Job Search; 'gambling'= Category
          Gambling; 'translation'= Category Translation; 'reference-and-research'=
          Category Reference and Research; 'shareware-and-freeware'= Category Shareware
          and Freeware; 'peer-to-peer'= Category Peer to Peer; 'marijuana'= Category
          Marijuana; 'hacking'= Category Hacking; 'games'= Category Games; 'philosophy-
          and-politics'= Category Philosophy and Political Advocacy; 'weapons'= Category
          Weapons; 'pay-to-surf'= Category Pay to Surf; 'hunting-and-fishing'= Category
          Hunting and Fishing; 'society'= Category Society; 'educational-institutions'=
          Category Educational Institutions; 'online-greeting-cards'= Category Online
          Greeting cards; 'sports'= Category Sports; 'swimsuits-and-intimate-apparel'=
          Category Swimsuits and Intimate Apparel; 'questionable'= Category Questionable;
          'kids'= Category Kids; 'hate-and-racism'= Category Hate and Racism; 'personal-
          storage'= Category Personal Storage; 'violence'= Category Violence;
          'keyloggers-and-monitoring'= Category Keyloggers and Monitoring; 'search-
          engines'= Category Search Engines; 'internet-portals'= Category Internet
          Portals; 'web-advertisements'= Category Web Advertisements; 'cheating'=
          Category Cheating; 'gross'= Category Gross; 'web-based-email'= Category Web
          based email; 'malware-sites'= Category Malware Sites; 'phishing-and-other-
          fraud'= Category Phishing and Other Frauds; 'proxy-avoid-and-anonymizers'=
          Category Proxy Avoid and Anonymizers; 'spyware-and-adware'= Category Spyware
          and Adware; 'music'= Category Music; 'government'= Category Government;
          'nudity'= Category Nudity; 'news-and-media'= Category News and Media;
          'illegal'= Category Illegal; 'cdns'= Category CDNs; 'internet-communications'=
          Category Internet Communications; 'bot-nets'= Category Bot Nets; 'abortion'=
          Category Abortion; 'health-and-medicine'= Category Health and Medicine; 'spam-
          urls'= Category SPAM URLs; 'dynamically-generated-content'= Category
          Dynamically Generated Content; 'parked-domains'= Category Parked Domains;
          'alcohol-and-tobacco'= Category Alcohol and Tobacco; 'image-and-video-search'=
          Category Image and Video Search; 'fashion-and-beauty'= Category Fashion and
          Beauty; 'recreation-and-hobbies'= Category Recreation and Hobbies; 'motor-
          vehicles'= Category Motor Vehicles; 'web-hosting-sites'= Category Web Hosting
          Sites; 'self-harm'= Category Self Harm; 'dns-over-https'= Category DNS over
          HTTPs; 'low-thc-cannabis-products'= Category Low-THC Cannabis Products;
          'generative-ai'= Category Generative AI; 'nudity-artistic'= Category Artistic
          Nudity; 'illegal-pornography'= Category Illegal Pornography eg. Child Sexual
          Abuse;"
                type: str
    require_web_category:
        description:
        - "Wait for web category to be resolved before taking bypass decision"
        type: bool
        required: False
    client_ipv4_list:
        description:
        - "Field client_ipv4_list"
        type: list
        required: False
        suboptions:
            client_ipv4_list_name:
                description:
                - "IPV4 client class-list name"
                type: str
    client_ipv6_list:
        description:
        - "Field client_ipv6_list"
        type: list
        required: False
        suboptions:
            client_ipv6_list_name:
                description:
                - "IPV6 client class-list name"
                type: str
    server_ipv4_list:
        description:
        - "Field server_ipv4_list"
        type: list
        required: False
        suboptions:
            server_ipv4_list_name:
                description:
                - "IPV4 server class-list name"
                type: str
    server_ipv6_list:
        description:
        - "Field server_ipv6_list"
        type: list
        required: False
        suboptions:
            server_ipv6_list_name:
                description:
                - "IPV6 server class-list name"
                type: str
    exception_client_ipv4_list:
        description:
        - "Field exception_client_ipv4_list"
        type: list
        required: False
        suboptions:
            exception_client_ipv4_list_name:
                description:
                - "IPV4 exception client class-list name"
                type: str
    exception_client_ipv6_list:
        description:
        - "Field exception_client_ipv6_list"
        type: list
        required: False
        suboptions:
            exception_client_ipv6_list_name:
                description:
                - "IPV6 exception client class-list name"
                type: str
    exception_server_ipv4_list:
        description:
        - "Field exception_server_ipv4_list"
        type: list
        required: False
        suboptions:
            exception_server_ipv4_list_name:
                description:
                - "IPV4 exception server class-list name"
                type: str
    exception_server_ipv6_list:
        description:
        - "Field exception_server_ipv6_list"
        type: list
        required: False
        suboptions:
            exception_server_ipv6_list_name:
                description:
                - "IPV6 exception server class-list name"
                type: str
    local_cert_pin_list:
        description:
        - "Field local_cert_pin_list"
        type: dict
        required: False
        suboptions:
            local_cert_pin_list_bypass_fail_count:
                description:
                - "Set the connection fail count as bypass criteria (Bypass when connection
          failure count is greater than the criteria (1-65536))"
                type: int
    central_cert_pin_list:
        description:
        - "Forward proxy bypass if SNI string is contained in central updated cert-
          pinning-candidate list"
        type: bool
        required: False
    forward_proxy_require_sni_cert_matched:
        description:
        - "'no-match-action-inspect'= Inspected if not matched; 'no-match-action-drop'=
          Dropped if not matched;"
        type: str
        required: False
    template_cipher:
        description:
        - "Cipher Template Name"
        type: str
        required: False
    shared_partition_cipher_template:
        description:
        - "Reference a cipher template from shared partition"
        type: bool
        required: False
    template_cipher_shared:
        description:
        - "Cipher Template Name"
        type: str
        required: False
    template_hsm:
        description:
        - "HSM Template (HSM Template Name)"
        type: str
        required: False
    hsm_type:
        description:
        - "'thales-embed'= Thales embed key; 'thales-hwcrhk'= Thales hwcrhk Key;"
        type: str
        required: False
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        type: list
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "'SSL3_RSA_DES_192_CBC3_SHA'= TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A);
          'SSL3_RSA_RC4_128_MD5'= TLS_RSA_WITH_RC4_128_MD5 (0x0004);
          'SSL3_RSA_RC4_128_SHA'= TLS_RSA_WITH_RC4_128_SHA (0x0005);
          'TLS1_RSA_AES_128_SHA'= TLS_RSA_WITH_AES_128_CBC_SHA (0x002F);
          'TLS1_RSA_AES_256_SHA'= TLS_RSA_WITH_AES_256_CBC_SHA (0x0035);
          'TLS1_RSA_AES_128_SHA256'= TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C);
          'TLS1_RSA_AES_256_SHA256'= TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D);
          'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
          (0x009E); 'TLS1_DHE_RSA_AES_128_SHA'= TLS_DHE_RSA_WITH_AES_128_CBC_SHA
          (0x0033); 'TLS1_DHE_RSA_AES_128_SHA256'= TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
          (0x0067); 'TLS1_DHE_RSA_AES_256_GCM_SHA384'=
          TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009F); 'TLS1_DHE_RSA_AES_256_SHA'=
          TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039); 'TLS1_DHE_RSA_AES_256_SHA256'=
          TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006B);
          'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
          (0xC02B); 'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
          (0xC009); 'TLS1_ECDHE_ECDSA_AES_128_SHA256'=
          TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023);
          'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
          (0xC02C); 'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
          (0xC00A); 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'=
          TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F); 'TLS1_ECDHE_RSA_AES_128_SHA'=
          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013); 'TLS1_ECDHE_RSA_AES_128_SHA256'=
          TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027);
          'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          (0xC030); 'TLS1_ECDHE_RSA_AES_256_SHA'= TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
          (0xC014); 'TLS1_RSA_AES_128_GCM_SHA256'= TLS_RSA_WITH_AES_128_GCM_SHA256
          (0x009C); 'TLS1_RSA_AES_256_GCM_SHA384'= TLS_RSA_WITH_AES_256_GCM_SHA384
          (0x009D); 'TLS1_ECDHE_RSA_AES_256_SHA384'=
          TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028);
          'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
          (0xC024); 'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8);
          'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256'=
          TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9);
          'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCAA);"
                type: str
    server_name_list:
        description:
        - "Field server_name_list"
        type: list
        required: False
        suboptions:
            server_name:
                description:
                - "Server name indication in Client hello extension (Server name String)"
                type: str
            server_cert:
                description:
                - "Server Certificate associated to SNI (Server Certificate Name)"
                type: str
            server_chain:
                description:
                - "Server Certificate Chain associated to SNI (Server Certificate Chain Name)"
                type: str
            server_key:
                description:
                - "Server Private Key associated to SNI (Server Private Key Name)"
                type: str
            server_passphrase:
                description:
                - "help Password Phrase"
                type: str
            server_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
            server_name_alternate:
                description:
                - "Specific the second certifcate"
                type: bool
            server_shared:
                description:
                - "Server Name Partition Shared"
                type: bool
            sni_template:
                description:
                - "Template associated to SNI"
                type: bool
            sni_template_client_ssl:
                description:
                - "Client SSL Template Name"
                type: str
            sni_shared_partition_client_ssl_template:
                description:
                - "Reference a Client SSL template from shared partition"
                type: bool
            sni_template_client_ssl_shared_name:
                description:
                - "Shared Partition Client SSL Template Name"
                type: str
            server_name_regex:
                description:
                - "Server name indication in Client hello extension with regular expression
          (Server name String with regex)"
                type: str
            server_cert_regex:
                description:
                - "Server Certificate associated to SNI regex (Server Certificate Name)"
                type: str
            server_chain_regex:
                description:
                - "Server Certificate Chain associated to SNI regex (Server Certificate Chain
          Name)"
                type: str
            server_key_regex:
                description:
                - "Server Private Key associated to SNI regex (Server Private Key Name)"
                type: str
            server_passphrase_regex:
                description:
                - "help Password Phrase"
                type: str
            server_encrypted_regex:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
            server_name_regex_alternate:
                description:
                - "Specific the second certifcate"
                type: bool
            server_shared_regex:
                description:
                - "Server Name Partition Shared"
                type: bool
            sni_regex_template:
                description:
                - "Template associated to SNI regex"
                type: bool
            sni_regex_template_client_ssl:
                description:
                - "Client SSL Template Name"
                type: str
            sni_regex_shared_partition_client_ssl_template:
                description:
                - "Reference a Client SSL template from shared partition"
                type: bool
            sni_regex_template_client_ssl_shared_name:
                description:
                - "Shared Partition Client SSL Template Name"
                type: str
    server_name_auto_map:
        description:
        - "Enable automatic mapping of server name indication in Client hello extension"
        type: bool
        required: False
    sni_enable_log:
        description:
        - "Enable logging of sni-auto-map failures. Disable by default"
        type: bool
        required: False
    sni_bypass_missing_cert:
        description:
        - "Bypass when missing cert/key"
        type: bool
        required: False
    sni_bypass_expired_cert:
        description:
        - "Bypass when certificate expired"
        type: bool
        required: False
    sni_bypass_explicit_list:
        description:
        - "Bypass when matched explicit bypass list (Specify class list name)"
        type: str
        required: False
    sni_bypass_enable_log:
        description:
        - "Enable logging when bypass event happens, disabled by default"
        type: bool
        required: False
    direct_client_server_auth:
        description:
        - "Let backend server does SSL client authentication directly"
        type: bool
        required: False
    session_cache_size:
        description:
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse
          disabled))"
        type: int
        required: False
    session_cache_timeout:
        description:
        - "Session Cache Timeout (Timeout value, in seconds. Default value 0 (Session
          cache timeout disabled))"
        type: int
        required: False
    session_ticket_disable:
        description:
        - "Disable client side session ticket support"
        type: bool
        required: False
    session_ticket_lifetime:
        description:
        - "Session ticket lifetime in seconds from stateless session resumption (Lifetime
          value in seconds. Default value 0 (Session ticket lifetime is 7200 seconds))"
        type: int
        required: False
    ssl_false_start_disable:
        description:
        - "disable SSL False Start"
        type: bool
        required: False
    disable_sslv3:
        description:
        - "Reject Client requests for SSL version 3"
        type: bool
        required: False
    version:
        description:
        - "TLS/SSL version, default is the highest number supported (TLS/SSL version=
          30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1, 33-TLSv1.2 and 34-TLSv1.3)"
        type: int
        required: False
    dgversion:
        description:
        - "Lower TLS/SSL version can be downgraded"
        type: int
        required: False
    renegotiation_disable:
        description:
        - "Disable SSL renegotiation"
        type: bool
        required: False
    sslv2_bypass_service_group:
        description:
        - "Service Group for Bypass SSLV2 (Service Group Name)"
        type: str
        required: False
    authorization:
        description:
        - "Specify LDAP server for client SSL authorizaiton"
        type: bool
        required: False
    authen_name:
        description:
        - "Specify authorization LDAP server name"
        type: str
        required: False
    ldap_base_dn_from_cert:
        description:
        - "Use Subject DN as LDAP search base DN"
        type: bool
        required: False
    ldap_search_filter:
        description:
        - "Specify LDAP search filter"
        type: str
        required: False
    auth_sg:
        description:
        - "Specify authorization LDAP service group"
        type: str
        required: False
    auth_sg_dn:
        description:
        - "Use Subject DN as LDAP search base DN"
        type: bool
        required: False
    auth_sg_filter:
        description:
        - "Specify LDAP search filter"
        type: str
        required: False
    auth_username_attribute:
        description:
        - "Specify attribute name of username for client SSL authorization"
        type: str
        required: False
    non_ssl_bypass_service_group:
        description:
        - "Service Group for Bypass non-ssl traffic (Service Group Name)"
        type: str
        required: False
    non_ssl_bypass_l4session:
        description:
        - "Handle the non-ssl session as L4 for performance optimization"
        type: bool
        required: False
    enable_ssli_ftp_alg:
        description:
        - "Enable SSLi FTP over TLS support at which port"
        type: int
        required: False
    early_data:
        description:
        - "Enable TLS 1.3 early data (0-RTT)"
        type: bool
        required: False
    no_anti_replay:
        description:
        - "Disable anti-replay protection for TLS 1.3 early data (0-RTT data)"
        type: bool
        required: False
    ja3_enable:
        description:
        - "Enable JA3 features"
        type: bool
        required: False
    ja3_insert_http_header:
        description:
        - "Insert the JA3 hash into this request as a HTTP header (HTTP Header Name)"
        type: str
        required: False
    ja3_reject_class_list:
        description:
        - "Drop request if the JA3 hash matches this class-list (type string-case-
          insensitive) (Class-List Name)"
        type: str
        required: False
    ja3_reject_max_number_per_host:
        description:
        - "Drop request if numbers of JA3 of this client address exceeded"
        type: int
        required: False
    ja3_ttl:
        description:
        - "seconds to keep each JA3 record"
        type: int
        required: False
    ja4_enable:
        description:
        - "Enable JA4 features"
        type: bool
        required: False
    ja4_insert_http_header:
        description:
        - "Insert the JA4 hash into this request as a HTTP header (HTTP Header Name)"
        type: str
        required: False
    ja4_reject_class_list:
        description:
        - "Drop request if the JA4 hash matches this class-list (type string-case-
          insensitive) (Class-List Name)"
        type: str
        required: False
    ja4_reject_max_number_per_host:
        description:
        - "Drop request if numbers of JA4 of this client address exceeded"
        type: int
        required: False
    ja4_ttl:
        description:
        - "seconds to keep each JA4 record"
        type: int
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
                - "'all'= all; 'real-estate'= real estate category; 'computer-and-internet-
          security'= computer and internet security category; 'financial-services'=
          financial services category; 'business-and-economy'= business and economy
          category; 'computer-and-internet-info'= computer and internet info category;
          'auctions'= auctions category; 'shopping'= shopping category; 'cult-and-
          occult'= cult and occult category; 'travel'= travel category; 'drugs'= drugs
          category; 'adult-and-pornography'= adult and pornography category; 'home-and-
          garden'= home and garden category; 'military'= military category; 'social-
          network'= social network category; 'dead-sites'= dead sites category; 'stock-
          advice-and-tools'= stock advice and tools category; 'training-and-tools'=
          training and tools category; 'dating'= dating category; 'sex-education'= sex
          education category; 'religion'= religion category; 'entertainment-and-arts'=
          entertainment and arts category; 'personal-sites-and-blogs'= personal sites and
          blogs category; 'legal'= legal category; 'local-information'= local information
          category; 'streaming-media'= streaming media category; 'job-search'= job search
          category; 'gambling'= gambling category; 'translation'= translation category;
          'reference-and-research'= reference and research category; 'shareware-and-
          freeware'= shareware and freeware category; 'peer-to-peer'= peer to peer
          category; 'marijuana'= marijuana category; 'hacking'= hacking category;
          'games'= games category; 'philosophy-and-politics'= philosophy and politics
          category; 'weapons'= weapons category; 'pay-to-surf'= pay to surf category;
          'hunting-and-fishing'= hunting and fishing category; 'society'= society
          category; 'educational-institutions'= educational institutions category;
          'online-greeting-cards'= online greeting cards category; 'sports'= sports
          category; 'swimsuits-and-intimate-apparel'= swimsuits and intimate apparel
          category; 'questionable'= questionable category; 'kids'= kids category; 'hate-
          and-racism'= hate and racism category; 'personal-storage'= personal storage
          category; 'violence'= violence category; 'keyloggers-and-monitoring'=
          keyloggers and monitoring category; 'search-engines'= search engines category;
          'internet-portals'= internet portals category; 'web-advertisements'= web
          advertisements category; 'cheating'= cheating category; 'gross'= gross
          category; 'web-based-email'= web based email category; 'malware-sites'= malware
          sites category; 'phishing-and-other-fraud'= phishing and other fraud category;
          'proxy-avoid-and-anonymizers'= proxy avoid and anonymizers category; 'spyware-
          and-adware'= spyware and adware category; 'music'= music category;
          'government'= government category; 'nudity'= nudity category; 'news-and-media'=
          news and media category; 'illegal'= illegal category; 'CDNs'= content delivery
          networks category; 'internet-communications'= internet communications category;
          'bot-nets'= bot nets category; 'abortion'= abortion category; 'health-and-
          medicine'= health and medicine category; 'confirmed-SPAM-sources'= confirmed
          SPAM sources category; 'SPAM-URLs'= SPAM URLs category; 'unconfirmed-SPAM-
          sources'= unconfirmed SPAM sources category; 'open-HTTP-proxies'= open HTTP
          proxies category; 'dynamically-generated-content'= dynamically generated
          content category; 'parked-domains'= parked domains category; 'alcohol-and-
          tobacco'= alcohol and tobacco category; 'private-IP-addresses'= private IP
          addresses category; 'image-and-video-search'= image and video search category;
          'fashion-and-beauty'= fashion and beauty category; 'recreation-and-hobbies'=
          recreation and hobbies category; 'motor-vehicles'= motor vehicles category;
          'web-hosting-sites'= web hosting sites category; 'food-and-dining'= food and
          dining category; 'dummy-item'= dummy item category; 'self-harm'= self harm
          category; 'dns-over-https'= dns over https category; 'low-thc-cannabis-
          products'= low-thc cannabis products; 'generative-ai'= generative ai category;
          'nudity-artistic'= artistic nudity; 'illegal-pornography'= illegal pornography
          eg. child sexual abuse; 'uncategorised'= uncategorised; 'other-category'= other
          category; 'trustworthy'= Trustworthy level(81-100); 'low-risk'= Low-risk
          level(61-80); 'moderate-risk'= Moderate-risk level(41-60); 'suspicious'=
          Suspicious level(21-40); 'malicious'= Malicious level(1-20);"
                type: str
    certificate_list:
        description:
        - "Field certificate_list"
        type: list
        required: False
        suboptions:
            cert:
                description:
                - "Certificate Name"
                type: str
            key:
                description:
                - "Server Private Key (Key Name)"
                type: str
            passphrase:
                description:
                - "Password Phrase"
                type: str
            key_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
            chain_cert:
                description:
                - "Chain Certificate (Chain Certificate Name)"
                type: str
            shared:
                description:
                - "Server Certificate and Key Partition Shared"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            cert_status_list:
                description:
                - "Field cert_status_list"
                type: list
            name:
                description:
                - "Client SSL Template Name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            real_estate:
                description:
                - "real estate category"
                type: str
            computer_and_internet_security:
                description:
                - "computer and internet security category"
                type: str
            financial_services:
                description:
                - "financial services category"
                type: str
            business_and_economy:
                description:
                - "business and economy category"
                type: str
            computer_and_internet_info:
                description:
                - "computer and internet info category"
                type: str
            auctions:
                description:
                - "auctions category"
                type: str
            shopping:
                description:
                - "shopping category"
                type: str
            cult_and_occult:
                description:
                - "cult and occult category"
                type: str
            travel:
                description:
                - "travel category"
                type: str
            drugs:
                description:
                - "drugs category"
                type: str
            adult_and_pornography:
                description:
                - "adult and pornography category"
                type: str
            home_and_garden:
                description:
                - "home and garden category"
                type: str
            military:
                description:
                - "military category"
                type: str
            social_network:
                description:
                - "social network category"
                type: str
            dead_sites:
                description:
                - "dead sites category"
                type: str
            stock_advice_and_tools:
                description:
                - "stock advice and tools category"
                type: str
            training_and_tools:
                description:
                - "training and tools category"
                type: str
            dating:
                description:
                - "dating category"
                type: str
            sex_education:
                description:
                - "sex education category"
                type: str
            religion:
                description:
                - "religion category"
                type: str
            entertainment_and_arts:
                description:
                - "entertainment and arts category"
                type: str
            personal_sites_and_blogs:
                description:
                - "personal sites and blogs category"
                type: str
            legal:
                description:
                - "legal category"
                type: str
            local_information:
                description:
                - "local information category"
                type: str
            streaming_media:
                description:
                - "streaming media category"
                type: str
            job_search:
                description:
                - "job search category"
                type: str
            gambling:
                description:
                - "gambling category"
                type: str
            translation:
                description:
                - "translation category"
                type: str
            reference_and_research:
                description:
                - "reference and research category"
                type: str
            shareware_and_freeware:
                description:
                - "shareware and freeware category"
                type: str
            peer_to_peer:
                description:
                - "peer to peer category"
                type: str
            marijuana:
                description:
                - "marijuana category"
                type: str
            hacking:
                description:
                - "hacking category"
                type: str
            games:
                description:
                - "games category"
                type: str
            philosophy_and_politics:
                description:
                - "philosophy and politics category"
                type: str
            weapons:
                description:
                - "weapons category"
                type: str
            pay_to_surf:
                description:
                - "pay to surf category"
                type: str
            hunting_and_fishing:
                description:
                - "hunting and fishing category"
                type: str
            society:
                description:
                - "society category"
                type: str
            educational_institutions:
                description:
                - "educational institutions category"
                type: str
            online_greeting_cards:
                description:
                - "online greeting cards category"
                type: str
            sports:
                description:
                - "sports category"
                type: str
            swimsuits_and_intimate_apparel:
                description:
                - "swimsuits and intimate apparel category"
                type: str
            questionable:
                description:
                - "questionable category"
                type: str
            kids:
                description:
                - "kids category"
                type: str
            hate_and_racism:
                description:
                - "hate and racism category"
                type: str
            personal_storage:
                description:
                - "personal storage category"
                type: str
            violence:
                description:
                - "violence category"
                type: str
            keyloggers_and_monitoring:
                description:
                - "keyloggers and monitoring category"
                type: str
            search_engines:
                description:
                - "search engines category"
                type: str
            internet_portals:
                description:
                - "internet portals category"
                type: str
            web_advertisements:
                description:
                - "web advertisements category"
                type: str
            cheating:
                description:
                - "cheating category"
                type: str
            gross:
                description:
                - "gross category"
                type: str
            web_based_email:
                description:
                - "web based email category"
                type: str
            malware_sites:
                description:
                - "malware sites category"
                type: str
            phishing_and_other_fraud:
                description:
                - "phishing and other fraud category"
                type: str
            proxy_avoid_and_anonymizers:
                description:
                - "proxy avoid and anonymizers category"
                type: str
            spyware_and_adware:
                description:
                - "spyware and adware category"
                type: str
            music:
                description:
                - "music category"
                type: str
            government:
                description:
                - "government category"
                type: str
            nudity:
                description:
                - "nudity category"
                type: str
            news_and_media:
                description:
                - "news and media category"
                type: str
            illegal:
                description:
                - "illegal category"
                type: str
            CDNs:
                description:
                - "content delivery networks category"
                type: str
            internet_communications:
                description:
                - "internet communications category"
                type: str
            bot_nets:
                description:
                - "bot nets category"
                type: str
            abortion:
                description:
                - "abortion category"
                type: str
            health_and_medicine:
                description:
                - "health and medicine category"
                type: str
            confirmed_SPAM_sources:
                description:
                - "confirmed SPAM sources category"
                type: str
            SPAM_URLs:
                description:
                - "SPAM URLs category"
                type: str
            unconfirmed_SPAM_sources:
                description:
                - "unconfirmed SPAM sources category"
                type: str
            open_HTTP_proxies:
                description:
                - "open HTTP proxies category"
                type: str
            dynamically_generated_content:
                description:
                - "dynamically generated content category"
                type: str
            parked_domains:
                description:
                - "parked domains category"
                type: str
            alcohol_and_tobacco:
                description:
                - "alcohol and tobacco category"
                type: str
            private_IP_addresses:
                description:
                - "private IP addresses category"
                type: str
            image_and_video_search:
                description:
                - "image and video search category"
                type: str
            fashion_and_beauty:
                description:
                - "fashion and beauty category"
                type: str
            recreation_and_hobbies:
                description:
                - "recreation and hobbies category"
                type: str
            motor_vehicles:
                description:
                - "motor vehicles category"
                type: str
            web_hosting_sites:
                description:
                - "web hosting sites category"
                type: str
            food_and_dining:
                description:
                - "food and dining category"
                type: str
            self_harm:
                description:
                - "self harm category"
                type: str
            dns_over_https:
                description:
                - "dns over https category"
                type: str
            low_thc_cannabis_products:
                description:
                - "low-thc cannabis products"
                type: str
            generative_ai:
                description:
                - "generative ai category"
                type: str
            nudity_artistic:
                description:
                - "artistic nudity"
                type: str
            illegal_pornography:
                description:
                - "illegal pornography eg. child sexual abuse"
                type: str
            uncategorised:
                description:
                - "uncategorised"
                type: str
            other_category:
                description:
                - "other category"
                type: str
            trustworthy:
                description:
                - "Trustworthy level(81-100)"
                type: str
            low_risk:
                description:
                - "Low-risk level(61-80)"
                type: str
            moderate_risk:
                description:
                - "Moderate-risk level(41-60)"
                type: str
            suspicious:
                description:
                - "Suspicious level(21-40)"
                type: str
            malicious:
                description:
                - "Malicious level(1-20)"
                type: str
            name:
                description:
                - "Client SSL Template Name"
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
    "ad_group_list", "alert_type", "auth_sg", "auth_sg_dn", "auth_sg_filter", "auth_username", "auth_username_attribute", "authen_name", "authorization", "bypass_cert_issuer_class_list_name", "bypass_cert_issuer_multi_class_list", "bypass_cert_san_class_list_name", "bypass_cert_san_multi_class_list", "bypass_cert_subject_class_list_name",
    "bypass_cert_subject_multi_class_list", "ca_certs", "cache_persistence_list_name", "case_insensitive", "central_cert_pin_list", "cert_revoke_action", "cert_unknown_action", "certificate_issuer_contains_list", "certificate_issuer_ends_with_list", "certificate_issuer_equals_list", "certificate_issuer_starts_with_list", "certificate_list",
    "certificate_san_contains_list", "certificate_san_ends_with_list", "certificate_san_equals_list", "certificate_san_starts_with_list", "certificate_subject_contains_list", "certificate_subject_ends_with_list", "certificate_subject_equals_list", "certificate_subject_starts_with_list", "chain_cert", "chain_cert_shared_str",
    "cipher_without_prio_list", "class_list_name", "client_auth_case_insensitive", "client_auth_class_list", "client_auth_contains_list", "client_auth_ends_with_list", "client_auth_equals_list", "client_auth_starts_with_list", "client_certificate", "client_ipv4_list", "client_ipv6_list", "close_notify", "contains_list", "crl_certs", "dgversion",
    "dh_type", "direct_client_server_auth", "disable_sslv3", "early_data", "ec_list", "enable_ssli_ftp_alg", "enable_tls_alert_logging", "ends_with_list", "equals_list", "exception_ad_group_list", "exception_certificate_issuer_cl_name", "exception_certificate_san_cl_name", "exception_certificate_subject_cl_name", "exception_client_ipv4_list",
    "exception_client_ipv6_list", "exception_server_ipv4_list", "exception_server_ipv6_list", "exception_sni_cl_name", "exception_user_name_list", "exception_web_category", "exception_web_reputation", "expire_hours", "forward_encrypted", "forward_passphrase", "forward_proxy_alt_sign", "forward_proxy_block_message", "forward_proxy_ca_cert",
    "forward_proxy_ca_key", "forward_proxy_cert_cache_limit", "forward_proxy_cert_cache_timeout", "forward_proxy_cert_expiry", "forward_proxy_cert_not_ready_action", "forward_proxy_cert_revoke_action", "forward_proxy_cert_unknown_action", "forward_proxy_crl_disable", "forward_proxy_decrypted_dscp", "forward_proxy_decrypted_dscp_bypass",
    "forward_proxy_enable", "forward_proxy_esni_action", "forward_proxy_failsafe_disable", "forward_proxy_hash_persistence_interval", "forward_proxy_log_disable", "forward_proxy_no_shared_cipher_action", "forward_proxy_no_sni_action", "forward_proxy_ocsp_disable", "forward_proxy_require_sni_cert_matched", "forward_proxy_selfsign_redir",
    "forward_proxy_ssl_version", "forward_proxy_trusted_ca_lists", "forward_proxy_verify_cert_fail_action", "fp_alt_cert", "fp_alt_chain_cert", "fp_alt_encrypted", "fp_alt_key", "fp_alt_passphrase", "fp_alt_shared", "fp_ca_certificate", "fp_ca_certificate_shared", "fp_ca_chain_cert", "fp_ca_key", "fp_ca_key_encrypted", "fp_ca_key_passphrase",
    "fp_ca_key_shared", "fp_ca_shared", "fp_cert_ext_aia_ca_issuers", "fp_cert_ext_aia_ocsp", "fp_cert_ext_crldp", "fp_cert_fetch_autonat", "fp_cert_fetch_autonat_precedence", "fp_cert_fetch_natpool_name", "fp_cert_fetch_natpool_name_shared", "fp_cert_fetch_natpool_precedence", "fp_esni_action", "handshake_logging_enable", "hsm_type",
    "inspect_certificate_issuer_cl_name", "inspect_certificate_san_cl_name", "inspect_certificate_subject_cl_name", "inspect_list_name", "ja3_enable", "ja3_insert_http_header", "ja3_reject_class_list", "ja3_reject_max_number_per_host", "ja3_ttl", "ja4_enable", "ja4_insert_http_header", "ja4_reject_class_list", "ja4_reject_max_number_per_host",
    "ja4_ttl", "ldap_base_dn_from_cert", "ldap_search_filter", "local_cert_pin_list", "local_logging", "multi_class_list", "name", "no_anti_replay", "no_shared_cipher_action", "non_ssl_bypass_l4session", "non_ssl_bypass_service_group", "notafter", "notafterday", "notaftermonth", "notafteryear", "notbefore", "notbeforeday", "notbeforemonth",
    "notbeforeyear", "ocsp_stapling", "ocspst_ca_cert", "ocspst_ocsp", "ocspst_sg", "ocspst_sg_days", "ocspst_sg_hours", "ocspst_sg_minutes", "ocspst_sg_timeout", "ocspst_srvr", "ocspst_srvr_days", "ocspst_srvr_hours", "ocspst_srvr_minutes", "ocspst_srvr_timeout", "oper", "renegotiation_disable", "req_ca_lists", "require_web_category",
    "sampling_enable", "server_ipv4_list", "server_ipv6_list", "server_name_auto_map", "server_name_list", "session_cache_size", "session_cache_timeout", "session_key_logging_enable", "session_ticket_disable", "session_ticket_lifetime", "shared_partition_cipher_template", "shared_partition_pool", "sni_bypass_enable_log", "sni_bypass_expired_cert",
    "sni_bypass_explicit_list", "sni_bypass_missing_cert", "sni_enable_log", "ssl_false_start_disable", "ssli_inbound_enable", "ssli_logging", "sslilogging", "sslv2_bypass_service_group", "starts_with_list", "stats", "template_cipher", "template_cipher_shared", "template_hsm", "user_name_list", "user_tag", "uuid", "verify_cert_fail_action",
    "version", "web_category", "web_reputation",
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
        'name': {
            'type': 'str',
            'required': True,
            },
        'auth_username': {
            'type': 'str',
            },
        'ca_certs': {
            'type': 'list',
            'ca_cert': {
                'type': 'str',
                },
            'ca_shared': {
                'type': 'bool',
                },
            'client_ocsp': {
                'type': 'bool',
                },
            'client_ocsp_srvr': {
                'type': 'str',
                },
            'client_ocsp_sg': {
                'type': 'str',
                }
            },
        'chain_cert': {
            'type': 'str',
            },
        'chain_cert_shared_str': {
            'type': 'str',
            },
        'dh_type': {
            'type': 'str',
            'choices': ['1024', '1024-dsa', '2048']
            },
        'ec_list': {
            'type': 'list',
            'ec': {
                'type': 'str',
                'choices': ['secp256r1', 'secp384r1', 'secp521r1', 'x25519']
                }
            },
        'local_logging': {
            'type': 'bool',
            },
        'ocsp_stapling': {
            'type': 'bool',
            },
        'ocspst_ca_cert': {
            'type': 'str',
            },
        'ocspst_ocsp': {
            'type': 'bool',
            },
        'ocspst_srvr': {
            'type': 'str',
            },
        'ocspst_srvr_days': {
            'type': 'int',
            },
        'ocspst_srvr_hours': {
            'type': 'int',
            },
        'ocspst_srvr_minutes': {
            'type': 'int',
            },
        'ocspst_srvr_timeout': {
            'type': 'int',
            },
        'ocspst_sg': {
            'type': 'str',
            },
        'ocspst_sg_days': {
            'type': 'int',
            },
        'ocspst_sg_hours': {
            'type': 'int',
            },
        'ocspst_sg_minutes': {
            'type': 'int',
            },
        'ocspst_sg_timeout': {
            'type': 'int',
            },
        'ssli_inbound_enable': {
            'type': 'bool',
            },
        'ssli_logging': {
            'type': 'bool',
            },
        'sslilogging': {
            'type': 'str',
            'choices': ['disable', 'all']
            },
        'client_certificate': {
            'type': 'str',
            'choices': ['Ignore', 'Require', 'Request']
            },
        'req_ca_lists': {
            'type': 'list',
            'client_certificate_Request_CA': {
                'type': 'str',
                },
            'client_cert_req_ca_shared': {
                'type': 'bool',
                }
            },
        'close_notify': {
            'type': 'bool',
            },
        'crl_certs': {
            'type': 'list',
            'crl': {
                'type': 'str',
                },
            'crl_shared': {
                'type': 'bool',
                }
            },
        'forward_proxy_ca_cert': {
            'type': 'str',
            },
        'fp_ca_shared': {
            'type': 'bool',
            },
        'forward_proxy_ca_key': {
            'type': 'str',
            },
        'forward_passphrase': {
            'type': 'str',
            },
        'forward_encrypted': {
            'type': 'str',
            },
        'fp_ca_key_shared': {
            'type': 'bool',
            },
        'fp_ca_certificate': {
            'type': 'str',
            },
        'fp_ca_key': {
            'type': 'str',
            },
        'fp_ca_key_passphrase': {
            'type': 'str',
            },
        'fp_ca_key_encrypted': {
            'type': 'str',
            },
        'fp_ca_chain_cert': {
            'type': 'str',
            },
        'fp_ca_certificate_shared': {
            'type': 'bool',
            },
        'forward_proxy_alt_sign': {
            'type': 'bool',
            },
        'fp_alt_cert': {
            'type': 'str',
            },
        'fp_alt_key': {
            'type': 'str',
            },
        'fp_alt_passphrase': {
            'type': 'str',
            },
        'fp_alt_encrypted': {
            'type': 'str',
            },
        'fp_alt_chain_cert': {
            'type': 'str',
            },
        'fp_alt_shared': {
            'type': 'bool',
            },
        'forward_proxy_trusted_ca_lists': {
            'type': 'list',
            'forward_proxy_trusted_ca': {
                'type': 'str',
                },
            'fp_trusted_ca_shared': {
                'type': 'bool',
                }
            },
        'forward_proxy_decrypted_dscp': {
            'type': 'int',
            },
        'forward_proxy_decrypted_dscp_bypass': {
            'type': 'int',
            },
        'enable_tls_alert_logging': {
            'type': 'bool',
            },
        'alert_type': {
            'type': 'str',
            'choices': ['fatal']
            },
        'forward_proxy_verify_cert_fail_action': {
            'type': 'bool',
            },
        'verify_cert_fail_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
            },
        'forward_proxy_cert_revoke_action': {
            'type': 'bool',
            },
        'cert_revoke_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
            },
        'forward_proxy_no_shared_cipher_action': {
            'type': 'bool',
            },
        'no_shared_cipher_action': {
            'type': 'str',
            'choices': ['bypass', 'drop']
            },
        'forward_proxy_esni_action': {
            'type': 'bool',
            },
        'fp_esni_action': {
            'type': 'str',
            'choices': ['bypass', 'drop']
            },
        'forward_proxy_cert_unknown_action': {
            'type': 'bool',
            },
        'cert_unknown_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
            },
        'forward_proxy_block_message': {
            'type': 'str',
            },
        'cache_persistence_list_name': {
            'type': 'str',
            },
        'fp_cert_ext_crldp': {
            'type': 'str',
            },
        'fp_cert_ext_aia_ocsp': {
            'type': 'str',
            },
        'fp_cert_ext_aia_ca_issuers': {
            'type': 'str',
            },
        'notbefore': {
            'type': 'bool',
            },
        'notbeforeday': {
            'type': 'int',
            },
        'notbeforemonth': {
            'type': 'int',
            },
        'notbeforeyear': {
            'type': 'int',
            },
        'notafter': {
            'type': 'bool',
            },
        'notafterday': {
            'type': 'int',
            },
        'notaftermonth': {
            'type': 'int',
            },
        'notafteryear': {
            'type': 'int',
            },
        'forward_proxy_hash_persistence_interval': {
            'type': 'int',
            },
        'forward_proxy_ssl_version': {
            'type': 'int',
            },
        'forward_proxy_ocsp_disable': {
            'type': 'bool',
            },
        'forward_proxy_crl_disable': {
            'type': 'bool',
            },
        'forward_proxy_cert_cache_timeout': {
            'type': 'int',
            },
        'forward_proxy_cert_cache_limit': {
            'type': 'int',
            },
        'forward_proxy_cert_expiry': {
            'type': 'bool',
            },
        'expire_hours': {
            'type': 'int',
            },
        'forward_proxy_enable': {
            'type': 'bool',
            },
        'handshake_logging_enable': {
            'type': 'bool',
            },
        'session_key_logging_enable': {
            'type': 'bool',
            },
        'forward_proxy_selfsign_redir': {
            'type': 'bool',
            },
        'forward_proxy_failsafe_disable': {
            'type': 'bool',
            },
        'forward_proxy_log_disable': {
            'type': 'bool',
            },
        'fp_cert_fetch_natpool_name': {
            'type': 'str',
            },
        'shared_partition_pool': {
            'type': 'bool',
            },
        'fp_cert_fetch_natpool_name_shared': {
            'type': 'str',
            },
        'fp_cert_fetch_natpool_precedence': {
            'type': 'bool',
            },
        'fp_cert_fetch_autonat': {
            'type': 'str',
            'choices': ['auto']
            },
        'fp_cert_fetch_autonat_precedence': {
            'type': 'bool',
            },
        'forward_proxy_no_sni_action': {
            'type': 'str',
            'choices': ['intercept', 'bypass', 'reset']
            },
        'case_insensitive': {
            'type': 'bool',
            },
        'class_list_name': {
            'type': 'str',
            },
        'multi_class_list': {
            'type': 'list',
            'multi_clist_name': {
                'type': 'str',
                }
            },
        'user_name_list': {
            'type': 'str',
            },
        'ad_group_list': {
            'type': 'str',
            },
        'exception_user_name_list': {
            'type': 'str',
            },
        'exception_ad_group_list': {
            'type': 'str',
            },
        'exception_sni_cl_name': {
            'type': 'str',
            },
        'inspect_list_name': {
            'type': 'str',
            },
        'inspect_certificate_subject_cl_name': {
            'type': 'str',
            },
        'inspect_certificate_issuer_cl_name': {
            'type': 'str',
            },
        'inspect_certificate_san_cl_name': {
            'type': 'str',
            },
        'contains_list': {
            'type': 'list',
            'contains': {
                'type': 'str',
                }
            },
        'ends_with_list': {
            'type': 'list',
            'ends_with': {
                'type': 'str',
                }
            },
        'equals_list': {
            'type': 'list',
            'equals': {
                'type': 'str',
                }
            },
        'starts_with_list': {
            'type': 'list',
            'starts_with': {
                'type': 'str',
                }
            },
        'certificate_subject_contains_list': {
            'type': 'list',
            'certificate_subject_contains': {
                'type': 'str',
                }
            },
        'bypass_cert_subject_class_list_name': {
            'type': 'str',
            },
        'bypass_cert_subject_multi_class_list': {
            'type': 'list',
            'bypass_cert_subject_multi_class_list_name': {
                'type': 'str',
                }
            },
        'exception_certificate_subject_cl_name': {
            'type': 'str',
            },
        'certificate_subject_ends_with_list': {
            'type': 'list',
            'certificate_subject_ends_with': {
                'type': 'str',
                }
            },
        'certificate_subject_equals_list': {
            'type': 'list',
            'certificate_subject_equals': {
                'type': 'str',
                }
            },
        'certificate_subject_starts_with_list': {
            'type': 'list',
            'certificate_subject_starts': {
                'type': 'str',
                }
            },
        'certificate_issuer_contains_list': {
            'type': 'list',
            'certificate_issuer_contains': {
                'type': 'str',
                }
            },
        'bypass_cert_issuer_class_list_name': {
            'type': 'str',
            },
        'bypass_cert_issuer_multi_class_list': {
            'type': 'list',
            'bypass_cert_issuer_multi_class_list_name': {
                'type': 'str',
                }
            },
        'exception_certificate_issuer_cl_name': {
            'type': 'str',
            },
        'certificate_issuer_ends_with_list': {
            'type': 'list',
            'certificate_issuer_ends_with': {
                'type': 'str',
                }
            },
        'certificate_issuer_equals_list': {
            'type': 'list',
            'certificate_issuer_equals': {
                'type': 'str',
                }
            },
        'certificate_issuer_starts_with_list': {
            'type': 'list',
            'certificate_issuer_starts': {
                'type': 'str',
                }
            },
        'certificate_san_contains_list': {
            'type': 'list',
            'certificate_san_contains': {
                'type': 'str',
                }
            },
        'bypass_cert_san_class_list_name': {
            'type': 'str',
            },
        'bypass_cert_san_multi_class_list': {
            'type': 'list',
            'bypass_cert_san_multi_class_list_name': {
                'type': 'str',
                }
            },
        'exception_certificate_san_cl_name': {
            'type': 'str',
            },
        'certificate_san_ends_with_list': {
            'type': 'list',
            'certificate_san_ends_with': {
                'type': 'str',
                }
            },
        'certificate_san_equals_list': {
            'type': 'list',
            'certificate_san_equals': {
                'type': 'str',
                }
            },
        'certificate_san_starts_with_list': {
            'type': 'list',
            'certificate_san_starts': {
                'type': 'str',
                }
            },
        'client_auth_case_insensitive': {
            'type': 'bool',
            },
        'client_auth_class_list': {
            'type': 'str',
            },
        'client_auth_contains_list': {
            'type': 'list',
            'client_auth_contains': {
                'type': 'str',
                }
            },
        'client_auth_ends_with_list': {
            'type': 'list',
            'client_auth_ends_with': {
                'type': 'str',
                }
            },
        'client_auth_equals_list': {
            'type': 'list',
            'client_auth_equals': {
                'type': 'str',
                }
            },
        'client_auth_starts_with_list': {
            'type': 'list',
            'client_auth_starts_with': {
                'type': 'str',
                }
            },
        'forward_proxy_cert_not_ready_action': {
            'type': 'str',
            'choices': ['bypass', 'reset', 'intercept']
            },
        'web_reputation': {
            'type': 'dict',
            'bypass_trustworthy': {
                'type': 'bool',
                },
            'bypass_low_risk': {
                'type': 'bool',
                },
            'bypass_moderate_risk': {
                'type': 'bool',
                },
            'bypass_suspicious': {
                'type': 'bool',
                },
            'bypass_malicious': {
                'type': 'bool',
                },
            'bypass_threshold': {
                'type': 'int',
                }
            },
        'exception_web_reputation': {
            'type': 'dict',
            'exception_trustworthy': {
                'type': 'bool',
                },
            'exception_low_risk': {
                'type': 'bool',
                },
            'exception_moderate_risk': {
                'type': 'bool',
                },
            'exception_suspicious': {
                'type': 'bool',
                },
            'exception_malicious': {
                'type': 'bool',
                },
            'exception_threshold': {
                'type': 'int',
                }
            },
        'web_category': {
            'type': 'dict',
            'bypassed_category': {
                'type':
                'str',
                'choices': [
                    'uncategorized', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools',
                    'training-and-tools', 'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games',
                    'philosophy-and-politics', 'weapons', 'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals',
                    'web-advertisements', 'cheating', 'gross', 'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'cdns', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'spam-urls',
                    'dynamically-generated-content', 'parked-domains', 'alcohol-and-tobacco', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'self-harm', 'dns-over-https', 'low-thc-cannabis-products', 'generative-ai', 'nudity-artistic', 'illegal-pornography'
                    ]
                }
            },
        'exception_web_category': {
            'type': 'dict',
            'exception_category': {
                'type':
                'str',
                'choices': [
                    'uncategorized', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools',
                    'training-and-tools', 'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games',
                    'philosophy-and-politics', 'weapons', 'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals',
                    'web-advertisements', 'cheating', 'gross', 'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'cdns', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'spam-urls',
                    'dynamically-generated-content', 'parked-domains', 'alcohol-and-tobacco', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'self-harm', 'dns-over-https', 'low-thc-cannabis-products', 'generative-ai', 'nudity-artistic', 'illegal-pornography'
                    ]
                }
            },
        'require_web_category': {
            'type': 'bool',
            },
        'client_ipv4_list': {
            'type': 'list',
            'client_ipv4_list_name': {
                'type': 'str',
                }
            },
        'client_ipv6_list': {
            'type': 'list',
            'client_ipv6_list_name': {
                'type': 'str',
                }
            },
        'server_ipv4_list': {
            'type': 'list',
            'server_ipv4_list_name': {
                'type': 'str',
                }
            },
        'server_ipv6_list': {
            'type': 'list',
            'server_ipv6_list_name': {
                'type': 'str',
                }
            },
        'exception_client_ipv4_list': {
            'type': 'list',
            'exception_client_ipv4_list_name': {
                'type': 'str',
                }
            },
        'exception_client_ipv6_list': {
            'type': 'list',
            'exception_client_ipv6_list_name': {
                'type': 'str',
                }
            },
        'exception_server_ipv4_list': {
            'type': 'list',
            'exception_server_ipv4_list_name': {
                'type': 'str',
                }
            },
        'exception_server_ipv6_list': {
            'type': 'list',
            'exception_server_ipv6_list_name': {
                'type': 'str',
                }
            },
        'local_cert_pin_list': {
            'type': 'dict',
            'local_cert_pin_list_bypass_fail_count': {
                'type': 'int',
                }
            },
        'central_cert_pin_list': {
            'type': 'bool',
            },
        'forward_proxy_require_sni_cert_matched': {
            'type': 'str',
            'choices': ['no-match-action-inspect', 'no-match-action-drop']
            },
        'template_cipher': {
            'type': 'str',
            },
        'shared_partition_cipher_template': {
            'type': 'bool',
            },
        'template_cipher_shared': {
            'type': 'str',
            },
        'template_hsm': {
            'type': 'str',
            },
        'hsm_type': {
            'type': 'str',
            'choices': ['thales-embed', 'thales-hwcrhk']
            },
        'cipher_without_prio_list': {
            'type': 'list',
            'cipher_wo_prio': {
                'type':
                'str',
                'choices': [
                    'SSL3_RSA_DES_192_CBC3_SHA', 'SSL3_RSA_RC4_128_MD5', 'SSL3_RSA_RC4_128_SHA', 'TLS1_RSA_AES_128_SHA', 'TLS1_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_SHA256', 'TLS1_RSA_AES_256_SHA256', 'TLS1_DHE_RSA_AES_128_GCM_SHA256', 'TLS1_DHE_RSA_AES_128_SHA', 'TLS1_DHE_RSA_AES_128_SHA256', 'TLS1_DHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_DHE_RSA_AES_256_SHA', 'TLS1_DHE_RSA_AES_256_SHA256', 'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256', 'TLS1_ECDHE_ECDSA_AES_128_SHA', 'TLS1_ECDHE_ECDSA_AES_128_SHA256', 'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_ECDSA_AES_256_SHA', 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256', 'TLS1_ECDHE_RSA_AES_128_SHA',
                    'TLS1_ECDHE_RSA_AES_128_SHA256', 'TLS1_ECDHE_RSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_GCM_SHA256', 'TLS1_RSA_AES_256_GCM_SHA384', 'TLS1_ECDHE_RSA_AES_256_SHA384', 'TLS1_ECDHE_ECDSA_AES_256_SHA384', 'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256', 'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'
                    ]
                }
            },
        'server_name_list': {
            'type': 'list',
            'server_name': {
                'type': 'str',
                },
            'server_cert': {
                'type': 'str',
                },
            'server_chain': {
                'type': 'str',
                },
            'server_key': {
                'type': 'str',
                },
            'server_passphrase': {
                'type': 'str',
                },
            'server_encrypted': {
                'type': 'str',
                },
            'server_name_alternate': {
                'type': 'bool',
                },
            'server_shared': {
                'type': 'bool',
                },
            'sni_template': {
                'type': 'bool',
                },
            'sni_template_client_ssl': {
                'type': 'str',
                },
            'sni_shared_partition_client_ssl_template': {
                'type': 'bool',
                },
            'sni_template_client_ssl_shared_name': {
                'type': 'str',
                },
            'server_name_regex': {
                'type': 'str',
                },
            'server_cert_regex': {
                'type': 'str',
                },
            'server_chain_regex': {
                'type': 'str',
                },
            'server_key_regex': {
                'type': 'str',
                },
            'server_passphrase_regex': {
                'type': 'str',
                },
            'server_encrypted_regex': {
                'type': 'str',
                },
            'server_name_regex_alternate': {
                'type': 'bool',
                },
            'server_shared_regex': {
                'type': 'bool',
                },
            'sni_regex_template': {
                'type': 'bool',
                },
            'sni_regex_template_client_ssl': {
                'type': 'str',
                },
            'sni_regex_shared_partition_client_ssl_template': {
                'type': 'bool',
                },
            'sni_regex_template_client_ssl_shared_name': {
                'type': 'str',
                }
            },
        'server_name_auto_map': {
            'type': 'bool',
            },
        'sni_enable_log': {
            'type': 'bool',
            },
        'sni_bypass_missing_cert': {
            'type': 'bool',
            },
        'sni_bypass_expired_cert': {
            'type': 'bool',
            },
        'sni_bypass_explicit_list': {
            'type': 'str',
            },
        'sni_bypass_enable_log': {
            'type': 'bool',
            },
        'direct_client_server_auth': {
            'type': 'bool',
            },
        'session_cache_size': {
            'type': 'int',
            },
        'session_cache_timeout': {
            'type': 'int',
            },
        'session_ticket_disable': {
            'type': 'bool',
            },
        'session_ticket_lifetime': {
            'type': 'int',
            },
        'ssl_false_start_disable': {
            'type': 'bool',
            },
        'disable_sslv3': {
            'type': 'bool',
            },
        'version': {
            'type': 'int',
            },
        'dgversion': {
            'type': 'int',
            },
        'renegotiation_disable': {
            'type': 'bool',
            },
        'sslv2_bypass_service_group': {
            'type': 'str',
            },
        'authorization': {
            'type': 'bool',
            },
        'authen_name': {
            'type': 'str',
            },
        'ldap_base_dn_from_cert': {
            'type': 'bool',
            },
        'ldap_search_filter': {
            'type': 'str',
            },
        'auth_sg': {
            'type': 'str',
            },
        'auth_sg_dn': {
            'type': 'bool',
            },
        'auth_sg_filter': {
            'type': 'str',
            },
        'auth_username_attribute': {
            'type': 'str',
            },
        'non_ssl_bypass_service_group': {
            'type': 'str',
            },
        'non_ssl_bypass_l4session': {
            'type': 'bool',
            },
        'enable_ssli_ftp_alg': {
            'type': 'int',
            },
        'early_data': {
            'type': 'bool',
            },
        'no_anti_replay': {
            'type': 'bool',
            },
        'ja3_enable': {
            'type': 'bool',
            },
        'ja3_insert_http_header': {
            'type': 'str',
            },
        'ja3_reject_class_list': {
            'type': 'str',
            },
        'ja3_reject_max_number_per_host': {
            'type': 'int',
            },
        'ja3_ttl': {
            'type': 'int',
            },
        'ja4_enable': {
            'type': 'bool',
            },
        'ja4_insert_http_header': {
            'type': 'str',
            },
        'ja4_reject_class_list': {
            'type': 'str',
            },
        'ja4_reject_max_number_per_host': {
            'type': 'int',
            },
        'ja4_ttl': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools', 'training-and-tools',
                    'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games', 'philosophy-and-politics', 'weapons',
                    'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals', 'web-advertisements', 'cheating', 'gross',
                    'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'CDNs', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'confirmed-SPAM-sources', 'SPAM-URLs', 'unconfirmed-SPAM-sources',
                    'open-HTTP-proxies', 'dynamically-generated-content', 'parked-domains', 'alcohol-and-tobacco', 'private-IP-addresses', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'food-and-dining', 'dummy-item', 'self-harm', 'dns-over-https', 'low-thc-cannabis-products',
                    'generative-ai', 'nudity-artistic', 'illegal-pornography', 'uncategorised', 'other-category', 'trustworthy', 'low-risk', 'moderate-risk', 'suspicious', 'malicious'
                    ]
                }
            },
        'certificate_list': {
            'type': 'list',
            'cert': {
                'type': 'str',
                'required': True,
                },
            'key': {
                'type': 'str',
                },
            'passphrase': {
                'type': 'str',
                },
            'key_encrypted': {
                'type': 'str',
                },
            'chain_cert': {
                'type': 'str',
                },
            'shared': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'cert_status_list': {
                'type': 'list',
                'cert_status_name': {
                    'type': 'str',
                    },
                'cert_status_status': {
                    'type': 'str',
                    },
                'cert_status_age': {
                    'type': 'int',
                    },
                'cert_status_next_update': {
                    'type': 'str',
                    },
                'cert_status_responder': {
                    'type': 'str',
                    }
                },
            'name': {
                'type': 'str',
                'required': True,
                }
            },
        'stats': {
            'type': 'dict',
            'real_estate': {
                'type': 'str',
                },
            'computer_and_internet_security': {
                'type': 'str',
                },
            'financial_services': {
                'type': 'str',
                },
            'business_and_economy': {
                'type': 'str',
                },
            'computer_and_internet_info': {
                'type': 'str',
                },
            'auctions': {
                'type': 'str',
                },
            'shopping': {
                'type': 'str',
                },
            'cult_and_occult': {
                'type': 'str',
                },
            'travel': {
                'type': 'str',
                },
            'drugs': {
                'type': 'str',
                },
            'adult_and_pornography': {
                'type': 'str',
                },
            'home_and_garden': {
                'type': 'str',
                },
            'military': {
                'type': 'str',
                },
            'social_network': {
                'type': 'str',
                },
            'dead_sites': {
                'type': 'str',
                },
            'stock_advice_and_tools': {
                'type': 'str',
                },
            'training_and_tools': {
                'type': 'str',
                },
            'dating': {
                'type': 'str',
                },
            'sex_education': {
                'type': 'str',
                },
            'religion': {
                'type': 'str',
                },
            'entertainment_and_arts': {
                'type': 'str',
                },
            'personal_sites_and_blogs': {
                'type': 'str',
                },
            'legal': {
                'type': 'str',
                },
            'local_information': {
                'type': 'str',
                },
            'streaming_media': {
                'type': 'str',
                },
            'job_search': {
                'type': 'str',
                },
            'gambling': {
                'type': 'str',
                },
            'translation': {
                'type': 'str',
                },
            'reference_and_research': {
                'type': 'str',
                },
            'shareware_and_freeware': {
                'type': 'str',
                },
            'peer_to_peer': {
                'type': 'str',
                },
            'marijuana': {
                'type': 'str',
                },
            'hacking': {
                'type': 'str',
                },
            'games': {
                'type': 'str',
                },
            'philosophy_and_politics': {
                'type': 'str',
                },
            'weapons': {
                'type': 'str',
                },
            'pay_to_surf': {
                'type': 'str',
                },
            'hunting_and_fishing': {
                'type': 'str',
                },
            'society': {
                'type': 'str',
                },
            'educational_institutions': {
                'type': 'str',
                },
            'online_greeting_cards': {
                'type': 'str',
                },
            'sports': {
                'type': 'str',
                },
            'swimsuits_and_intimate_apparel': {
                'type': 'str',
                },
            'questionable': {
                'type': 'str',
                },
            'kids': {
                'type': 'str',
                },
            'hate_and_racism': {
                'type': 'str',
                },
            'personal_storage': {
                'type': 'str',
                },
            'violence': {
                'type': 'str',
                },
            'keyloggers_and_monitoring': {
                'type': 'str',
                },
            'search_engines': {
                'type': 'str',
                },
            'internet_portals': {
                'type': 'str',
                },
            'web_advertisements': {
                'type': 'str',
                },
            'cheating': {
                'type': 'str',
                },
            'gross': {
                'type': 'str',
                },
            'web_based_email': {
                'type': 'str',
                },
            'malware_sites': {
                'type': 'str',
                },
            'phishing_and_other_fraud': {
                'type': 'str',
                },
            'proxy_avoid_and_anonymizers': {
                'type': 'str',
                },
            'spyware_and_adware': {
                'type': 'str',
                },
            'music': {
                'type': 'str',
                },
            'government': {
                'type': 'str',
                },
            'nudity': {
                'type': 'str',
                },
            'news_and_media': {
                'type': 'str',
                },
            'illegal': {
                'type': 'str',
                },
            'CDNs': {
                'type': 'str',
                },
            'internet_communications': {
                'type': 'str',
                },
            'bot_nets': {
                'type': 'str',
                },
            'abortion': {
                'type': 'str',
                },
            'health_and_medicine': {
                'type': 'str',
                },
            'confirmed_SPAM_sources': {
                'type': 'str',
                },
            'SPAM_URLs': {
                'type': 'str',
                },
            'unconfirmed_SPAM_sources': {
                'type': 'str',
                },
            'open_HTTP_proxies': {
                'type': 'str',
                },
            'dynamically_generated_content': {
                'type': 'str',
                },
            'parked_domains': {
                'type': 'str',
                },
            'alcohol_and_tobacco': {
                'type': 'str',
                },
            'private_IP_addresses': {
                'type': 'str',
                },
            'image_and_video_search': {
                'type': 'str',
                },
            'fashion_and_beauty': {
                'type': 'str',
                },
            'recreation_and_hobbies': {
                'type': 'str',
                },
            'motor_vehicles': {
                'type': 'str',
                },
            'web_hosting_sites': {
                'type': 'str',
                },
            'food_and_dining': {
                'type': 'str',
                },
            'self_harm': {
                'type': 'str',
                },
            'dns_over_https': {
                'type': 'str',
                },
            'low_thc_cannabis_products': {
                'type': 'str',
                },
            'generative_ai': {
                'type': 'str',
                },
            'nudity_artistic': {
                'type': 'str',
                },
            'illegal_pornography': {
                'type': 'str',
                },
            'uncategorised': {
                'type': 'str',
                },
            'other_category': {
                'type': 'str',
                },
            'trustworthy': {
                'type': 'str',
                },
            'low_risk': {
                'type': 'str',
                },
            'moderate_risk': {
                'type': 'str',
                },
            'suspicious': {
                'type': 'str',
                },
            'malicious': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/client-ssl/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/client-ssl"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["client-ssl"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["client-ssl"].get(k) != v:
            change_results["changed"] = True
            config_changes["client-ssl"][k] = v

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
    payload = utils.build_json("client-ssl", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["client-ssl"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["client-ssl-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["client-ssl"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["client-ssl"]["stats"] if info != "NotFound" else info
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
