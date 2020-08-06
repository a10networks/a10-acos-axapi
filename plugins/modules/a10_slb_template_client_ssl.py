#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_client_ssl
description:
    - Client SSL Template
short_description: Configures A10 slb.template.client-ssl
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
    bypass_cert_subject_multi_class_list:
        description:
        - "Field bypass_cert_subject_multi_class_list"
        required: False
        suboptions:
            bypass_cert_subject_multi_class_list_name:
                description:
                - "Class List Name"
    verify_cert_fail_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        required: False
    inspect_certificate_issuer_cl_name:
        description:
        - "Forward proxy Inspect if Certificate issuer matches class-list"
        required: False
    certificate_san_contains_list:
        description:
        - "Field certificate_san_contains_list"
        required: False
        suboptions:
            certificate_san_contains:
                description:
                - "Forward proxy bypass if Certificate SAN contains another string"
    forward_proxy_block_message:
        description:
        - "Message to be included on the block page (Message, enclose in quotes if spaces
          are present)"
        required: False
    direct_client_server_auth:
        description:
        - "Let backend server does SSL client authentication directly"
        required: False
    ocspst_sg_hours:
        description:
        - "Specify update period, in hours"
        required: False
    no_shared_cipher_action:
        description:
        - "'bypass'= bypass SSLi processing; 'drop'= close the connection;"
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            name:
                description:
                - "Client SSL Template Name"
            cert_status_list:
                description:
                - "Field cert_status_list"
    fp_cert_fetch_autonat:
        description:
        - "'auto'= Configure auto NAT for server certificate fetching;"
        required: False
    equals_list:
        description:
        - "Field equals_list"
        required: False
        suboptions:
            equals:
                description:
                - "Forward proxy bypass if SNI string equals another string"
    exception_certificate_subject_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    forward_proxy_trusted_ca_lists:
        description:
        - "Field forward_proxy_trusted_ca_lists"
        required: False
        suboptions:
            forward_proxy_trusted_ca:
                description:
                - "Forward proxy trusted CA file (CA file name)"
    template_cipher_shared:
        description:
        - "Cipher Template Name"
        required: False
    forward_proxy_ca_cert:
        description:
        - "CA Certificate for forward proxy (SSL forward proxy CA Certificate Name)"
        required: False
    ssl_false_start_disable:
        description:
        - "disable SSL False Start"
        required: False
    dgversion:
        description:
        - "Lower TLS/SSL version can be downgraded"
        required: False
    client_auth_class_list:
        description:
        - "Forward proxy client auth bypass if SNI string matches class-list (Class List
          Name)"
        required: False
    key_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    notafteryear:
        description:
        - "Year"
        required: False
    forward_proxy_alt_sign:
        description:
        - "Forward proxy alternate signing cert and key"
        required: False
    template_hsm:
        description:
        - "HSM Template (HSM Template Name)"
        required: False
    forward_passphrase:
        description:
        - "Password Phrase"
        required: False
    exception_certificate_issuer_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        required: False
    contains_list:
        description:
        - "Field contains_list"
        required: False
        suboptions:
            contains:
                description:
                - "Forward proxy bypass if SNI string contains another string"
    forward_proxy_ca_key:
        description:
        - "CA Private Key for forward proxy (SSL forward proxy CA Key Name)"
        required: False
    notbefore:
        description:
        - "notBefore date"
        required: False
    ends_with_list:
        description:
        - "Field ends_with_list"
        required: False
        suboptions:
            ends_with:
                description:
                - "Forward proxy bypass if SNI string ends with another string"
    bypass_cert_subject_class_list_name:
        description:
        - "Class List Name"
        required: False
    notafter:
        description:
        - "notAfter date"
        required: False
    class_list_name:
        description:
        - "Class List Name"
        required: False
    ocspst_ocsp:
        description:
        - "Specify OCSP Authentication"
        required: False
    notbeforeday:
        description:
        - "Day"
        required: False
    key_alt_passphrase:
        description:
        - "Password Phrase"
        required: False
    forward_proxy_ssl_version:
        description:
        - "TLS/SSL version, default is TLS1.2 (TLS/SSL version= 31-TLSv1.0, 32-TLSv1.1 and
          33-TLSv1.2)"
        required: False
    ca_certs:
        description:
        - "Field ca_certs"
        required: False
        suboptions:
            ca_cert:
                description:
                - "CA Certificate (CA Certificate Name)"
            client_ocsp_sg:
                description:
                - "Specify service-group (Service group name)"
            client_ocsp:
                description:
                - "Specify ocsp authentication server(s) for client certificate verification"
            client_ocsp_srvr:
                description:
                - "Specify authentication server"
            ca_shared:
                description:
                - "CA Certificate Partition Shared"
    forward_proxy_crl_disable:
        description:
        - "Disable Certificate Revocation List checking for forward proxy"
        required: False
    client_auth_contains_list:
        description:
        - "Field client_auth_contains_list"
        required: False
        suboptions:
            client_auth_contains:
                description:
                - "Forward proxy bypass if SNI string contains another string"
    certificate_subject_contains_list:
        description:
        - "Field certificate_subject_contains_list"
        required: False
        suboptions:
            certificate_subject_contains:
                description:
                - "Forward proxy bypass if Certificate Subject contains another string"
    name:
        description:
        - "Client SSL Template Name"
        required: True
    forward_proxy_cert_revoke_action:
        description:
        - "Action taken if a certificate is irreversibly revoked, bypass SSLi processing
          by default"
        required: False
    fp_cert_ext_aia_ocsp:
        description:
        - "OCSP (Authority Information Access URI)"
        required: False
    req_ca_lists:
        description:
        - "Field req_ca_lists"
        required: False
        suboptions:
            client_certificate_Request_CA:
                description:
                - "Send CA lists in certificate request (CA Certificate Name)"
    user_tag:
        description:
        - "Customized tag"
        required: False
    cert_unknown_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
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
          proxies category; 'dynamic-comment'= dynamic comment category; 'parked-
          domains'= parked domains category; 'alcohol-and-tobacco'= alcohol and tobacco
          category; 'private-IP-addresses'= private IP addresses category; 'image-and-
          video-search'= image and video search category; 'fashion-and-beauty'= fashion
          and beauty category; 'recreation-and-hobbies'= recreation and hobbies category;
          'motor-vehicles'= motor vehicles category; 'web-hosting-sites'= web hosting
          sites category; 'food-and-dining'= food and dining category; 'uncategorised'=
          uncategorised; 'other-category'= other category;"
    renegotiation_disable:
        description:
        - "Disable SSL renegotiation"
        required: False
    exception_ad_group_list:
        description:
        - "Exceptions to forward proxy bypass if ad-group matches class-list"
        required: False
    key_alternate:
        description:
        - "Specify the second private key (Key Name)"
        required: False
    fp_alt_key:
        description:
        - "CA Private Key for forward proxy alternate signing (Key name)"
        required: False
    server_name_auto_map:
        description:
        - "Enable automatic mapping of server name indication in Client hello extension"
        required: False
    disable_sslv3:
        description:
        - "Reject Client requests for SSL version 3"
        required: False
    bypass_cert_issuer_multi_class_list:
        description:
        - "Field bypass_cert_issuer_multi_class_list"
        required: False
        suboptions:
            bypass_cert_issuer_multi_class_list_name:
                description:
                - "Class List Name"
    client_auth_equals_list:
        description:
        - "Field client_auth_equals_list"
        required: False
        suboptions:
            client_auth_equals:
                description:
                - "Forward proxy bypass if SNI string equals another string"
    forward_proxy_no_sni_action:
        description:
        - "'intercept'= intercept in no SNI case; 'bypass'= bypass in no SNI case;
          'reset'= reset in no SNI case;"
        required: False
    certificate_issuer_equals_list:
        description:
        - "Field certificate_issuer_equals_list"
        required: False
        suboptions:
            certificate_issuer_equals:
                description:
                - "Forward proxy bypass if Certificate issuer equals another string"
    fp_alt_passphrase:
        description:
        - "Password Phrase"
        required: False
    certificate_subject_starts_with_list:
        description:
        - "Field certificate_subject_starts_with_list"
        required: False
        suboptions:
            certificate_subject_starts:
                description:
                - "Forward proxy bypass if Certificate Subject starts with another string"
    certificate_san_ends_with_list:
        description:
        - "Field certificate_san_ends_with_list"
        required: False
        suboptions:
            certificate_san_ends_with:
                description:
                - "Forward proxy bypass if Certificate SAN ends with another string"
    forward_proxy_cert_cache_timeout:
        description:
        - "Certificate cache timeout, default is 1 hour (seconds, set to 0 for never
          timeout)"
        required: False
    fp_cert_fetch_natpool_name_shared:
        description:
        - "Specify NAT pool or pool group"
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        required: False
        suboptions:
            crl_shared:
                description:
                - "Certificate Revocation Lists Partition Shared"
            crl:
                description:
                - "Certificate Revocation Lists (Certificate Revocation Lists file name)"
    notafterday:
        description:
        - "Day"
        required: False
    ocspst_srvr_hours:
        description:
        - "Specify update period, in hours"
        required: False
    local_logging:
        description:
        - "Enable local logging"
        required: False
    fp_cert_fetch_autonat_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued
          under template policy"
        required: False
    cert_str:
        description:
        - "Certificate Name"
        required: False
    cert_shared_str:
        description:
        - "Certificate Name"
        required: False
    cert_revoke_action:
        description:
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'=
          close the connection; 'block'= block the connection with a warning page;"
        required: False
    version:
        description:
        - "TLS/SSL version, default is the highest number supported (TLS/SSL version=
          30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)"
        required: False
    multi_class_list:
        description:
        - "Field multi_class_list"
        required: False
        suboptions:
            multi_clist_name:
                description:
                - "Class List Name"
    user_name_list:
        description:
        - "Forward proxy bypass if user-name matches class-list"
        required: False
    session_ticket_lifetime:
        description:
        - "Session ticket lifetime in seconds from stateless session resumption (Lifetime
          value in seconds. Default value 0 (Session ticket lifetime limit disabled))"
        required: False
    certificate_issuer_ends_with_list:
        description:
        - "Field certificate_issuer_ends_with_list"
        required: False
        suboptions:
            certificate_issuer_ends_with:
                description:
                - "Forward proxy bypass if Certificate issuer ends with another string"
    ssli_logging:
        description:
        - "SSLi logging level, default is error logging only"
        required: False
    session_cache_size:
        description:
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse
          disabled))"
        required: False
    handshake_logging_enable:
        description:
        - "Enable SSL handshake logging"
        required: False
    non_ssl_bypass_service_group:
        description:
        - "Service Group for Bypass non-ssl traffic (Service Group Name)"
        required: False
    forward_proxy_failsafe_disable:
        description:
        - "Disable Failsafe for SSL forward proxy"
        required: False
    session_cache_timeout:
        description:
        - "Session Cache Timeout (Timeout value, in seconds. Default value 0 (Session
          cache timeout disabled))"
        required: False
    sslv2_bypass_service_group:
        description:
        - "Service Group for Bypass SSLV2 (Service Group Name)"
        required: False
    forward_proxy_decrypted_dscp:
        description:
        - "Apply a DSCP to decrypted and bypassed traffic (DSCP to apply to decrypted
          traffic)"
        required: False
    auth_sg:
        description:
        - "Specify authorization LDAP service group"
        required: False
    ocspst_ca_cert:
        description:
        - "CA certificate"
        required: False
    forward_proxy_selfsign_redir:
        description:
        - "Redirect connections to pages with self signed certs to a warning page"
        required: False
    auth_sg_dn:
        description:
        - "Use Subject DN as LDAP search base DN"
        required: False
    hsm_type:
        description:
        - "'thales-embed'= Thales embed key; 'thales-hwcrhk'= Thales hwcrhk Key;"
        required: False
    forward_proxy_log_disable:
        description:
        - "Disable SSL forward proxy logging"
        required: False
    fp_alt_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    inspect_certificate_san_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject Alternative Name matches class-
          list"
        required: False
    web_category:
        description:
        - "Field web_category"
        required: False
        suboptions:
            philosophy_and_politics:
                description:
                - "Category Philosophy and Political Advocacy"
            stock_advice_and_tools:
                description:
                - "Category Stock Advice and Tools"
            news_and_media:
                description:
                - "Category News and Media"
            business_and_economy:
                description:
                - "Category Business and Economy"
            peer_to_peer:
                description:
                - "Category Peer to Peer"
            phishing_and_other_fraud:
                description:
                - "Category Phishing and Other Frauds"
            nudity:
                description:
                - "Category Nudity"
            weapons:
                description:
                - "Category Weapons"
            health_and_medicine:
                description:
                - "Category Health and Medicine"
            marijuana:
                description:
                - "Category Marijuana"
            home_and_garden:
                description:
                - "Category Home and Garden"
            cult_and_occult:
                description:
                - "Category Cult and Occult"
            society:
                description:
                - "Category Society"
            personal_storage:
                description:
                - "Category Personal Storage"
            computer_and_internet_security:
                description:
                - "Category Computer and Internet Security"
            food_and_dining:
                description:
                - "Category Food and Dining"
            motor_vehicles:
                description:
                - "Category Motor Vehicles"
            swimsuits_and_intimate_apparel:
                description:
                - "Category Swimsuits and Intimate Apparel"
            dead_sites:
                description:
                - "Category Dead Sites (db Ops only)"
            translation:
                description:
                - "Category Translation"
            proxy_avoid_and_anonymizers:
                description:
                - "Category Proxy Avoid and Anonymizers"
            financial_services:
                description:
                - "Category Financial Services"
            gross:
                description:
                - "Category Gross"
            cheating:
                description:
                - "Category Cheating"
            entertainment_and_arts:
                description:
                - "Category Entertainment and Arts"
            sex_education:
                description:
                - "Category Sex Education"
            illegal:
                description:
                - "Category Illegal"
            travel:
                description:
                - "Category Travel"
            cdns:
                description:
                - "Category CDNs"
            local_information:
                description:
                - "Category Local Information"
            legal:
                description:
                - "Category Legal"
            sports:
                description:
                - "Category Sports"
            bot_nets:
                description:
                - "Category Bot Nets"
            religion:
                description:
                - "Category Religion"
            private_ip_addresses:
                description:
                - "Category Private IP Addresses"
            music:
                description:
                - "Category Music"
            hate_and_racism:
                description:
                - "Category Hate and Racism"
            open_http_proxies:
                description:
                - "Category Open HTTP Proxies"
            internet_communications:
                description:
                - "Category Internet Communications"
            shareware_and_freeware:
                description:
                - "Category Shareware and Freeware"
            dating:
                description:
                - "Category Dating"
            spyware_and_adware:
                description:
                - "Category Spyware and Adware"
            uncategorized:
                description:
                - "Uncategorized URLs"
            questionable:
                description:
                - "Category Questionable"
            reference_and_research:
                description:
                - "Category Reference and Research"
            web_advertisements:
                description:
                - "Category Web Advertisements"
            streaming_media:
                description:
                - "Category Streaming Media"
            social_network:
                description:
                - "Category Social Network"
            government:
                description:
                - "Category Government"
            drugs:
                description:
                - "Category Abused Drugs"
            web_hosting_sites:
                description:
                - "Category Web Hosting Sites"
            malware_sites:
                description:
                - "Category Malware Sites"
            pay_to_surf:
                description:
                - "Category Pay to Surf"
            spam_urls:
                description:
                - "Category SPAM URLs"
            kids:
                description:
                - "Category Kids"
            gambling:
                description:
                - "Category Gambling"
            online_greeting_cards:
                description:
                - "Category Online Greeting cards"
            confirmed_spam_sources:
                description:
                - "Category Confirmed SPAM Sources"
            image_and_video_search:
                description:
                - "Category Image and Video Search"
            educational_institutions:
                description:
                - "Category Educational Institutions"
            keyloggers_and_monitoring:
                description:
                - "Category Keyloggers and Monitoring"
            hunting_and_fishing:
                description:
                - "Category Hunting and Fishing"
            search_engines:
                description:
                - "Category Search Engines"
            fashion_and_beauty:
                description:
                - "Category Fashion and Beauty"
            dynamic_comment:
                description:
                - "Category Dynamic Comment"
            computer_and_internet_info:
                description:
                - "Category Computer and Internet Info"
            real_estate:
                description:
                - "Category Real Estate"
            internet_portals:
                description:
                - "Category Internet Portals"
            shopping:
                description:
                - "Category Shopping"
            violence:
                description:
                - "Category Violence"
            abortion:
                description:
                - "Category Abortion"
            training_and_tools:
                description:
                - "Category Training and Tools"
            web_based_email:
                description:
                - "Category Web based email"
            personal_sites_and_blogs:
                description:
                - "Category Personal sites and Blogs"
            unconfirmed_spam_sources:
                description:
                - "Category Unconfirmed SPAM Sources"
            games:
                description:
                - "Category Games"
            parked_domains:
                description:
                - "Category Parked Domains"
            auctions:
                description:
                - "Category Auctions"
            job_search:
                description:
                - "Category Job Search"
            recreation_and_hobbies:
                description:
                - "Category Recreation and Hobbies"
            hacking:
                description:
                - "Category Hacking"
            alcohol_and_tobacco:
                description:
                - "Category Alcohol and Tobacco"
            adult_and_pornography:
                description:
                - "Category Adult and Pornography"
            military:
                description:
                - "Category Military"
    certificate_san_equals_list:
        description:
        - "Field certificate_san_equals_list"
        required: False
        suboptions:
            certificate_san_equals:
                description:
                - "Forward proxy bypass if Certificate SAN equals another string"
    template_cipher:
        description:
        - "Cipher Template Name"
        required: False
    notbeforemonth:
        description:
        - "Month"
        required: False
    bypass_cert_san_class_list_name:
        description:
        - "Class List Name"
        required: False
    chain_cert:
        description:
        - "Chain Certificate Name"
        required: False
    forward_proxy_cert_unknown_action:
        description:
        - "Action taken if a certificate revocation status is unknown, bypass SSLi
          processing by default"
        required: False
    exception_certificate_san_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        required: False
    ocspst_sg:
        description:
        - "Specify authentication service group"
        required: False
    key_alt_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    fp_cert_ext_aia_ca_issuers:
        description:
        - "CA Issuers (Authority Information Access URI)"
        required: False
    authen_name:
        description:
        - "Specify authorization LDAP server name"
        required: False
    expire_hours:
        description:
        - "Certificate lifetime in hours"
        required: False
    client_auth_case_insensitive:
        description:
        - "Case insensitive forward proxy client auth bypass"
        required: False
    ocsp_stapling:
        description:
        - "Config OCSP stapling support"
        required: False
    notbeforeyear:
        description:
        - "Year"
        required: False
    forward_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            stock_advice_and_tools:
                description:
                - "stock advice and tools category"
            news_and_media:
                description:
                - "news and media category"
            CDNs:
                description:
                - "content delivery networks category"
            cult_and_occult:
                description:
                - "cult and occult category"
            fashion_and_beauty:
                description:
                - "fashion and beauty category"
            food_and_dining:
                description:
                - "food and dining category"
            SPAM_URLs:
                description:
                - "SPAM URLs category"
            streaming_media:
                description:
                - "streaming media category"
            bot_nets:
                description:
                - "bot nets category"
            cheating:
                description:
                - "cheating category"
            entertainment_and_arts:
                description:
                - "entertainment and arts category"
            illegal:
                description:
                - "illegal category"
            local_information:
                description:
                - "local information category"
            sports:
                description:
                - "sports category"
            confirmed_SPAM_sources:
                description:
                - "confirmed SPAM sources category"
            private_IP_addresses:
                description:
                - "private IP addresses category"
            music:
                description:
                - "music category"
            open_HTTP_proxies:
                description:
                - "open HTTP proxies category"
            shareware_and_freeware:
                description:
                - "shareware and freeware category"
            spyware_and_adware:
                description:
                - "spyware and adware category"
            questionable:
                description:
                - "questionable category"
            financial_services:
                description:
                - "financial services category"
            social_network:
                description:
                - "social network category"
            government:
                description:
                - "government category"
            drugs:
                description:
                - "drugs category"
            web_hosting_sites:
                description:
                - "web hosting sites category"
            web_advertisements:
                description:
                - "web advertisements category"
            educational_institutions:
                description:
                - "educational institutions category"
            dynamic_comment:
                description:
                - "dynamic comment category"
            translation:
                description:
                - "translation category"
            job_search:
                description:
                - "job search category"
            hunting_and_fishing:
                description:
                - "hunting and fishing category"
            search_engines:
                description:
                - "search engines category"
            peer_to_peer:
                description:
                - "peer to peer category"
            computer_and_internet_security:
                description:
                - "computer and internet security category"
            real_estate:
                description:
                - "real estate category"
            computer_and_internet_info:
                description:
                - "computer and internet info category"
            internet_portals:
                description:
                - "internet portals category"
            shopping:
                description:
                - "shopping category"
            philosophy_and_politics:
                description:
                - "philosophy and politics category"
            web_based_email:
                description:
                - "web based email category"
            recreation_and_hobbies:
                description:
                - "recreation and hobbies category"
            hacking:
                description:
                - "hacking category"
            adult_and_pornography:
                description:
                - "adult and pornography category"
            business_and_economy:
                description:
                - "business and economy category"
            phishing_and_other_fraud:
                description:
                - "phishing and other fraud category"
            nudity:
                description:
                - "nudity category"
            health_and_medicine:
                description:
                - "health and medicine category"
            marijuana:
                description:
                - "marijuana category"
            home_and_garden:
                description:
                - "home and garden category"
            society:
                description:
                - "society category"
            unconfirmed_SPAM_sources:
                description:
                - "unconfirmed SPAM sources category"
            personal_storage:
                description:
                - "personal storage category"
            motor_vehicles:
                description:
                - "motor vehicles category"
            swimsuits_and_intimate_apparel:
                description:
                - "swimsuits and intimate apparel category"
            dead_sites:
                description:
                - "dead sites category"
            other_category:
                description:
                - "other category"
            proxy_avoid_and_anonymizers:
                description:
                - "proxy avoid and anonymizers category"
            gross:
                description:
                - "gross category"
            uncategorised:
                description:
                - "uncategorised"
            travel:
                description:
                - "travel category"
            legal:
                description:
                - "legal category"
            weapons:
                description:
                - "weapons category"
            religion:
                description:
                - "religion category"
            hate_and_racism:
                description:
                - "hate and racism category"
            internet_communications:
                description:
                - "internet communications category"
            gambling:
                description:
                - "gambling category"
            dating:
                description:
                - "dating category"
            malware_sites:
                description:
                - "malware sites category"
            name:
                description:
                - "Client SSL Template Name"
            pay_to_surf:
                description:
                - "pay to surf category"
            military:
                description:
                - "military category"
            image_and_video_search:
                description:
                - "image and video search category"
            reference_and_research:
                description:
                - "reference and research category"
            keyloggers_and_monitoring:
                description:
                - "keyloggers and monitoring category"
            kids:
                description:
                - "kids category"
            online_greeting_cards:
                description:
                - "online greeting cards category"
            violence:
                description:
                - "violence category"
            training_and_tools:
                description:
                - "training and tools category"
            sex_education:
                description:
                - "sex education category"
            personal_sites_and_blogs:
                description:
                - "personal sites and blogs category"
            games:
                description:
                - "games category"
            parked_domains:
                description:
                - "parked domains category"
            auctions:
                description:
                - "auctions category"
            abortion:
                description:
                - "abortion category"
            alcohol_and_tobacco:
                description:
                - "alcohol and tobacco category"
    sni_enable_log:
        description:
        - "Enable logging of sni-auto-map failures. Disable by default"
        required: False
    key_shared_str:
        description:
        - "Key Name"
        required: False
    notaftermonth:
        description:
        - "Month"
        required: False
    cache_persistence_list_name:
        description:
        - "Class List Name"
        required: False
    ocspst_sg_timeout:
        description:
        - "Specify retry timeout (Default is 30 mins)"
        required: False
    key_passphrase:
        description:
        - "Password Phrase"
        required: False
    ocspst_srvr:
        description:
        - "Specify OCSP authentication server"
        required: False
    ocspst_srvr_minutes:
        description:
        - "Specify update period, in minutes"
        required: False
    certificate_issuer_contains_list:
        description:
        - "Field certificate_issuer_contains_list"
        required: False
        suboptions:
            certificate_issuer_contains:
                description:
                - "Forward proxy bypass if Certificate  issuer contains another string
          (Certificate issuer)"
    require_web_category:
        description:
        - "Wait for web category to be resolved before taking bypass decision"
        required: False
    bypass_cert_san_multi_class_list:
        description:
        - "Field bypass_cert_san_multi_class_list"
        required: False
        suboptions:
            bypass_cert_san_multi_class_list_name:
                description:
                - "Class List Name"
    client_auth_starts_with_list:
        description:
        - "Field client_auth_starts_with_list"
        required: False
        suboptions:
            client_auth_starts_with:
                description:
                - "Forward proxy bypass if SNI string starts with another string"
    certificate_subject_ends_with_list:
        description:
        - "Field certificate_subject_ends_with_list"
        required: False
        suboptions:
            certificate_subject_ends_with:
                description:
                - "Forward proxy bypass if Certificate Subject ends with another string"
    authorization:
        description:
        - "Specify LDAP server for client SSL authorizaiton"
        required: False
    forward_proxy_verify_cert_fail_action:
        description:
        - "Action taken if certificate verification fails, close the connection by default"
        required: False
    ocspst_srvr_days:
        description:
        - "Specify update period, in days"
        required: False
    ec_list:
        description:
        - "Field ec_list"
        required: False
        suboptions:
            ec:
                description:
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1;"
    forward_proxy_decrypted_dscp_bypass:
        description:
        - "DSCP to apply to bypassed traffic"
        required: False
    alert_type:
        description:
        - "'fatal'= Log fatal alerts;"
        required: False
    forward_proxy_cert_not_ready_action:
        description:
        - "'bypass'= bypass the connection; 'reset'= reset the connection; 'intercept'=
          wait for cert and then inspect the connection;"
        required: False
    server_name_list:
        description:
        - "Field server_name_list"
        required: False
        suboptions:
            server_shared:
                description:
                - "Server Name Partition Shared"
            server_passphrase_regex:
                description:
                - "help Password Phrase"
            server_chain:
                description:
                - "Server Certificate Chain associated to SNI (Server Certificate Chain Name)"
            server_cert_regex:
                description:
                - "Server Certificate associated to SNI regex (Server Certificate Name)"
            server_name:
                description:
                - "Server name indication in Client hello extension (Server name String)"
            server_key_regex:
                description:
                - "Server Private Key associated to SNI regex (Server Private Key Name)"
            server_name_regex_alternate:
                description:
                - "Specific the second certifcate"
            server_encrypted_regex:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
            server_shared_regex:
                description:
                - "Server Name Partition Shared"
            server_name_regex:
                description:
                - "Server name indication in Client hello extension with regular expression
          (Server name String with regex)"
            server_passphrase:
                description:
                - "help Password Phrase"
            server_key:
                description:
                - "Server Private Key associated to SNI (Server Private Key Name)"
            server_chain_regex:
                description:
                - "Server Certificate Chain associated to SNI regex (Server Certificate Chain
          Name)"
            server_name_alternate:
                description:
                - "Specific the second certifcate"
            server_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
            server_cert:
                description:
                - "Server Certificate associated to SNI (Server Certificate Name)"
    bypass_cert_issuer_class_list_name:
        description:
        - "Class List Name"
        required: False
    fp_cert_ext_crldp:
        description:
        - "CRL Distribution Point (CRL Distribution Point URI)"
        required: False
    shared_partition_cipher_template:
        description:
        - "Reference a cipher template from shared partition"
        required: False
    fp_cert_fetch_natpool_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued
          under template policy"
        required: False
    cert_alternate:
        description:
        - "Specify the second certificate (Certificate Name)"
        required: False
    forward_proxy_cert_cache_limit:
        description:
        - "Certificate cache size limit, default is 524288 (set to 0 for unlimited size)"
        required: False
    non_ssl_bypass_l4session:
        description:
        - "Handle the non-ssl session as L4 for performance optimization"
        required: False
    certificate_issuer_starts_with_list:
        description:
        - "Field certificate_issuer_starts_with_list"
        required: False
        suboptions:
            certificate_issuer_starts:
                description:
                - "Forward proxy bypass if Certificate issuer starts with another string"
    certificate_san_starts_with_list:
        description:
        - "Field certificate_san_starts_with_list"
        required: False
        suboptions:
            certificate_san_starts:
                description:
                - "Forward proxy bypass if Certificate SAN starts with another string"
    client_auth_ends_with_list:
        description:
        - "Field client_auth_ends_with_list"
        required: False
        suboptions:
            client_auth_ends_with:
                description:
                - "Forward proxy bypass if SNI string ends with another string"
    close_notify:
        description:
        - "Send close notification when terminate connection"
        required: False
    forward_proxy_no_shared_cipher_action:
        description:
        - "Action taken if handshake fails due to no shared ciper, close the connection by
          default"
        required: False
    forward_proxy_ocsp_disable:
        description:
        - "Disable ocsp-stapling for forward proxy"
        required: False
    sslilogging:
        description:
        - "'disable'= Disable all logging; 'all'= enable all logging(error, info);"
        required: False
    auth_username:
        description:
        - "Specify the Username Field in the Client Certificate(If multi-fields are
          specificed, prior one has higher priority)"
        required: False
    exception_user_name_list:
        description:
        - "Exceptions to forward proxy bypass if user-name matches class-list"
        required: False
    ocspst_sg_days:
        description:
        - "Specify update period, in days"
        required: False
    key_str:
        description:
        - "Key Name"
        required: False
    inspect_list_name:
        description:
        - "Class List Name"
        required: False
    auth_username_attribute:
        description:
        - "Specify attribute name of username for client SSL authorization"
        required: False
    fp_cert_fetch_natpool_name:
        description:
        - "Specify NAT pool or pool group"
        required: False
    exception_sni_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
        required: False
    inspect_certificate_subject_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject matches class-list"
        required: False
    ldap_base_dn_from_cert:
        description:
        - "Use Subject DN as LDAP search base DN"
        required: False
    ad_group_list:
        description:
        - "Forward proxy bypass if ad-group matches class-list"
        required: False
    client_certificate:
        description:
        - "'Ignore'= Don't request client certificate; 'Require'= Require client
          certificate; 'Request'= Request client certificate;"
        required: False
    forward_proxy_cert_expiry:
        description:
        - "Adjust certificate expiry relative to the time when it is created on the device"
        required: False
    forward_proxy_enable:
        description:
        - "Enable SSL forward proxy"
        required: False
    shared_partition_pool:
        description:
        - "Reference a NAT pool or pool group from shared partition"
        required: False
    ldap_search_filter:
        description:
        - "Specify LDAP search filter"
        required: False
    key_shared_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        required: False
    auth_sg_filter:
        description:
        - "Specify LDAP search filter"
        required: False
    ocspst_srvr_timeout:
        description:
        - "Specify retry timeout (Default is 30 mins)"
        required: False
    certificate_subject_equals_list:
        description:
        - "Field certificate_subject_equals_list"
        required: False
        suboptions:
            certificate_subject_equals:
                description:
                - "Forward proxy bypass if Certificate Subject equals another string"
    chain_cert_shared_str:
        description:
        - "Chain Certificate Name"
        required: False
    enable_tls_alert_logging:
        description:
        - "Enable TLS alert logging"
        required: False
    dh_type:
        description:
        - "'1024'= 1024; '1024-dsa'= 1024-dsa; '2048'= 2048;"
        required: False
    fp_alt_cert:
        description:
        - "CA Certificate for forward proxy alternate signing (Certificate name)"
        required: False
    case_insensitive:
        description:
        - "Case insensitive forward proxy bypass"
        required: False
    cipher_without_prio_list:
        description:
        - "Field cipher_without_prio_list"
        required: False
        suboptions:
            cipher_wo_prio:
                description:
                - "'SSL3_RSA_DES_192_CBC3_SHA'= SSL3_RSA_DES_192_CBC3_SHA; 'SSL3_RSA_RC4_128_MD5'=
          SSL3_RSA_RC4_128_MD5; 'SSL3_RSA_RC4_128_SHA'= SSL3_RSA_RC4_128_SHA;
          'TLS1_RSA_AES_128_SHA'= TLS1_RSA_AES_128_SHA; 'TLS1_RSA_AES_256_SHA'=
          TLS1_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_SHA256'= TLS1_RSA_AES_128_SHA256;
          'TLS1_RSA_AES_256_SHA256'= TLS1_RSA_AES_256_SHA256;
          'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS1_DHE_RSA_AES_128_GCM_SHA256;
          'TLS1_DHE_RSA_AES_128_SHA'= TLS1_DHE_RSA_AES_128_SHA;
          'TLS1_DHE_RSA_AES_128_SHA256'= TLS1_DHE_RSA_AES_128_SHA256;
          'TLS1_DHE_RSA_AES_256_GCM_SHA384'= TLS1_DHE_RSA_AES_256_GCM_SHA384;
          'TLS1_DHE_RSA_AES_256_SHA'= TLS1_DHE_RSA_AES_256_SHA;
          'TLS1_DHE_RSA_AES_256_SHA256'= TLS1_DHE_RSA_AES_256_SHA256;
          'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256;
          'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS1_ECDHE_ECDSA_AES_128_SHA;
          'TLS1_ECDHE_ECDSA_AES_128_SHA256'= TLS1_ECDHE_ECDSA_AES_128_SHA256;
          'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS1_ECDHE_ECDSA_AES_256_SHA;
          'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'= TLS1_ECDHE_RSA_AES_128_GCM_SHA256;
          'TLS1_ECDHE_RSA_AES_128_SHA'= TLS1_ECDHE_RSA_AES_128_SHA;
          'TLS1_ECDHE_RSA_AES_128_SHA256'= TLS1_ECDHE_RSA_AES_128_SHA256;
          'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS1_ECDHE_RSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_RSA_AES_256_SHA'= TLS1_ECDHE_RSA_AES_256_SHA;
          'TLS1_RSA_AES_128_GCM_SHA256'= TLS1_RSA_AES_128_GCM_SHA256;
          'TLS1_RSA_AES_256_GCM_SHA384'= TLS1_RSA_AES_256_GCM_SHA384;
          'TLS1_ECDHE_RSA_AES_256_SHA384'= TLS1_ECDHE_RSA_AES_256_SHA384;
          'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS1_ECDHE_ECDSA_AES_256_SHA384;
          'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256'=
          TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256;
          'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256'=
          TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256;
          'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'= TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256;"
    ocspst_sg_minutes:
        description:
        - "Specify update period, in minutes"
        required: False
    starts_with_list:
        description:
        - "Field starts_with_list"
        required: False
        suboptions:
            starts_with:
                description:
                - "Forward proxy bypass if SNI string starts with another string"
    key_shared_passphrase:
        description:
        - "Password Phrase"
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
AVAILABLE_PROPERTIES = [
    "ad_group_list",
    "alert_type",
    "auth_sg",
    "auth_sg_dn",
    "auth_sg_filter",
    "auth_username",
    "auth_username_attribute",
    "authen_name",
    "authorization",
    "bypass_cert_issuer_class_list_name",
    "bypass_cert_issuer_multi_class_list",
    "bypass_cert_san_class_list_name",
    "bypass_cert_san_multi_class_list",
    "bypass_cert_subject_class_list_name",
    "bypass_cert_subject_multi_class_list",
    "ca_certs",
    "cache_persistence_list_name",
    "case_insensitive",
    "cert_alternate",
    "cert_revoke_action",
    "cert_shared_str",
    "cert_str",
    "cert_unknown_action",
    "certificate_issuer_contains_list",
    "certificate_issuer_ends_with_list",
    "certificate_issuer_equals_list",
    "certificate_issuer_starts_with_list",
    "certificate_san_contains_list",
    "certificate_san_ends_with_list",
    "certificate_san_equals_list",
    "certificate_san_starts_with_list",
    "certificate_subject_contains_list",
    "certificate_subject_ends_with_list",
    "certificate_subject_equals_list",
    "certificate_subject_starts_with_list",
    "chain_cert",
    "chain_cert_shared_str",
    "cipher_without_prio_list",
    "class_list_name",
    "client_auth_case_insensitive",
    "client_auth_class_list",
    "client_auth_contains_list",
    "client_auth_ends_with_list",
    "client_auth_equals_list",
    "client_auth_starts_with_list",
    "client_certificate",
    "close_notify",
    "contains_list",
    "crl_certs",
    "dgversion",
    "dh_type",
    "direct_client_server_auth",
    "disable_sslv3",
    "ec_list",
    "enable_tls_alert_logging",
    "ends_with_list",
    "equals_list",
    "exception_ad_group_list",
    "exception_certificate_issuer_cl_name",
    "exception_certificate_san_cl_name",
    "exception_certificate_subject_cl_name",
    "exception_sni_cl_name",
    "exception_user_name_list",
    "expire_hours",
    "forward_encrypted",
    "forward_passphrase",
    "forward_proxy_alt_sign",
    "forward_proxy_block_message",
    "forward_proxy_ca_cert",
    "forward_proxy_ca_key",
    "forward_proxy_cert_cache_limit",
    "forward_proxy_cert_cache_timeout",
    "forward_proxy_cert_expiry",
    "forward_proxy_cert_not_ready_action",
    "forward_proxy_cert_revoke_action",
    "forward_proxy_cert_unknown_action",
    "forward_proxy_crl_disable",
    "forward_proxy_decrypted_dscp",
    "forward_proxy_decrypted_dscp_bypass",
    "forward_proxy_enable",
    "forward_proxy_failsafe_disable",
    "forward_proxy_log_disable",
    "forward_proxy_no_shared_cipher_action",
    "forward_proxy_no_sni_action",
    "forward_proxy_ocsp_disable",
    "forward_proxy_selfsign_redir",
    "forward_proxy_ssl_version",
    "forward_proxy_trusted_ca_lists",
    "forward_proxy_verify_cert_fail_action",
    "fp_alt_cert",
    "fp_alt_encrypted",
    "fp_alt_key",
    "fp_alt_passphrase",
    "fp_cert_ext_aia_ca_issuers",
    "fp_cert_ext_aia_ocsp",
    "fp_cert_ext_crldp",
    "fp_cert_fetch_autonat",
    "fp_cert_fetch_autonat_precedence",
    "fp_cert_fetch_natpool_name",
    "fp_cert_fetch_natpool_name_shared",
    "fp_cert_fetch_natpool_precedence",
    "handshake_logging_enable",
    "hsm_type",
    "inspect_certificate_issuer_cl_name",
    "inspect_certificate_san_cl_name",
    "inspect_certificate_subject_cl_name",
    "inspect_list_name",
    "key_alt_encrypted",
    "key_alt_passphrase",
    "key_alternate",
    "key_encrypted",
    "key_passphrase",
    "key_shared_encrypted",
    "key_shared_passphrase",
    "key_shared_str",
    "key_str",
    "ldap_base_dn_from_cert",
    "ldap_search_filter",
    "local_logging",
    "multi_class_list",
    "name",
    "no_shared_cipher_action",
    "non_ssl_bypass_l4session",
    "non_ssl_bypass_service_group",
    "notafter",
    "notafterday",
    "notaftermonth",
    "notafteryear",
    "notbefore",
    "notbeforeday",
    "notbeforemonth",
    "notbeforeyear",
    "ocsp_stapling",
    "ocspst_ca_cert",
    "ocspst_ocsp",
    "ocspst_sg",
    "ocspst_sg_days",
    "ocspst_sg_hours",
    "ocspst_sg_minutes",
    "ocspst_sg_timeout",
    "ocspst_srvr",
    "ocspst_srvr_days",
    "ocspst_srvr_hours",
    "ocspst_srvr_minutes",
    "ocspst_srvr_timeout",
    "oper",
    "renegotiation_disable",
    "req_ca_lists",
    "require_web_category",
    "sampling_enable",
    "server_name_auto_map",
    "server_name_list",
    "session_cache_size",
    "session_cache_timeout",
    "session_ticket_lifetime",
    "shared_partition_cipher_template",
    "shared_partition_pool",
    "sni_enable_log",
    "ssl_false_start_disable",
    "ssli_logging",
    "sslilogging",
    "sslv2_bypass_service_group",
    "starts_with_list",
    "stats",
    "template_cipher",
    "template_cipher_shared",
    "template_hsm",
    "user_name_list",
    "user_tag",
    "uuid",
    "verify_cert_fail_action",
    "version",
    "web_category",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'bypass_cert_subject_multi_class_list': {
            'type': 'list',
            'bypass_cert_subject_multi_class_list_name': {
                'type': 'str',
            }
        },
        'verify_cert_fail_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
        },
        'inspect_certificate_issuer_cl_name': {
            'type': 'str',
        },
        'certificate_san_contains_list': {
            'type': 'list',
            'certificate_san_contains': {
                'type': 'str',
            }
        },
        'forward_proxy_block_message': {
            'type': 'str',
        },
        'direct_client_server_auth': {
            'type': 'bool',
        },
        'ocspst_sg_hours': {
            'type': 'int',
        },
        'no_shared_cipher_action': {
            'type': 'str',
            'choices': ['bypass', 'drop']
        },
        'oper': {
            'type': 'dict',
            'name': {
                'type': 'str',
                'required': True,
            },
            'cert_status_list': {
                'type': 'list',
                'cert_status_responder': {
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
                'cert_status_name': {
                    'type': 'str',
                }
            }
        },
        'fp_cert_fetch_autonat': {
            'type': 'str',
            'choices': ['auto']
        },
        'equals_list': {
            'type': 'list',
            'equals': {
                'type': 'str',
            }
        },
        'exception_certificate_subject_cl_name': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'forward_proxy_trusted_ca_lists': {
            'type': 'list',
            'forward_proxy_trusted_ca': {
                'type': 'str',
            }
        },
        'template_cipher_shared': {
            'type': 'str',
        },
        'forward_proxy_ca_cert': {
            'type': 'str',
        },
        'ssl_false_start_disable': {
            'type': 'bool',
        },
        'dgversion': {
            'type': 'int',
        },
        'client_auth_class_list': {
            'type': 'str',
        },
        'key_encrypted': {
            'type': 'str',
        },
        'notafteryear': {
            'type': 'int',
        },
        'forward_proxy_alt_sign': {
            'type': 'bool',
        },
        'template_hsm': {
            'type': 'str',
        },
        'forward_passphrase': {
            'type': 'str',
        },
        'exception_certificate_issuer_cl_name': {
            'type': 'str',
        },
        'contains_list': {
            'type': 'list',
            'contains': {
                'type': 'str',
            }
        },
        'forward_proxy_ca_key': {
            'type': 'str',
        },
        'notbefore': {
            'type': 'bool',
        },
        'ends_with_list': {
            'type': 'list',
            'ends_with': {
                'type': 'str',
            }
        },
        'bypass_cert_subject_class_list_name': {
            'type': 'str',
        },
        'notafter': {
            'type': 'bool',
        },
        'class_list_name': {
            'type': 'str',
        },
        'ocspst_ocsp': {
            'type': 'bool',
        },
        'notbeforeday': {
            'type': 'int',
        },
        'key_alt_passphrase': {
            'type': 'str',
        },
        'forward_proxy_ssl_version': {
            'type': 'int',
        },
        'ca_certs': {
            'type': 'list',
            'ca_cert': {
                'type': 'str',
            },
            'client_ocsp_sg': {
                'type': 'str',
            },
            'client_ocsp': {
                'type': 'bool',
            },
            'client_ocsp_srvr': {
                'type': 'str',
            },
            'ca_shared': {
                'type': 'bool',
            }
        },
        'forward_proxy_crl_disable': {
            'type': 'bool',
        },
        'client_auth_contains_list': {
            'type': 'list',
            'client_auth_contains': {
                'type': 'str',
            }
        },
        'certificate_subject_contains_list': {
            'type': 'list',
            'certificate_subject_contains': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'forward_proxy_cert_revoke_action': {
            'type': 'bool',
        },
        'fp_cert_ext_aia_ocsp': {
            'type': 'str',
        },
        'req_ca_lists': {
            'type': 'list',
            'client_certificate_Request_CA': {
                'type': 'str',
            }
        },
        'user_tag': {
            'type': 'str',
        },
        'cert_unknown_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'real-estate', 'computer-and-internet-security',
                    'financial-services', 'business-and-economy',
                    'computer-and-internet-info', 'auctions', 'shopping',
                    'cult-and-occult', 'travel', 'drugs',
                    'adult-and-pornography', 'home-and-garden', 'military',
                    'social-network', 'dead-sites', 'stock-advice-and-tools',
                    'training-and-tools', 'dating', 'sex-education',
                    'religion', 'entertainment-and-arts',
                    'personal-sites-and-blogs', 'legal', 'local-information',
                    'streaming-media', 'job-search', 'gambling', 'translation',
                    'reference-and-research', 'shareware-and-freeware',
                    'peer-to-peer', 'marijuana', 'hacking', 'games',
                    'philosophy-and-politics', 'weapons', 'pay-to-surf',
                    'hunting-and-fishing', 'society',
                    'educational-institutions', 'online-greeting-cards',
                    'sports', 'swimsuits-and-intimate-apparel', 'questionable',
                    'kids', 'hate-and-racism', 'personal-storage', 'violence',
                    'keyloggers-and-monitoring', 'search-engines',
                    'internet-portals', 'web-advertisements', 'cheating',
                    'gross', 'web-based-email', 'malware-sites',
                    'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers',
                    'spyware-and-adware', 'music', 'government', 'nudity',
                    'news-and-media', 'illegal', 'CDNs',
                    'internet-communications', 'bot-nets', 'abortion',
                    'health-and-medicine', 'confirmed-SPAM-sources',
                    'SPAM-URLs', 'unconfirmed-SPAM-sources',
                    'open-HTTP-proxies', 'dynamic-comment', 'parked-domains',
                    'alcohol-and-tobacco', 'private-IP-addresses',
                    'image-and-video-search', 'fashion-and-beauty',
                    'recreation-and-hobbies', 'motor-vehicles',
                    'web-hosting-sites', 'food-and-dining', 'uncategorised',
                    'other-category'
                ]
            }
        },
        'renegotiation_disable': {
            'type': 'bool',
        },
        'exception_ad_group_list': {
            'type': 'str',
        },
        'key_alternate': {
            'type': 'str',
        },
        'fp_alt_key': {
            'type': 'str',
        },
        'server_name_auto_map': {
            'type': 'bool',
        },
        'disable_sslv3': {
            'type': 'bool',
        },
        'bypass_cert_issuer_multi_class_list': {
            'type': 'list',
            'bypass_cert_issuer_multi_class_list_name': {
                'type': 'str',
            }
        },
        'client_auth_equals_list': {
            'type': 'list',
            'client_auth_equals': {
                'type': 'str',
            }
        },
        'forward_proxy_no_sni_action': {
            'type': 'str',
            'choices': ['intercept', 'bypass', 'reset']
        },
        'certificate_issuer_equals_list': {
            'type': 'list',
            'certificate_issuer_equals': {
                'type': 'str',
            }
        },
        'fp_alt_passphrase': {
            'type': 'str',
        },
        'certificate_subject_starts_with_list': {
            'type': 'list',
            'certificate_subject_starts': {
                'type': 'str',
            }
        },
        'certificate_san_ends_with_list': {
            'type': 'list',
            'certificate_san_ends_with': {
                'type': 'str',
            }
        },
        'forward_proxy_cert_cache_timeout': {
            'type': 'int',
        },
        'fp_cert_fetch_natpool_name_shared': {
            'type': 'str',
        },
        'crl_certs': {
            'type': 'list',
            'crl_shared': {
                'type': 'bool',
            },
            'crl': {
                'type': 'str',
            }
        },
        'notafterday': {
            'type': 'int',
        },
        'ocspst_srvr_hours': {
            'type': 'int',
        },
        'local_logging': {
            'type': 'bool',
        },
        'fp_cert_fetch_autonat_precedence': {
            'type': 'bool',
        },
        'cert_str': {
            'type': 'str',
        },
        'cert_shared_str': {
            'type': 'str',
        },
        'cert_revoke_action': {
            'type': 'str',
            'choices': ['bypass', 'continue', 'drop', 'block']
        },
        'version': {
            'type': 'int',
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
        'session_ticket_lifetime': {
            'type': 'int',
        },
        'certificate_issuer_ends_with_list': {
            'type': 'list',
            'certificate_issuer_ends_with': {
                'type': 'str',
            }
        },
        'ssli_logging': {
            'type': 'bool',
        },
        'session_cache_size': {
            'type': 'int',
        },
        'handshake_logging_enable': {
            'type': 'bool',
        },
        'non_ssl_bypass_service_group': {
            'type': 'str',
        },
        'forward_proxy_failsafe_disable': {
            'type': 'bool',
        },
        'session_cache_timeout': {
            'type': 'int',
        },
        'sslv2_bypass_service_group': {
            'type': 'str',
        },
        'forward_proxy_decrypted_dscp': {
            'type': 'int',
        },
        'auth_sg': {
            'type': 'str',
        },
        'ocspst_ca_cert': {
            'type': 'str',
        },
        'forward_proxy_selfsign_redir': {
            'type': 'bool',
        },
        'auth_sg_dn': {
            'type': 'bool',
        },
        'hsm_type': {
            'type': 'str',
            'choices': ['thales-embed', 'thales-hwcrhk']
        },
        'forward_proxy_log_disable': {
            'type': 'bool',
        },
        'fp_alt_encrypted': {
            'type': 'str',
        },
        'inspect_certificate_san_cl_name': {
            'type': 'str',
        },
        'web_category': {
            'type': 'dict',
            'philosophy_and_politics': {
                'type': 'bool',
            },
            'stock_advice_and_tools': {
                'type': 'bool',
            },
            'news_and_media': {
                'type': 'bool',
            },
            'business_and_economy': {
                'type': 'bool',
            },
            'peer_to_peer': {
                'type': 'bool',
            },
            'phishing_and_other_fraud': {
                'type': 'bool',
            },
            'nudity': {
                'type': 'bool',
            },
            'weapons': {
                'type': 'bool',
            },
            'health_and_medicine': {
                'type': 'bool',
            },
            'marijuana': {
                'type': 'bool',
            },
            'home_and_garden': {
                'type': 'bool',
            },
            'cult_and_occult': {
                'type': 'bool',
            },
            'society': {
                'type': 'bool',
            },
            'personal_storage': {
                'type': 'bool',
            },
            'computer_and_internet_security': {
                'type': 'bool',
            },
            'food_and_dining': {
                'type': 'bool',
            },
            'motor_vehicles': {
                'type': 'bool',
            },
            'swimsuits_and_intimate_apparel': {
                'type': 'bool',
            },
            'dead_sites': {
                'type': 'bool',
            },
            'translation': {
                'type': 'bool',
            },
            'proxy_avoid_and_anonymizers': {
                'type': 'bool',
            },
            'financial_services': {
                'type': 'bool',
            },
            'gross': {
                'type': 'bool',
            },
            'cheating': {
                'type': 'bool',
            },
            'entertainment_and_arts': {
                'type': 'bool',
            },
            'sex_education': {
                'type': 'bool',
            },
            'illegal': {
                'type': 'bool',
            },
            'travel': {
                'type': 'bool',
            },
            'cdns': {
                'type': 'bool',
            },
            'local_information': {
                'type': 'bool',
            },
            'legal': {
                'type': 'bool',
            },
            'sports': {
                'type': 'bool',
            },
            'bot_nets': {
                'type': 'bool',
            },
            'religion': {
                'type': 'bool',
            },
            'private_ip_addresses': {
                'type': 'bool',
            },
            'music': {
                'type': 'bool',
            },
            'hate_and_racism': {
                'type': 'bool',
            },
            'open_http_proxies': {
                'type': 'bool',
            },
            'internet_communications': {
                'type': 'bool',
            },
            'shareware_and_freeware': {
                'type': 'bool',
            },
            'dating': {
                'type': 'bool',
            },
            'spyware_and_adware': {
                'type': 'bool',
            },
            'uncategorized': {
                'type': 'bool',
            },
            'questionable': {
                'type': 'bool',
            },
            'reference_and_research': {
                'type': 'bool',
            },
            'web_advertisements': {
                'type': 'bool',
            },
            'streaming_media': {
                'type': 'bool',
            },
            'social_network': {
                'type': 'bool',
            },
            'government': {
                'type': 'bool',
            },
            'drugs': {
                'type': 'bool',
            },
            'web_hosting_sites': {
                'type': 'bool',
            },
            'malware_sites': {
                'type': 'bool',
            },
            'pay_to_surf': {
                'type': 'bool',
            },
            'spam_urls': {
                'type': 'bool',
            },
            'kids': {
                'type': 'bool',
            },
            'gambling': {
                'type': 'bool',
            },
            'online_greeting_cards': {
                'type': 'bool',
            },
            'confirmed_spam_sources': {
                'type': 'bool',
            },
            'image_and_video_search': {
                'type': 'bool',
            },
            'educational_institutions': {
                'type': 'bool',
            },
            'keyloggers_and_monitoring': {
                'type': 'bool',
            },
            'hunting_and_fishing': {
                'type': 'bool',
            },
            'search_engines': {
                'type': 'bool',
            },
            'fashion_and_beauty': {
                'type': 'bool',
            },
            'dynamic_comment': {
                'type': 'bool',
            },
            'computer_and_internet_info': {
                'type': 'bool',
            },
            'real_estate': {
                'type': 'bool',
            },
            'internet_portals': {
                'type': 'bool',
            },
            'shopping': {
                'type': 'bool',
            },
            'violence': {
                'type': 'bool',
            },
            'abortion': {
                'type': 'bool',
            },
            'training_and_tools': {
                'type': 'bool',
            },
            'web_based_email': {
                'type': 'bool',
            },
            'personal_sites_and_blogs': {
                'type': 'bool',
            },
            'unconfirmed_spam_sources': {
                'type': 'bool',
            },
            'games': {
                'type': 'bool',
            },
            'parked_domains': {
                'type': 'bool',
            },
            'auctions': {
                'type': 'bool',
            },
            'job_search': {
                'type': 'bool',
            },
            'recreation_and_hobbies': {
                'type': 'bool',
            },
            'hacking': {
                'type': 'bool',
            },
            'alcohol_and_tobacco': {
                'type': 'bool',
            },
            'adult_and_pornography': {
                'type': 'bool',
            },
            'military': {
                'type': 'bool',
            }
        },
        'certificate_san_equals_list': {
            'type': 'list',
            'certificate_san_equals': {
                'type': 'str',
            }
        },
        'template_cipher': {
            'type': 'str',
        },
        'notbeforemonth': {
            'type': 'int',
        },
        'bypass_cert_san_class_list_name': {
            'type': 'str',
        },
        'chain_cert': {
            'type': 'str',
        },
        'forward_proxy_cert_unknown_action': {
            'type': 'bool',
        },
        'exception_certificate_san_cl_name': {
            'type': 'str',
        },
        'ocspst_sg': {
            'type': 'str',
        },
        'key_alt_encrypted': {
            'type': 'str',
        },
        'fp_cert_ext_aia_ca_issuers': {
            'type': 'str',
        },
        'authen_name': {
            'type': 'str',
        },
        'expire_hours': {
            'type': 'int',
        },
        'client_auth_case_insensitive': {
            'type': 'bool',
        },
        'ocsp_stapling': {
            'type': 'bool',
        },
        'notbeforeyear': {
            'type': 'int',
        },
        'forward_encrypted': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'stock_advice_and_tools': {
                'type': 'str',
            },
            'news_and_media': {
                'type': 'str',
            },
            'CDNs': {
                'type': 'str',
            },
            'cult_and_occult': {
                'type': 'str',
            },
            'fashion_and_beauty': {
                'type': 'str',
            },
            'food_and_dining': {
                'type': 'str',
            },
            'SPAM_URLs': {
                'type': 'str',
            },
            'streaming_media': {
                'type': 'str',
            },
            'bot_nets': {
                'type': 'str',
            },
            'cheating': {
                'type': 'str',
            },
            'entertainment_and_arts': {
                'type': 'str',
            },
            'illegal': {
                'type': 'str',
            },
            'local_information': {
                'type': 'str',
            },
            'sports': {
                'type': 'str',
            },
            'confirmed_SPAM_sources': {
                'type': 'str',
            },
            'private_IP_addresses': {
                'type': 'str',
            },
            'music': {
                'type': 'str',
            },
            'open_HTTP_proxies': {
                'type': 'str',
            },
            'shareware_and_freeware': {
                'type': 'str',
            },
            'spyware_and_adware': {
                'type': 'str',
            },
            'questionable': {
                'type': 'str',
            },
            'financial_services': {
                'type': 'str',
            },
            'social_network': {
                'type': 'str',
            },
            'government': {
                'type': 'str',
            },
            'drugs': {
                'type': 'str',
            },
            'web_hosting_sites': {
                'type': 'str',
            },
            'web_advertisements': {
                'type': 'str',
            },
            'educational_institutions': {
                'type': 'str',
            },
            'dynamic_comment': {
                'type': 'str',
            },
            'translation': {
                'type': 'str',
            },
            'job_search': {
                'type': 'str',
            },
            'hunting_and_fishing': {
                'type': 'str',
            },
            'search_engines': {
                'type': 'str',
            },
            'peer_to_peer': {
                'type': 'str',
            },
            'computer_and_internet_security': {
                'type': 'str',
            },
            'real_estate': {
                'type': 'str',
            },
            'computer_and_internet_info': {
                'type': 'str',
            },
            'internet_portals': {
                'type': 'str',
            },
            'shopping': {
                'type': 'str',
            },
            'philosophy_and_politics': {
                'type': 'str',
            },
            'web_based_email': {
                'type': 'str',
            },
            'recreation_and_hobbies': {
                'type': 'str',
            },
            'hacking': {
                'type': 'str',
            },
            'adult_and_pornography': {
                'type': 'str',
            },
            'business_and_economy': {
                'type': 'str',
            },
            'phishing_and_other_fraud': {
                'type': 'str',
            },
            'nudity': {
                'type': 'str',
            },
            'health_and_medicine': {
                'type': 'str',
            },
            'marijuana': {
                'type': 'str',
            },
            'home_and_garden': {
                'type': 'str',
            },
            'society': {
                'type': 'str',
            },
            'unconfirmed_SPAM_sources': {
                'type': 'str',
            },
            'personal_storage': {
                'type': 'str',
            },
            'motor_vehicles': {
                'type': 'str',
            },
            'swimsuits_and_intimate_apparel': {
                'type': 'str',
            },
            'dead_sites': {
                'type': 'str',
            },
            'other_category': {
                'type': 'str',
            },
            'proxy_avoid_and_anonymizers': {
                'type': 'str',
            },
            'gross': {
                'type': 'str',
            },
            'uncategorised': {
                'type': 'str',
            },
            'travel': {
                'type': 'str',
            },
            'legal': {
                'type': 'str',
            },
            'weapons': {
                'type': 'str',
            },
            'religion': {
                'type': 'str',
            },
            'hate_and_racism': {
                'type': 'str',
            },
            'internet_communications': {
                'type': 'str',
            },
            'gambling': {
                'type': 'str',
            },
            'dating': {
                'type': 'str',
            },
            'malware_sites': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'pay_to_surf': {
                'type': 'str',
            },
            'military': {
                'type': 'str',
            },
            'image_and_video_search': {
                'type': 'str',
            },
            'reference_and_research': {
                'type': 'str',
            },
            'keyloggers_and_monitoring': {
                'type': 'str',
            },
            'kids': {
                'type': 'str',
            },
            'online_greeting_cards': {
                'type': 'str',
            },
            'violence': {
                'type': 'str',
            },
            'training_and_tools': {
                'type': 'str',
            },
            'sex_education': {
                'type': 'str',
            },
            'personal_sites_and_blogs': {
                'type': 'str',
            },
            'games': {
                'type': 'str',
            },
            'parked_domains': {
                'type': 'str',
            },
            'auctions': {
                'type': 'str',
            },
            'abortion': {
                'type': 'str',
            },
            'alcohol_and_tobacco': {
                'type': 'str',
            }
        },
        'sni_enable_log': {
            'type': 'bool',
        },
        'key_shared_str': {
            'type': 'str',
        },
        'notaftermonth': {
            'type': 'int',
        },
        'cache_persistence_list_name': {
            'type': 'str',
        },
        'ocspst_sg_timeout': {
            'type': 'int',
        },
        'key_passphrase': {
            'type': 'str',
        },
        'ocspst_srvr': {
            'type': 'str',
        },
        'ocspst_srvr_minutes': {
            'type': 'int',
        },
        'certificate_issuer_contains_list': {
            'type': 'list',
            'certificate_issuer_contains': {
                'type': 'str',
            }
        },
        'require_web_category': {
            'type': 'bool',
        },
        'bypass_cert_san_multi_class_list': {
            'type': 'list',
            'bypass_cert_san_multi_class_list_name': {
                'type': 'str',
            }
        },
        'client_auth_starts_with_list': {
            'type': 'list',
            'client_auth_starts_with': {
                'type': 'str',
            }
        },
        'certificate_subject_ends_with_list': {
            'type': 'list',
            'certificate_subject_ends_with': {
                'type': 'str',
            }
        },
        'authorization': {
            'type': 'bool',
        },
        'forward_proxy_verify_cert_fail_action': {
            'type': 'bool',
        },
        'ocspst_srvr_days': {
            'type': 'int',
        },
        'ec_list': {
            'type': 'list',
            'ec': {
                'type': 'str',
                'choices': ['secp256r1', 'secp384r1']
            }
        },
        'forward_proxy_decrypted_dscp_bypass': {
            'type': 'int',
        },
        'alert_type': {
            'type': 'str',
            'choices': ['fatal']
        },
        'forward_proxy_cert_not_ready_action': {
            'type': 'str',
            'choices': ['bypass', 'reset', 'intercept']
        },
        'server_name_list': {
            'type': 'list',
            'server_shared': {
                'type': 'bool',
            },
            'server_passphrase_regex': {
                'type': 'str',
            },
            'server_chain': {
                'type': 'str',
            },
            'server_cert_regex': {
                'type': 'str',
            },
            'server_name': {
                'type': 'str',
            },
            'server_key_regex': {
                'type': 'str',
            },
            'server_name_regex_alternate': {
                'type': 'bool',
            },
            'server_encrypted_regex': {
                'type': 'str',
            },
            'server_shared_regex': {
                'type': 'bool',
            },
            'server_name_regex': {
                'type': 'str',
            },
            'server_passphrase': {
                'type': 'str',
            },
            'server_key': {
                'type': 'str',
            },
            'server_chain_regex': {
                'type': 'str',
            },
            'server_name_alternate': {
                'type': 'bool',
            },
            'server_encrypted': {
                'type': 'str',
            },
            'server_cert': {
                'type': 'str',
            }
        },
        'bypass_cert_issuer_class_list_name': {
            'type': 'str',
        },
        'fp_cert_ext_crldp': {
            'type': 'str',
        },
        'shared_partition_cipher_template': {
            'type': 'bool',
        },
        'fp_cert_fetch_natpool_precedence': {
            'type': 'bool',
        },
        'cert_alternate': {
            'type': 'str',
        },
        'forward_proxy_cert_cache_limit': {
            'type': 'int',
        },
        'non_ssl_bypass_l4session': {
            'type': 'bool',
        },
        'certificate_issuer_starts_with_list': {
            'type': 'list',
            'certificate_issuer_starts': {
                'type': 'str',
            }
        },
        'certificate_san_starts_with_list': {
            'type': 'list',
            'certificate_san_starts': {
                'type': 'str',
            }
        },
        'client_auth_ends_with_list': {
            'type': 'list',
            'client_auth_ends_with': {
                'type': 'str',
            }
        },
        'close_notify': {
            'type': 'bool',
        },
        'forward_proxy_no_shared_cipher_action': {
            'type': 'bool',
        },
        'forward_proxy_ocsp_disable': {
            'type': 'bool',
        },
        'sslilogging': {
            'type': 'str',
            'choices': ['disable', 'all']
        },
        'auth_username': {
            'type': 'str',
        },
        'exception_user_name_list': {
            'type': 'str',
        },
        'ocspst_sg_days': {
            'type': 'int',
        },
        'key_str': {
            'type': 'str',
        },
        'inspect_list_name': {
            'type': 'str',
        },
        'auth_username_attribute': {
            'type': 'str',
        },
        'fp_cert_fetch_natpool_name': {
            'type': 'str',
        },
        'exception_sni_cl_name': {
            'type': 'str',
        },
        'inspect_certificate_subject_cl_name': {
            'type': 'str',
        },
        'ldap_base_dn_from_cert': {
            'type': 'bool',
        },
        'ad_group_list': {
            'type': 'str',
        },
        'client_certificate': {
            'type': 'str',
            'choices': ['Ignore', 'Require', 'Request']
        },
        'forward_proxy_cert_expiry': {
            'type': 'bool',
        },
        'forward_proxy_enable': {
            'type': 'bool',
        },
        'shared_partition_pool': {
            'type': 'bool',
        },
        'ldap_search_filter': {
            'type': 'str',
        },
        'key_shared_encrypted': {
            'type': 'str',
        },
        'auth_sg_filter': {
            'type': 'str',
        },
        'ocspst_srvr_timeout': {
            'type': 'int',
        },
        'certificate_subject_equals_list': {
            'type': 'list',
            'certificate_subject_equals': {
                'type': 'str',
            }
        },
        'chain_cert_shared_str': {
            'type': 'str',
        },
        'enable_tls_alert_logging': {
            'type': 'bool',
        },
        'dh_type': {
            'type': 'str',
            'choices': ['1024', '1024-dsa', '2048']
        },
        'fp_alt_cert': {
            'type': 'str',
        },
        'case_insensitive': {
            'type': 'bool',
        },
        'cipher_without_prio_list': {
            'type': 'list',
            'cipher_wo_prio': {
                'type':
                'str',
                'choices': [
                    'SSL3_RSA_DES_192_CBC3_SHA', 'SSL3_RSA_RC4_128_MD5',
                    'SSL3_RSA_RC4_128_SHA', 'TLS1_RSA_AES_128_SHA',
                    'TLS1_RSA_AES_256_SHA', 'TLS1_RSA_AES_128_SHA256',
                    'TLS1_RSA_AES_256_SHA256',
                    'TLS1_DHE_RSA_AES_128_GCM_SHA256',
                    'TLS1_DHE_RSA_AES_128_SHA', 'TLS1_DHE_RSA_AES_128_SHA256',
                    'TLS1_DHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_DHE_RSA_AES_256_SHA', 'TLS1_DHE_RSA_AES_256_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_128_SHA',
                    'TLS1_ECDHE_ECDSA_AES_128_SHA256',
                    'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_ECDSA_AES_256_SHA',
                    'TLS1_ECDHE_RSA_AES_128_GCM_SHA256',
                    'TLS1_ECDHE_RSA_AES_128_SHA',
                    'TLS1_ECDHE_RSA_AES_128_SHA256',
                    'TLS1_ECDHE_RSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_RSA_AES_256_SHA',
                    'TLS1_RSA_AES_128_GCM_SHA256',
                    'TLS1_RSA_AES_256_GCM_SHA384',
                    'TLS1_ECDHE_RSA_AES_256_SHA384',
                    'TLS1_ECDHE_ECDSA_AES_256_SHA384',
                    'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256',
                    'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'
                ]
            }
        },
        'ocspst_sg_minutes': {
            'type': 'int',
        },
        'starts_with_list': {
            'type': 'list',
            'starts_with': {
                'type': 'str',
            }
        },
        'key_shared_passphrase': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/client-ssl/{name}"

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
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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

    for k, v in param.items():
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/client-ssl/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
        for k, v in payload["client-ssl"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["client-ssl"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["client-ssl"][k] = v
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
    payload = build_json("client-ssl", module)
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

    result = dict(changed=False, original_message="", message="", result={})

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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
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
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
