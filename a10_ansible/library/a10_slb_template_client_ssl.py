#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
        - present
        - absent
        required: True

    a10_protocol:
        description:
        - HTTP / HTTPS Protocol for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port number AXAPI is running on
        required: True
    partition:
        description:
        - Destination/target partition for object/command
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
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'= close the connection; 'block'= block the connection with a warning page; "
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
        - "Message to be included on the block page (Message, enclose in quotes if spaces are present)"
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
        - "'bypass'= bypass SSLi processing; 'drop'= close the connection; "
        required: False
    fp_cert_fetch_autonat:
        description:
        - "'auto'= Configure auto NAT for server certificate fetching; "
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
        - "Forward proxy client auth bypass if SNI string matches class-list (Class List Name)"
        required: False
    key_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
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
        - "TLS/SSL version, default is TLS1.2 (TLS/SSL version= 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)"
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
        - "Action taken if a certificate is irreversibly revoked, bypass SSLi processing by default"
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
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'= close the connection; 'block'= block the connection with a warning page; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'real-estate'= real estate category; 'computer-and-internet-security'= computer and internet security category; 'financial-services'= financial services category; 'business-and-economy'= business and economy category; 'computer-and-internet-info'= computer and internet info category; 'auctions'= auctions category; 'shopping'= shopping category; 'cult-and-occult'= cult and occult category; 'travel'= travel category; 'drugs'= drugs category; 'adult-and-pornography'= adult and pornography category; 'home-and-garden'= home and garden category; 'military'= military category; 'social-network'= social network category; 'dead-sites'= dead sites category; 'stock-advice-and-tools'= stock advice and tools category; 'training-and-tools'= training and tools category; 'dating'= dating category; 'sex-education'= sex education category; 'religion'= religion category; 'entertainment-and-arts'= entertainment and arts category; 'personal-sites-and-blogs'= personal sites and blogs category; 'legal'= legal category; 'local-information'= local information category; 'streaming-media'= streaming media category; 'job-search'= job search category; 'gambling'= gambling category; 'translation'= translation category; 'reference-and-research'= reference and research category; 'shareware-and-freeware'= shareware and freeware category; 'peer-to-peer'= peer to peer category; 'marijuana'= marijuana category; 'hacking'= hacking category; 'games'= games category; 'philosophy-and-politics'= philosophy and politics category; 'weapons'= weapons category; 'pay-to-surf'= pay to surf category; 'hunting-and-fishing'= hunting and fishing category; 'society'= society category; 'educational-institutions'= educational institutions category; 'online-greeting-cards'= online greeting cards category; 'sports'= sports category; 'swimsuits-and-intimate-apparel'= swimsuits and intimate apparel category; 'questionable'= questionable category; 'kids'= kids category; 'hate-and-racism'= hate and racism category; 'personal-storage'= personal storage category; 'violence'= violence category; 'keyloggers-and-monitoring'= keyloggers and monitoring category; 'search-engines'= search engines category; 'internet-portals'= internet portals category; 'web-advertisements'= web advertisements category; 'cheating'= cheating category; 'gross'= gross category; 'web-based-email'= web based email category; 'malware-sites'= malware sites category; 'phishing-and-other-fraud'= phishing and other fraud category; 'proxy-avoid-and-anonymizers'= proxy avoid and anonymizers category; 'spyware-and-adware'= spyware and adware category; 'music'= music category; 'government'= government category; 'nudity'= nudity category; 'news-and-media'= news and media category; 'illegal'= illegal category; 'CDNs'= content delivery networks category; 'internet-communications'= internet communications category; 'bot-nets'= bot nets category; 'abortion'= abortion category; 'health-and-medicine'= health and medicine category; 'confirmed-SPAM-sources'= confirmed SPAM sources category; 'SPAM-URLs'= SPAM URLs category; 'unconfirmed-SPAM-sources'= unconfirmed SPAM sources category; 'open-HTTP-proxies'= open HTTP proxies category; 'dynamic-comment'= dynamic comment category; 'parked-domains'= parked domains category; 'alcohol-and-tobacco'= alcohol and tobacco category; 'private-IP-addresses'= private IP addresses category; 'image-and-video-search'= image and video search category; 'fashion-and-beauty'= fashion and beauty category; 'recreation-and-hobbies'= recreation and hobbies category; 'motor-vehicles'= motor vehicles category; 'web-hosting-sites'= web hosting sites category; 'food-and-dining'= food and dining category; 'uncategorised'= uncategorised; 'other-category'= other category; "
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
        - "'intercept'= intercept in no SNI case; 'bypass'= bypass in no SNI case; 'reset'= reset in no SNI case; "
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
        - "Certificate cache timeout, default is 1 hour (seconds, set to 0 for never timeout)"
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
        - "Set this NAT pool as higher precedence than other source NAT like configued under template policy"
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
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'= close the connection; 'block'= block the connection with a warning page; "
        required: False
    version:
        description:
        - "TLS/SSL version, default is the highest number supported (TLS/SSL version= 30-SSLv3.0, 31-TLSv1.0, 32-TLSv1.1 and 33-TLSv1.2)"
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
        - "Session ticket lifetime in seconds from stateless session resumption (Lifetime value in seconds. Default value 0 (Session ticket lifetime limit disabled))"
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
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse disabled))"
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
        - "Session Cache Timeout (Timeout value, in seconds. Default value 0 (Session cache timeout disabled))"
        required: False
    sslv2_bypass_service_group:
        description:
        - "Service Group for Bypass SSLV2 (Service Group Name)"
        required: False
    forward_proxy_decrypted_dscp:
        description:
        - "Apply a DSCP to decrypted and bypassed traffic (DSCP to apply to decrypted traffic)"
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
        - "'thales-embed'= Thales embed key; 'thales-hwcrhk'= Thales hwcrhk Key; "
        required: False
    forward_proxy_log_disable:
        description:
        - "Disable SSL forward proxy logging"
        required: False
    fp_alt_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
        required: False
    inspect_certificate_san_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject Alternative Name matches class-list"
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
        - "Action taken if a certificate revocation status is unknown, bypass SSLi processing by default"
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
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
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
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
        required: False
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
                - "Forward proxy bypass if Certificate  issuer contains another string (Certificate issuer)"
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
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1; "
    forward_proxy_decrypted_dscp_bypass:
        description:
        - "DSCP to apply to bypassed traffic"
        required: False
    alert_type:
        description:
        - "'fatal'= Log fatal alerts; "
        required: False
    forward_proxy_cert_not_ready_action:
        description:
        - "'bypass'= bypass the connection; 'reset'= reset the connection; 'intercept'= wait for cert and then inspect the connection; "
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
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
            server_shared_regex:
                description:
                - "Server Name Partition Shared"
            server_name_regex:
                description:
                - "Server name indication in Client hello extension with regular expression (Server name String with regex)"
            server_passphrase:
                description:
                - "help Password Phrase"
            server_key:
                description:
                - "Server Private Key associated to SNI (Server Private Key Name)"
            server_chain_regex:
                description:
                - "Server Certificate Chain associated to SNI regex (Server Certificate Chain Name)"
            server_name_alternate:
                description:
                - "Specific the second certifcate"
            server_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
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
        - "Set this NAT pool as higher precedence than other source NAT like configued under template policy"
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
        - "Action taken if handshake fails due to no shared ciper, close the connection by default"
        required: False
    forward_proxy_ocsp_disable:
        description:
        - "Disable ocsp-stapling for forward proxy"
        required: False
    sslilogging:
        description:
        - "'disable'= Disable all logging; 'all'= enable all logging(error, info); "
        required: False
    auth_username:
        description:
        - "Specify the Username Field in the Client Certificate(If multi-fields are specificed, prior one has higher priority)"
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
        - "'Ignore'= Don't request client certificate; 'Require'= Require client certificate; 'Request'= Request client certificate; "
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
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
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
        - "'1024'= 1024; '1024-dsa'= 1024-dsa; '2048'= 2048; "
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
                - "'SSL3_RSA_DES_192_CBC3_SHA'= SSL3_RSA_DES_192_CBC3_SHA; 'SSL3_RSA_RC4_128_MD5'= SSL3_RSA_RC4_128_MD5; 'SSL3_RSA_RC4_128_SHA'= SSL3_RSA_RC4_128_SHA; 'TLS1_RSA_AES_128_SHA'= TLS1_RSA_AES_128_SHA; 'TLS1_RSA_AES_256_SHA'= TLS1_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_SHA256'= TLS1_RSA_AES_128_SHA256; 'TLS1_RSA_AES_256_SHA256'= TLS1_RSA_AES_256_SHA256; 'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS1_DHE_RSA_AES_128_GCM_SHA256; 'TLS1_DHE_RSA_AES_128_SHA'= TLS1_DHE_RSA_AES_128_SHA; 'TLS1_DHE_RSA_AES_128_SHA256'= TLS1_DHE_RSA_AES_128_SHA256; 'TLS1_DHE_RSA_AES_256_GCM_SHA384'= TLS1_DHE_RSA_AES_256_GCM_SHA384; 'TLS1_DHE_RSA_AES_256_SHA'= TLS1_DHE_RSA_AES_256_SHA; 'TLS1_DHE_RSA_AES_256_SHA256'= TLS1_DHE_RSA_AES_256_SHA256; 'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256; 'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS1_ECDHE_ECDSA_AES_128_SHA; 'TLS1_ECDHE_ECDSA_AES_128_SHA256'= TLS1_ECDHE_ECDSA_AES_128_SHA256; 'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS1_ECDHE_ECDSA_AES_256_SHA; 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'= TLS1_ECDHE_RSA_AES_128_GCM_SHA256; 'TLS1_ECDHE_RSA_AES_128_SHA'= TLS1_ECDHE_RSA_AES_128_SHA; 'TLS1_ECDHE_RSA_AES_128_SHA256'= TLS1_ECDHE_RSA_AES_128_SHA256; 'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS1_ECDHE_RSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_RSA_AES_256_SHA'= TLS1_ECDHE_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_GCM_SHA256'= TLS1_RSA_AES_128_GCM_SHA256; 'TLS1_RSA_AES_256_GCM_SHA384'= TLS1_RSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_RSA_AES_256_SHA384'= TLS1_ECDHE_RSA_AES_256_SHA384; 'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS1_ECDHE_ECDSA_AES_256_SHA384; 'TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256'= TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256; 'TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256'= TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256; 'TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'= TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256; "
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

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["ad_group_list","alert_type","auth_sg","auth_sg_dn","auth_sg_filter","auth_username","auth_username_attribute","authen_name","authorization","bypass_cert_issuer_class_list_name","bypass_cert_issuer_multi_class_list","bypass_cert_san_class_list_name","bypass_cert_san_multi_class_list","bypass_cert_subject_class_list_name","bypass_cert_subject_multi_class_list","ca_certs","cache_persistence_list_name","case_insensitive","cert_alternate","cert_revoke_action","cert_shared_str","cert_str","cert_unknown_action","certificate_issuer_contains_list","certificate_issuer_ends_with_list","certificate_issuer_equals_list","certificate_issuer_starts_with_list","certificate_san_contains_list","certificate_san_ends_with_list","certificate_san_equals_list","certificate_san_starts_with_list","certificate_subject_contains_list","certificate_subject_ends_with_list","certificate_subject_equals_list","certificate_subject_starts_with_list","chain_cert","chain_cert_shared_str","cipher_without_prio_list","class_list_name","client_auth_case_insensitive","client_auth_class_list","client_auth_contains_list","client_auth_ends_with_list","client_auth_equals_list","client_auth_starts_with_list","client_certificate","close_notify","contains_list","crl_certs","dgversion","dh_type","direct_client_server_auth","disable_sslv3","ec_list","enable_tls_alert_logging","ends_with_list","equals_list","exception_ad_group_list","exception_certificate_issuer_cl_name","exception_certificate_san_cl_name","exception_certificate_subject_cl_name","exception_sni_cl_name","exception_user_name_list","expire_hours","forward_encrypted","forward_passphrase","forward_proxy_alt_sign","forward_proxy_block_message","forward_proxy_ca_cert","forward_proxy_ca_key","forward_proxy_cert_cache_limit","forward_proxy_cert_cache_timeout","forward_proxy_cert_expiry","forward_proxy_cert_not_ready_action","forward_proxy_cert_revoke_action","forward_proxy_cert_unknown_action","forward_proxy_crl_disable","forward_proxy_decrypted_dscp","forward_proxy_decrypted_dscp_bypass","forward_proxy_enable","forward_proxy_failsafe_disable","forward_proxy_log_disable","forward_proxy_no_shared_cipher_action","forward_proxy_no_sni_action","forward_proxy_ocsp_disable","forward_proxy_selfsign_redir","forward_proxy_ssl_version","forward_proxy_trusted_ca_lists","forward_proxy_verify_cert_fail_action","fp_alt_cert","fp_alt_encrypted","fp_alt_key","fp_alt_passphrase","fp_cert_ext_aia_ca_issuers","fp_cert_ext_aia_ocsp","fp_cert_ext_crldp","fp_cert_fetch_autonat","fp_cert_fetch_autonat_precedence","fp_cert_fetch_natpool_name","fp_cert_fetch_natpool_name_shared","fp_cert_fetch_natpool_precedence","handshake_logging_enable","hsm_type","inspect_certificate_issuer_cl_name","inspect_certificate_san_cl_name","inspect_certificate_subject_cl_name","inspect_list_name","key_alt_encrypted","key_alt_passphrase","key_alternate","key_encrypted","key_passphrase","key_shared_encrypted","key_shared_passphrase","key_shared_str","key_str","ldap_base_dn_from_cert","ldap_search_filter","local_logging","multi_class_list","name","no_shared_cipher_action","non_ssl_bypass_l4session","non_ssl_bypass_service_group","notafter","notafterday","notaftermonth","notafteryear","notbefore","notbeforeday","notbeforemonth","notbeforeyear","ocsp_stapling","ocspst_ca_cert","ocspst_ocsp","ocspst_sg","ocspst_sg_days","ocspst_sg_hours","ocspst_sg_minutes","ocspst_sg_timeout","ocspst_srvr","ocspst_srvr_days","ocspst_srvr_hours","ocspst_srvr_minutes","ocspst_srvr_timeout","renegotiation_disable","req_ca_lists","require_web_category","sampling_enable","server_name_auto_map","server_name_list","session_cache_size","session_cache_timeout","session_ticket_lifetime","shared_partition_cipher_template","shared_partition_pool","sni_enable_log","ssl_false_start_disable","ssli_logging","sslilogging","sslv2_bypass_service_group","starts_with_list","template_cipher","template_cipher_shared","template_hsm","user_name_list","user_tag","uuid","verify_cert_fail_action","version","web_category",]

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
        bypass_cert_subject_multi_class_list=dict(type='list',bypass_cert_subject_multi_class_list_name=dict(type='str',)),
        verify_cert_fail_action=dict(type='str',choices=['bypass','continue','drop','block']),
        inspect_certificate_issuer_cl_name=dict(type='str',),
        certificate_san_contains_list=dict(type='list',certificate_san_contains=dict(type='str',)),
        forward_proxy_block_message=dict(type='str',),
        direct_client_server_auth=dict(type='bool',),
        ocspst_sg_hours=dict(type='int',),
        no_shared_cipher_action=dict(type='str',choices=['bypass','drop']),
        fp_cert_fetch_autonat=dict(type='str',choices=['auto']),
        equals_list=dict(type='list',equals=dict(type='str',)),
        exception_certificate_subject_cl_name=dict(type='str',),
        uuid=dict(type='str',),
        forward_proxy_trusted_ca_lists=dict(type='list',forward_proxy_trusted_ca=dict(type='str',)),
        template_cipher_shared=dict(type='str',),
        forward_proxy_ca_cert=dict(type='str',),
        ssl_false_start_disable=dict(type='bool',),
        dgversion=dict(type='int',),
        client_auth_class_list=dict(type='str',),
        key_encrypted=dict(type='str',),
        notafteryear=dict(type='int',),
        forward_proxy_alt_sign=dict(type='bool',),
        template_hsm=dict(type='str',),
        forward_passphrase=dict(type='str',),
        exception_certificate_issuer_cl_name=dict(type='str',),
        contains_list=dict(type='list',contains=dict(type='str',)),
        forward_proxy_ca_key=dict(type='str',),
        notbefore=dict(type='bool',),
        ends_with_list=dict(type='list',ends_with=dict(type='str',)),
        bypass_cert_subject_class_list_name=dict(type='str',),
        notafter=dict(type='bool',),
        class_list_name=dict(type='str',),
        ocspst_ocsp=dict(type='bool',),
        notbeforeday=dict(type='int',),
        key_alt_passphrase=dict(type='str',),
        forward_proxy_ssl_version=dict(type='int',),
        ca_certs=dict(type='list',ca_cert=dict(type='str',),client_ocsp_sg=dict(type='str',),client_ocsp=dict(type='bool',),client_ocsp_srvr=dict(type='str',),ca_shared=dict(type='bool',)),
        forward_proxy_crl_disable=dict(type='bool',),
        client_auth_contains_list=dict(type='list',client_auth_contains=dict(type='str',)),
        certificate_subject_contains_list=dict(type='list',certificate_subject_contains=dict(type='str',)),
        name=dict(type='str',required=True,),
        forward_proxy_cert_revoke_action=dict(type='bool',),
        fp_cert_ext_aia_ocsp=dict(type='str',),
        req_ca_lists=dict(type='list',client_certificate_Request_CA=dict(type='str',)),
        user_tag=dict(type='str',),
        cert_unknown_action=dict(type='str',choices=['bypass','continue','drop','block']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','real-estate','computer-and-internet-security','financial-services','business-and-economy','computer-and-internet-info','auctions','shopping','cult-and-occult','travel','drugs','adult-and-pornography','home-and-garden','military','social-network','dead-sites','stock-advice-and-tools','training-and-tools','dating','sex-education','religion','entertainment-and-arts','personal-sites-and-blogs','legal','local-information','streaming-media','job-search','gambling','translation','reference-and-research','shareware-and-freeware','peer-to-peer','marijuana','hacking','games','philosophy-and-politics','weapons','pay-to-surf','hunting-and-fishing','society','educational-institutions','online-greeting-cards','sports','swimsuits-and-intimate-apparel','questionable','kids','hate-and-racism','personal-storage','violence','keyloggers-and-monitoring','search-engines','internet-portals','web-advertisements','cheating','gross','web-based-email','malware-sites','phishing-and-other-fraud','proxy-avoid-and-anonymizers','spyware-and-adware','music','government','nudity','news-and-media','illegal','CDNs','internet-communications','bot-nets','abortion','health-and-medicine','confirmed-SPAM-sources','SPAM-URLs','unconfirmed-SPAM-sources','open-HTTP-proxies','dynamic-comment','parked-domains','alcohol-and-tobacco','private-IP-addresses','image-and-video-search','fashion-and-beauty','recreation-and-hobbies','motor-vehicles','web-hosting-sites','food-and-dining','uncategorised','other-category'])),
        renegotiation_disable=dict(type='bool',),
        exception_ad_group_list=dict(type='str',),
        key_alternate=dict(type='str',),
        fp_alt_key=dict(type='str',),
        server_name_auto_map=dict(type='bool',),
        disable_sslv3=dict(type='bool',),
        bypass_cert_issuer_multi_class_list=dict(type='list',bypass_cert_issuer_multi_class_list_name=dict(type='str',)),
        client_auth_equals_list=dict(type='list',client_auth_equals=dict(type='str',)),
        forward_proxy_no_sni_action=dict(type='str',choices=['intercept','bypass','reset']),
        certificate_issuer_equals_list=dict(type='list',certificate_issuer_equals=dict(type='str',)),
        fp_alt_passphrase=dict(type='str',),
        certificate_subject_starts_with_list=dict(type='list',certificate_subject_starts=dict(type='str',)),
        certificate_san_ends_with_list=dict(type='list',certificate_san_ends_with=dict(type='str',)),
        forward_proxy_cert_cache_timeout=dict(type='int',),
        fp_cert_fetch_natpool_name_shared=dict(type='str',),
        crl_certs=dict(type='list',crl_shared=dict(type='bool',),crl=dict(type='str',)),
        notafterday=dict(type='int',),
        ocspst_srvr_hours=dict(type='int',),
        local_logging=dict(type='bool',),
        fp_cert_fetch_autonat_precedence=dict(type='bool',),
        cert_str=dict(type='str',),
        cert_shared_str=dict(type='str',),
        cert_revoke_action=dict(type='str',choices=['bypass','continue','drop','block']),
        version=dict(type='int',),
        multi_class_list=dict(type='list',multi_clist_name=dict(type='str',)),
        user_name_list=dict(type='str',),
        session_ticket_lifetime=dict(type='int',),
        certificate_issuer_ends_with_list=dict(type='list',certificate_issuer_ends_with=dict(type='str',)),
        ssli_logging=dict(type='bool',),
        session_cache_size=dict(type='int',),
        handshake_logging_enable=dict(type='bool',),
        non_ssl_bypass_service_group=dict(type='str',),
        forward_proxy_failsafe_disable=dict(type='bool',),
        session_cache_timeout=dict(type='int',),
        sslv2_bypass_service_group=dict(type='str',),
        forward_proxy_decrypted_dscp=dict(type='int',),
        auth_sg=dict(type='str',),
        ocspst_ca_cert=dict(type='str',),
        forward_proxy_selfsign_redir=dict(type='bool',),
        auth_sg_dn=dict(type='bool',),
        hsm_type=dict(type='str',choices=['thales-embed','thales-hwcrhk']),
        forward_proxy_log_disable=dict(type='bool',),
        fp_alt_encrypted=dict(type='str',),
        inspect_certificate_san_cl_name=dict(type='str',),
        web_category=dict(type='dict',philosophy_and_politics=dict(type='bool',),stock_advice_and_tools=dict(type='bool',),news_and_media=dict(type='bool',),business_and_economy=dict(type='bool',),peer_to_peer=dict(type='bool',),phishing_and_other_fraud=dict(type='bool',),nudity=dict(type='bool',),weapons=dict(type='bool',),health_and_medicine=dict(type='bool',),marijuana=dict(type='bool',),home_and_garden=dict(type='bool',),cult_and_occult=dict(type='bool',),society=dict(type='bool',),personal_storage=dict(type='bool',),computer_and_internet_security=dict(type='bool',),food_and_dining=dict(type='bool',),motor_vehicles=dict(type='bool',),swimsuits_and_intimate_apparel=dict(type='bool',),dead_sites=dict(type='bool',),translation=dict(type='bool',),proxy_avoid_and_anonymizers=dict(type='bool',),financial_services=dict(type='bool',),gross=dict(type='bool',),cheating=dict(type='bool',),entertainment_and_arts=dict(type='bool',),sex_education=dict(type='bool',),illegal=dict(type='bool',),travel=dict(type='bool',),cdns=dict(type='bool',),local_information=dict(type='bool',),legal=dict(type='bool',),sports=dict(type='bool',),bot_nets=dict(type='bool',),religion=dict(type='bool',),private_ip_addresses=dict(type='bool',),music=dict(type='bool',),hate_and_racism=dict(type='bool',),open_http_proxies=dict(type='bool',),internet_communications=dict(type='bool',),shareware_and_freeware=dict(type='bool',),dating=dict(type='bool',),spyware_and_adware=dict(type='bool',),uncategorized=dict(type='bool',),questionable=dict(type='bool',),reference_and_research=dict(type='bool',),web_advertisements=dict(type='bool',),streaming_media=dict(type='bool',),social_network=dict(type='bool',),government=dict(type='bool',),drugs=dict(type='bool',),web_hosting_sites=dict(type='bool',),malware_sites=dict(type='bool',),pay_to_surf=dict(type='bool',),spam_urls=dict(type='bool',),kids=dict(type='bool',),gambling=dict(type='bool',),online_greeting_cards=dict(type='bool',),confirmed_spam_sources=dict(type='bool',),image_and_video_search=dict(type='bool',),educational_institutions=dict(type='bool',),keyloggers_and_monitoring=dict(type='bool',),hunting_and_fishing=dict(type='bool',),search_engines=dict(type='bool',),fashion_and_beauty=dict(type='bool',),dynamic_comment=dict(type='bool',),computer_and_internet_info=dict(type='bool',),real_estate=dict(type='bool',),internet_portals=dict(type='bool',),shopping=dict(type='bool',),violence=dict(type='bool',),abortion=dict(type='bool',),training_and_tools=dict(type='bool',),web_based_email=dict(type='bool',),personal_sites_and_blogs=dict(type='bool',),unconfirmed_spam_sources=dict(type='bool',),games=dict(type='bool',),parked_domains=dict(type='bool',),auctions=dict(type='bool',),job_search=dict(type='bool',),recreation_and_hobbies=dict(type='bool',),hacking=dict(type='bool',),alcohol_and_tobacco=dict(type='bool',),adult_and_pornography=dict(type='bool',),military=dict(type='bool',)),
        certificate_san_equals_list=dict(type='list',certificate_san_equals=dict(type='str',)),
        template_cipher=dict(type='str',),
        notbeforemonth=dict(type='int',),
        bypass_cert_san_class_list_name=dict(type='str',),
        chain_cert=dict(type='str',),
        forward_proxy_cert_unknown_action=dict(type='bool',),
        exception_certificate_san_cl_name=dict(type='str',),
        ocspst_sg=dict(type='str',),
        key_alt_encrypted=dict(type='str',),
        fp_cert_ext_aia_ca_issuers=dict(type='str',),
        authen_name=dict(type='str',),
        expire_hours=dict(type='int',),
        client_auth_case_insensitive=dict(type='bool',),
        ocsp_stapling=dict(type='bool',),
        notbeforeyear=dict(type='int',),
        forward_encrypted=dict(type='str',),
        sni_enable_log=dict(type='bool',),
        key_shared_str=dict(type='str',),
        notaftermonth=dict(type='int',),
        cache_persistence_list_name=dict(type='str',),
        ocspst_sg_timeout=dict(type='int',),
        key_passphrase=dict(type='str',),
        ocspst_srvr=dict(type='str',),
        ocspst_srvr_minutes=dict(type='int',),
        certificate_issuer_contains_list=dict(type='list',certificate_issuer_contains=dict(type='str',)),
        require_web_category=dict(type='bool',),
        bypass_cert_san_multi_class_list=dict(type='list',bypass_cert_san_multi_class_list_name=dict(type='str',)),
        client_auth_starts_with_list=dict(type='list',client_auth_starts_with=dict(type='str',)),
        certificate_subject_ends_with_list=dict(type='list',certificate_subject_ends_with=dict(type='str',)),
        authorization=dict(type='bool',),
        forward_proxy_verify_cert_fail_action=dict(type='bool',),
        ocspst_srvr_days=dict(type='int',),
        ec_list=dict(type='list',ec=dict(type='str',choices=['secp256r1','secp384r1'])),
        forward_proxy_decrypted_dscp_bypass=dict(type='int',),
        alert_type=dict(type='str',choices=['fatal']),
        forward_proxy_cert_not_ready_action=dict(type='str',choices=['bypass','reset','intercept']),
        server_name_list=dict(type='list',server_shared=dict(type='bool',),server_passphrase_regex=dict(type='str',),server_chain=dict(type='str',),server_cert_regex=dict(type='str',),server_name=dict(type='str',),server_key_regex=dict(type='str',),server_name_regex_alternate=dict(type='bool',),server_encrypted_regex=dict(type='str',),server_shared_regex=dict(type='bool',),server_name_regex=dict(type='str',),server_passphrase=dict(type='str',),server_key=dict(type='str',),server_chain_regex=dict(type='str',),server_name_alternate=dict(type='bool',),server_encrypted=dict(type='str',),server_cert=dict(type='str',)),
        bypass_cert_issuer_class_list_name=dict(type='str',),
        fp_cert_ext_crldp=dict(type='str',),
        shared_partition_cipher_template=dict(type='bool',),
        fp_cert_fetch_natpool_precedence=dict(type='bool',),
        cert_alternate=dict(type='str',),
        forward_proxy_cert_cache_limit=dict(type='int',),
        non_ssl_bypass_l4session=dict(type='bool',),
        certificate_issuer_starts_with_list=dict(type='list',certificate_issuer_starts=dict(type='str',)),
        certificate_san_starts_with_list=dict(type='list',certificate_san_starts=dict(type='str',)),
        client_auth_ends_with_list=dict(type='list',client_auth_ends_with=dict(type='str',)),
        close_notify=dict(type='bool',),
        forward_proxy_no_shared_cipher_action=dict(type='bool',),
        forward_proxy_ocsp_disable=dict(type='bool',),
        sslilogging=dict(type='str',choices=['disable','all']),
        auth_username=dict(type='str',),
        exception_user_name_list=dict(type='str',),
        ocspst_sg_days=dict(type='int',),
        key_str=dict(type='str',),
        inspect_list_name=dict(type='str',),
        auth_username_attribute=dict(type='str',),
        fp_cert_fetch_natpool_name=dict(type='str',),
        exception_sni_cl_name=dict(type='str',),
        inspect_certificate_subject_cl_name=dict(type='str',),
        ldap_base_dn_from_cert=dict(type='bool',),
        ad_group_list=dict(type='str',),
        client_certificate=dict(type='str',choices=['Ignore','Require','Request']),
        forward_proxy_cert_expiry=dict(type='bool',),
        forward_proxy_enable=dict(type='bool',),
        shared_partition_pool=dict(type='bool',),
        ldap_search_filter=dict(type='str',),
        key_shared_encrypted=dict(type='str',),
        auth_sg_filter=dict(type='str',),
        ocspst_srvr_timeout=dict(type='int',),
        certificate_subject_equals_list=dict(type='list',certificate_subject_equals=dict(type='str',)),
        chain_cert_shared_str=dict(type='str',),
        enable_tls_alert_logging=dict(type='bool',),
        dh_type=dict(type='str',choices=['1024','1024-dsa','2048']),
        fp_alt_cert=dict(type='str',),
        case_insensitive=dict(type='bool',),
        cipher_without_prio_list=dict(type='list',cipher_wo_prio=dict(type='str',choices=['SSL3_RSA_DES_192_CBC3_SHA','SSL3_RSA_RC4_128_MD5','SSL3_RSA_RC4_128_SHA','TLS1_RSA_AES_128_SHA','TLS1_RSA_AES_256_SHA','TLS1_RSA_AES_128_SHA256','TLS1_RSA_AES_256_SHA256','TLS1_DHE_RSA_AES_128_GCM_SHA256','TLS1_DHE_RSA_AES_128_SHA','TLS1_DHE_RSA_AES_128_SHA256','TLS1_DHE_RSA_AES_256_GCM_SHA384','TLS1_DHE_RSA_AES_256_SHA','TLS1_DHE_RSA_AES_256_SHA256','TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256','TLS1_ECDHE_ECDSA_AES_128_SHA','TLS1_ECDHE_ECDSA_AES_128_SHA256','TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA','TLS1_ECDHE_RSA_AES_128_GCM_SHA256','TLS1_ECDHE_RSA_AES_128_SHA','TLS1_ECDHE_RSA_AES_128_SHA256','TLS1_ECDHE_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA','TLS1_RSA_AES_128_GCM_SHA256','TLS1_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA384','TLS1_ECDHE_RSA_CHACHA20_POLY1305_SHA256','TLS1_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256','TLS1_DHE_RSA_CHACHA20_POLY1305_SHA256'])),
        ocspst_sg_minutes=dict(type='int',),
        starts_with_list=dict(type='list',starts_with=dict(type='str',)),
        key_shared_passphrase=dict(type='str',)
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("client-ssl", module)
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
    payload = build_json("client-ssl", module)
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
    payload = build_json("client-ssl", module)
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