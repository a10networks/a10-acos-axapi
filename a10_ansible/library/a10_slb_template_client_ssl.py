#!/usr/bin/python
# -*- coding: UTF-8 -*-

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
        - "'bypass'= bypass SSLi processing; 'continue'= continue the connection; 'drop'= close the connection; 'block'= block the connection with a warning page; "
        required: False
    inspect_certificate_issuer_cl_name:
        description:
        - "Forward proxy Inspect if Certificate issuer matches class-list"
        required: False
    forward_proxy_block_message:
        description:
        - "Message to be included on the block page (Message, enclose in quotes if spaces are present)"
        required: False
    ocspst_sg_hours:
        description:
        - "Specify update period, in hours"
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
    ec_list:
        description:
        - "Field ec_list"
        required: False
        suboptions:
            ec:
                description:
                - "'secp256r1'= X9_62_prime256v1; 'secp384r1'= secp384r1; "
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
            client_ocsp:
                description:
                - "Specify ocsp authentication server(s) for client certificate verification"
            client_ocsp_sg:
                description:
                - "Specify service-group (Service group name)"
            client_ocsp_srvr:
                description:
                - "Specify authentication server"
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
    fp_alt_key:
        description:
        - "CA Private Key for forward proxy alternate signing (Key name)"
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
    forward_proxy_cert_cache_timeout:
        description:
        - "Certificate cache timeout, default is 1 hour (seconds, set to 0 for never timeout)"
        required: False
    crl_certs:
        description:
        - "Field crl_certs"
        required: False
        suboptions:
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
    session_cache_size:
        description:
        - "Session Cache Size (Maximum cache size. Default value 0 (Session ID reuse disabled))"
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
    cert:
        description:
        - "Server Certificate (Certificate Name)"
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
    notbeforemonth:
        description:
        - "Month"
        required: False
    chain_cert:
        description:
        - "Chain Certificate (Chain Certificate Name)"
        required: False
    forward_proxy_cert_unknown_action:
        description:
        - "Action taken if a certificate revocation status is unknown, bypass SSLi processing by default"
        required: False
    key:
        description:
        - "Server Private Key (Key Name)"
        required: False
    ocspst_sg:
        description:
        - "Specify authentication service group"
        required: False
    exception_sni_cl_name:
        description:
        - "Exceptions to forward-proxy-bypass"
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
    ocspst_srvr:
        description:
        - "Specify OCSP authentication server"
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
    template_cipher:
        description:
        - "Cipher Template Name"
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
    client_auth_class_list:
        description:
        - "Forward proxy client auth bypass if SNI string matches class-list (Class List Name)"
        required: False
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
            server_passphrase_regex:
                description:
                - "help Password Phrase"
            server_cert_regex:
                description:
                - "Server Certificate associated to SNI regex (Server Certificate Name)"
            server_name:
                description:
                - "Server name indication in Client hello extension (Server name String)"
            server_key:
                description:
                - "Server Private Key associated to SNI (Server Private Key Name)"
            server_encrypted_regex:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)"
            server_name_regex:
                description:
                - "Server name indication in Client hello extension with regular expression (Server name String with regex)"
            server_key_regex:
                description:
                - "Server Private Key associated to SNI regex (Server Private Key Name)"
            server_passphrase:
                description:
                - "help Password Phrase"
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
    shared_partition_cipher_template:
        description:
        - "Reference a cipher template from shared partition"
        required: False
    fp_cert_fetch_natpool_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued under template policy"
        required: False
    forward_proxy_cert_cache_limit:
        description:
        - "Certificate cache size limit, default is 524288 (set to 0 for unlimited size)"
        required: False
    certificate_issuer_starts_with_list:
        description:
        - "Field certificate_issuer_starts_with_list"
        required: False
        suboptions:
            certificate_issuer_starts:
                description:
                - "Forward proxy bypass if Certificate issuer starts with another string"
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
    forward_proxy_ocsp_disable:
        description:
        - "Disable ocsp-stapling for forward proxy"
        required: False
    fp_cert_fetch_autonat_precedence:
        description:
        - "Set this NAT pool as higher precedence than other source NAT like configued under template policy"
        required: False
    auth_username:
        description:
        - "Specify the Username Field in the Client Certificate(If multi-fields are specificed, prior one has higher priority)"
        required: False
    fp_cert_ext_crldp:
        description:
        - "CRL Distribution Point (CRL Distribution Point URI)"
        required: False
    ocspst_sg_days:
        description:
        - "Specify update period, in days"
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
    inspect_certificate_subject_cl_name:
        description:
        - "Forward proxy Inspect if Certificate Subject matches class-list"
        required: False
    ldap_base_dn_from_cert:
        description:
        - "Use Subject DN as LDAP search base DN"
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
    ldap_search_filter:
        description:
        - "Specify LDAP search filter"
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
                - "'SSL3_RSA_DES_192_CBC3_SHA'= SSL3_RSA_DES_192_CBC3_SHA; 'SSL3_RSA_RC4_128_MD5'= SSL3_RSA_RC4_128_MD5; 'SSL3_RSA_RC4_128_SHA'= SSL3_RSA_RC4_128_SHA; 'TLS1_RSA_AES_128_SHA'= TLS1_RSA_AES_128_SHA; 'TLS1_RSA_AES_256_SHA'= TLS1_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_SHA256'= TLS1_RSA_AES_128_SHA256; 'TLS1_RSA_AES_256_SHA256'= TLS1_RSA_AES_256_SHA256; 'TLS1_DHE_RSA_AES_128_GCM_SHA256'= TLS1_DHE_RSA_AES_128_GCM_SHA256; 'TLS1_DHE_RSA_AES_128_SHA'= TLS1_DHE_RSA_AES_128_SHA; 'TLS1_DHE_RSA_AES_128_SHA256'= TLS1_DHE_RSA_AES_128_SHA256; 'TLS1_DHE_RSA_AES_256_GCM_SHA384'= TLS1_DHE_RSA_AES_256_GCM_SHA384; 'TLS1_DHE_RSA_AES_256_SHA'= TLS1_DHE_RSA_AES_256_SHA; 'TLS1_DHE_RSA_AES_256_SHA256'= TLS1_DHE_RSA_AES_256_SHA256; 'TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256'= TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256; 'TLS1_ECDHE_ECDSA_AES_128_SHA'= TLS1_ECDHE_ECDSA_AES_128_SHA; 'TLS1_ECDHE_ECDSA_AES_128_SHA256'= TLS1_ECDHE_ECDSA_AES_128_SHA256; 'TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384'= TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_ECDSA_AES_256_SHA'= TLS1_ECDHE_ECDSA_AES_256_SHA; 'TLS1_ECDHE_RSA_AES_128_GCM_SHA256'= TLS1_ECDHE_RSA_AES_128_GCM_SHA256; 'TLS1_ECDHE_RSA_AES_128_SHA'= TLS1_ECDHE_RSA_AES_128_SHA; 'TLS1_ECDHE_RSA_AES_128_SHA256'= TLS1_ECDHE_RSA_AES_128_SHA256; 'TLS1_ECDHE_RSA_AES_256_GCM_SHA384'= TLS1_ECDHE_RSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_RSA_AES_256_SHA'= TLS1_ECDHE_RSA_AES_256_SHA; 'TLS1_RSA_AES_128_GCM_SHA256'= TLS1_RSA_AES_128_GCM_SHA256; 'TLS1_RSA_AES_256_GCM_SHA384'= TLS1_RSA_AES_256_GCM_SHA384; 'TLS1_ECDHE_RSA_AES_256_SHA384'= TLS1_ECDHE_RSA_AES_256_SHA384; 'TLS1_ECDHE_ECDSA_AES_256_SHA384'= TLS1_ECDHE_ECDSA_AES_256_SHA384; "
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


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["alert_type","auth_sg","auth_sg_dn","auth_sg_filter","auth_username","auth_username_attribute","authen_name","authorization","bypass_cert_issuer_class_list_name","bypass_cert_issuer_multi_class_list","bypass_cert_subject_class_list_name","bypass_cert_subject_multi_class_list","ca_certs","cache_persistence_list_name","case_insensitive","cert","cert_revoke_action","cert_unknown_action","certificate_issuer_contains_list","certificate_issuer_ends_with_list","certificate_issuer_equals_list","certificate_issuer_starts_with_list","certificate_subject_contains_list","certificate_subject_ends_with_list","certificate_subject_equals_list","certificate_subject_starts_with_list","chain_cert","cipher_without_prio_list","class_list_name","client_auth_case_insensitive","client_auth_class_list","client_auth_contains_list","client_auth_ends_with_list","client_auth_equals_list","client_auth_starts_with_list","client_certificate","close_notify","contains_list","crl_certs","dgversion","dh_type","disable_sslv3","ec_list","enable_tls_alert_logging","ends_with_list","equals_list","exception_certificate_issuer_cl_name","exception_certificate_subject_cl_name","exception_sni_cl_name","expire_hours","forward_encrypted","forward_passphrase","forward_proxy_alt_sign","forward_proxy_block_message","forward_proxy_ca_cert","forward_proxy_ca_key","forward_proxy_cert_cache_limit","forward_proxy_cert_cache_timeout","forward_proxy_cert_expiry","forward_proxy_cert_not_ready_action","forward_proxy_cert_revoke_action","forward_proxy_cert_unknown_action","forward_proxy_crl_disable","forward_proxy_decrypted_dscp","forward_proxy_decrypted_dscp_bypass","forward_proxy_enable","forward_proxy_failsafe_disable","forward_proxy_log_disable","forward_proxy_ocsp_disable","forward_proxy_selfsign_redir","forward_proxy_ssl_version","forward_proxy_trusted_ca_lists","forward_proxy_verify_cert_fail_action","fp_alt_cert","fp_alt_encrypted","fp_alt_key","fp_alt_passphrase","fp_cert_ext_aia_ca_issuers","fp_cert_ext_aia_ocsp","fp_cert_ext_crldp","fp_cert_fetch_autonat","fp_cert_fetch_autonat_precedence","fp_cert_fetch_natpool_name","fp_cert_fetch_natpool_precedence","hsm_type","inspect_certificate_issuer_cl_name","inspect_certificate_subject_cl_name","inspect_list_name","key","key_encrypted","key_passphrase","ldap_base_dn_from_cert","ldap_search_filter","multi_class_list","name","non_ssl_bypass_service_group","notafter","notafterday","notaftermonth","notafteryear","notbefore","notbeforeday","notbeforemonth","notbeforeyear","ocsp_stapling","ocspst_ca_cert","ocspst_ocsp","ocspst_sg","ocspst_sg_days","ocspst_sg_hours","ocspst_sg_minutes","ocspst_sg_timeout","ocspst_srvr","ocspst_srvr_days","ocspst_srvr_hours","ocspst_srvr_minutes","ocspst_srvr_timeout","renegotiation_disable","req_ca_lists","sampling_enable","server_name_list","session_cache_size","session_cache_timeout","session_ticket_lifetime","shared_partition_cipher_template","ssl_false_start_disable","sslv2_bypass_service_group","starts_with_list","stats","template_cipher","template_cipher_shared","template_hsm","user_tag","uuid","verify_cert_fail_action","version","web_category",]

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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        bypass_cert_subject_multi_class_list=dict(type='list',bypass_cert_subject_multi_class_list_name=dict(type='str',)),
        verify_cert_fail_action=dict(type='str',choices=['bypass','continue','drop','block']),
        inspect_certificate_issuer_cl_name=dict(type='str',),
        forward_proxy_block_message=dict(type='str',),
        ocspst_sg_hours=dict(type='int',),
        fp_cert_fetch_autonat=dict(type='str',choices=['auto']),
        equals_list=dict(type='list',equals=dict(type='str',)),
        exception_certificate_subject_cl_name=dict(type='str',),
        uuid=dict(type='str',),
        forward_proxy_trusted_ca_lists=dict(type='list',forward_proxy_trusted_ca=dict(type='str',)),
        template_cipher_shared=dict(type='str',),
        forward_proxy_ca_cert=dict(type='str',),
        ssl_false_start_disable=dict(type='bool',),
        dgversion=dict(type='int',),
        ec_list=dict(type='list',ec=dict(type='str',choices=['secp256r1','secp384r1'])),
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
        forward_proxy_ssl_version=dict(type='int',),
        ca_certs=dict(type='list',ca_cert=dict(type='str',),client_ocsp=dict(type='bool',),client_ocsp_sg=dict(type='str',),client_ocsp_srvr=dict(type='str',)),
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
        fp_alt_key=dict(type='str',),
        disable_sslv3=dict(type='bool',),
        bypass_cert_issuer_multi_class_list=dict(type='list',bypass_cert_issuer_multi_class_list_name=dict(type='str',)),
        client_auth_equals_list=dict(type='list',client_auth_equals=dict(type='str',)),
        certificate_issuer_equals_list=dict(type='list',certificate_issuer_equals=dict(type='str',)),
        fp_alt_passphrase=dict(type='str',),
        certificate_subject_starts_with_list=dict(type='list',certificate_subject_starts=dict(type='str',)),
        forward_proxy_cert_cache_timeout=dict(type='int',),
        crl_certs=dict(type='list',crl=dict(type='str',)),
        notafterday=dict(type='int',),
        ocspst_srvr_hours=dict(type='int',),
        cert_revoke_action=dict(type='str',choices=['bypass','continue','drop','block']),
        version=dict(type='int',),
        multi_class_list=dict(type='list',multi_clist_name=dict(type='str',)),
        session_ticket_lifetime=dict(type='int',),
        certificate_issuer_ends_with_list=dict(type='list',certificate_issuer_ends_with=dict(type='str',)),
        session_cache_size=dict(type='int',),
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
        cert=dict(type='str',),
        web_category=dict(type='dict',philosophy_and_politics=dict(type='bool',),stock_advice_and_tools=dict(type='bool',),news_and_media=dict(type='bool',),business_and_economy=dict(type='bool',),peer_to_peer=dict(type='bool',),phishing_and_other_fraud=dict(type='bool',),nudity=dict(type='bool',),weapons=dict(type='bool',),health_and_medicine=dict(type='bool',),marijuana=dict(type='bool',),home_and_garden=dict(type='bool',),cult_and_occult=dict(type='bool',),society=dict(type='bool',),personal_storage=dict(type='bool',),computer_and_internet_security=dict(type='bool',),food_and_dining=dict(type='bool',),motor_vehicles=dict(type='bool',),swimsuits_and_intimate_apparel=dict(type='bool',),dead_sites=dict(type='bool',),translation=dict(type='bool',),proxy_avoid_and_anonymizers=dict(type='bool',),financial_services=dict(type='bool',),gross=dict(type='bool',),cheating=dict(type='bool',),entertainment_and_arts=dict(type='bool',),sex_education=dict(type='bool',),illegal=dict(type='bool',),travel=dict(type='bool',),cdns=dict(type='bool',),local_information=dict(type='bool',),legal=dict(type='bool',),sports=dict(type='bool',),bot_nets=dict(type='bool',),religion=dict(type='bool',),private_ip_addresses=dict(type='bool',),music=dict(type='bool',),hate_and_racism=dict(type='bool',),open_http_proxies=dict(type='bool',),internet_communications=dict(type='bool',),shareware_and_freeware=dict(type='bool',),dating=dict(type='bool',),spyware_and_adware=dict(type='bool',),uncategorized=dict(type='bool',),questionable=dict(type='bool',),reference_and_research=dict(type='bool',),web_advertisements=dict(type='bool',),streaming_media=dict(type='bool',),social_network=dict(type='bool',),government=dict(type='bool',),drugs=dict(type='bool',),web_hosting_sites=dict(type='bool',),malware_sites=dict(type='bool',),pay_to_surf=dict(type='bool',),spam_urls=dict(type='bool',),kids=dict(type='bool',),gambling=dict(type='bool',),online_greeting_cards=dict(type='bool',),confirmed_spam_sources=dict(type='bool',),image_and_video_search=dict(type='bool',),educational_institutions=dict(type='bool',),keyloggers_and_monitoring=dict(type='bool',),hunting_and_fishing=dict(type='bool',),search_engines=dict(type='bool',),fashion_and_beauty=dict(type='bool',),dynamic_comment=dict(type='bool',),computer_and_internet_info=dict(type='bool',),real_estate=dict(type='bool',),internet_portals=dict(type='bool',),shopping=dict(type='bool',),violence=dict(type='bool',),abortion=dict(type='bool',),training_and_tools=dict(type='bool',),web_based_email=dict(type='bool',),personal_sites_and_blogs=dict(type='bool',),unconfirmed_spam_sources=dict(type='bool',),games=dict(type='bool',),parked_domains=dict(type='bool',),auctions=dict(type='bool',),job_search=dict(type='bool',),recreation_and_hobbies=dict(type='bool',),hacking=dict(type='bool',),alcohol_and_tobacco=dict(type='bool',),adult_and_pornography=dict(type='bool',),military=dict(type='bool',)),
        notbeforemonth=dict(type='int',),
        chain_cert=dict(type='str',),
        forward_proxy_cert_unknown_action=dict(type='bool',),
        key=dict(type='str',),
        ocspst_sg=dict(type='str',),
        exception_sni_cl_name=dict(type='str',),
        fp_cert_ext_aia_ca_issuers=dict(type='str',),
        authen_name=dict(type='str',),
        expire_hours=dict(type='int',),
        client_auth_case_insensitive=dict(type='bool',),
        ocsp_stapling=dict(type='bool',),
        notbeforeyear=dict(type='int',),
        forward_encrypted=dict(type='str',),
        stats=dict(type='dict',stock_advice_and_tools=dict(type='str',),news_and_media=dict(type='str',),CDNs=dict(type='str',),cult_and_occult=dict(type='str',),fashion_and_beauty=dict(type='str',),food_and_dining=dict(type='str',),SPAM_URLs=dict(type='str',),streaming_media=dict(type='str',),bot_nets=dict(type='str',),cheating=dict(type='str',),entertainment_and_arts=dict(type='str',),illegal=dict(type='str',),local_information=dict(type='str',),sports=dict(type='str',),confirmed_SPAM_sources=dict(type='str',),private_IP_addresses=dict(type='str',),music=dict(type='str',),open_HTTP_proxies=dict(type='str',),shareware_and_freeware=dict(type='str',),spyware_and_adware=dict(type='str',),questionable=dict(type='str',),financial_services=dict(type='str',),social_network=dict(type='str',),government=dict(type='str',),drugs=dict(type='str',),web_hosting_sites=dict(type='str',),web_advertisements=dict(type='str',),educational_institutions=dict(type='str',),dynamic_comment=dict(type='str',),translation=dict(type='str',),job_search=dict(type='str',),hunting_and_fishing=dict(type='str',),search_engines=dict(type='str',),peer_to_peer=dict(type='str',),computer_and_internet_security=dict(type='str',),real_estate=dict(type='str',),computer_and_internet_info=dict(type='str',),internet_portals=dict(type='str',),shopping=dict(type='str',),philosophy_and_politics=dict(type='str',),web_based_email=dict(type='str',),recreation_and_hobbies=dict(type='str',),hacking=dict(type='str',),adult_and_pornography=dict(type='str',),business_and_economy=dict(type='str',),phishing_and_other_fraud=dict(type='str',),nudity=dict(type='str',),health_and_medicine=dict(type='str',),marijuana=dict(type='str',),home_and_garden=dict(type='str',),society=dict(type='str',),unconfirmed_SPAM_sources=dict(type='str',),personal_storage=dict(type='str',),motor_vehicles=dict(type='str',),swimsuits_and_intimate_apparel=dict(type='str',),dead_sites=dict(type='str',),other_category=dict(type='str',),proxy_avoid_and_anonymizers=dict(type='str',),gross=dict(type='str',),uncategorised=dict(type='str',),travel=dict(type='str',),legal=dict(type='str',),weapons=dict(type='str',),religion=dict(type='str',),hate_and_racism=dict(type='str',),internet_communications=dict(type='str',),gambling=dict(type='str',),dating=dict(type='str',),malware_sites=dict(type='str',),name=dict(type='str',required=True,),pay_to_surf=dict(type='str',),military=dict(type='str',),image_and_video_search=dict(type='str',),reference_and_research=dict(type='str',),keyloggers_and_monitoring=dict(type='str',),kids=dict(type='str',),online_greeting_cards=dict(type='str',),violence=dict(type='str',),training_and_tools=dict(type='str',),sex_education=dict(type='str',),personal_sites_and_blogs=dict(type='str',),games=dict(type='str',),parked_domains=dict(type='str',),auctions=dict(type='str',),abortion=dict(type='str',),alcohol_and_tobacco=dict(type='str',)),
        ocspst_srvr=dict(type='str',),
        notaftermonth=dict(type='int',),
        cache_persistence_list_name=dict(type='str',),
        ocspst_sg_timeout=dict(type='int',),
        key_passphrase=dict(type='str',),
        template_cipher=dict(type='str',),
        ocspst_srvr_minutes=dict(type='int',),
        certificate_issuer_contains_list=dict(type='list',certificate_issuer_contains=dict(type='str',)),
        client_auth_starts_with_list=dict(type='list',client_auth_starts_with=dict(type='str',)),
        certificate_subject_ends_with_list=dict(type='list',certificate_subject_ends_with=dict(type='str',)),
        authorization=dict(type='bool',),
        forward_proxy_verify_cert_fail_action=dict(type='bool',),
        ocspst_srvr_days=dict(type='int',),
        client_auth_class_list=dict(type='str',),
        forward_proxy_decrypted_dscp_bypass=dict(type='int',),
        alert_type=dict(type='str',choices=['fatal']),
        forward_proxy_cert_not_ready_action=dict(type='str',choices=['bypass','reset','intercept']),
        server_name_list=dict(type='list',server_passphrase_regex=dict(type='str',),server_cert_regex=dict(type='str',),server_name=dict(type='str',),server_key=dict(type='str',),server_encrypted_regex=dict(type='str',),server_name_regex=dict(type='str',),server_key_regex=dict(type='str',),server_passphrase=dict(type='str',),server_encrypted=dict(type='str',),server_cert=dict(type='str',)),
        bypass_cert_issuer_class_list_name=dict(type='str',),
        shared_partition_cipher_template=dict(type='bool',),
        fp_cert_fetch_natpool_precedence=dict(type='bool',),
        forward_proxy_cert_cache_limit=dict(type='int',),
        certificate_issuer_starts_with_list=dict(type='list',certificate_issuer_starts=dict(type='str',)),
        client_auth_ends_with_list=dict(type='list',client_auth_ends_with=dict(type='str',)),
        close_notify=dict(type='bool',),
        forward_proxy_ocsp_disable=dict(type='bool',),
        fp_cert_fetch_autonat_precedence=dict(type='bool',),
        auth_username=dict(type='str',),
        fp_cert_ext_crldp=dict(type='str',),
        ocspst_sg_days=dict(type='int',),
        inspect_list_name=dict(type='str',),
        auth_username_attribute=dict(type='str',),
        fp_cert_fetch_natpool_name=dict(type='str',),
        inspect_certificate_subject_cl_name=dict(type='str',),
        ldap_base_dn_from_cert=dict(type='bool',),
        client_certificate=dict(type='str',choices=['Ignore','Require','Request']),
        forward_proxy_cert_expiry=dict(type='bool',),
        forward_proxy_enable=dict(type='bool',),
        ldap_search_filter=dict(type='str',),
        auth_sg_filter=dict(type='str',),
        ocspst_srvr_timeout=dict(type='int',),
        certificate_subject_equals_list=dict(type='list',certificate_subject_equals=dict(type='str',)),
        enable_tls_alert_logging=dict(type='bool',),
        dh_type=dict(type='str',choices=['1024','1024-dsa','2048']),
        fp_alt_cert=dict(type='str',),
        case_insensitive=dict(type='bool',),
        cipher_without_prio_list=dict(type='list',cipher_wo_prio=dict(type='str',choices=['SSL3_RSA_DES_192_CBC3_SHA','SSL3_RSA_RC4_128_MD5','SSL3_RSA_RC4_128_SHA','TLS1_RSA_AES_128_SHA','TLS1_RSA_AES_256_SHA','TLS1_RSA_AES_128_SHA256','TLS1_RSA_AES_256_SHA256','TLS1_DHE_RSA_AES_128_GCM_SHA256','TLS1_DHE_RSA_AES_128_SHA','TLS1_DHE_RSA_AES_128_SHA256','TLS1_DHE_RSA_AES_256_GCM_SHA384','TLS1_DHE_RSA_AES_256_SHA','TLS1_DHE_RSA_AES_256_SHA256','TLS1_ECDHE_ECDSA_AES_128_GCM_SHA256','TLS1_ECDHE_ECDSA_AES_128_SHA','TLS1_ECDHE_ECDSA_AES_128_SHA256','TLS1_ECDHE_ECDSA_AES_256_GCM_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA','TLS1_ECDHE_RSA_AES_128_GCM_SHA256','TLS1_ECDHE_RSA_AES_128_SHA','TLS1_ECDHE_RSA_AES_128_SHA256','TLS1_ECDHE_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA','TLS1_RSA_AES_128_GCM_SHA256','TLS1_RSA_AES_256_GCM_SHA384','TLS1_ECDHE_RSA_AES_256_SHA384','TLS1_ECDHE_ECDSA_AES_256_SHA384'])),
        ocspst_sg_minutes=dict(type='int',),
        starts_with_list=dict(type='list',starts_with=dict(type='str',))
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
                    if result["changed"] != True:
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