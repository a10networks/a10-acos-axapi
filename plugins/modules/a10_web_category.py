#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_web_category
description:
    - Web-Category Commands
short_description: Configures A10 web-category
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
    ansible_protocol:
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
    rtu_update_interval:
        description:
        - "Interval to check for real time updates if enabled in mins(default 60)"
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            web_cat_connection_status:
                description:
                - "Field web_cat_connection_status"
            web_cat_last_update_time:
                description:
                - "Field web_cat_last_update_time"
            bypassed_urls:
                description:
                - "Field bypassed_urls"
            intercepted_urls:
                description:
                - "Field intercepted_urls"
            license:
                description:
                - "Field license"
            url:
                description:
                - "Field url"
            web_cat_version:
                description:
                - "Field web_cat_version"
            web_cat_database_version:
                description:
                - "Field web_cat_database_version"
            web_cat_database_size:
                description:
                - "Field web_cat_database_size"
            statistics:
                description:
                - "Field statistics"
            web_cat_next_update_time:
                description:
                - "Field web_cat_next_update_time"
            web_cat_database_status:
                description:
                - "Field web_cat_database_status"
            web_cat_database_name:
                description:
                - "Field web_cat_database_name"
            web_cat_last_successful_connection:
                description:
                - "Field web_cat_last_successful_connection"
            web_cat_failure_reason:
                description:
                - "Field web_cat_failure_reason"
    database_server:
        description:
        - "BrightCloud Database Server"
        required: False
    port:
        description:
        - "BrightCloud Query Server Listening Port(default 80)"
        required: False
    statistics:
        description:
        - "Field statistics"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    intercepted_urls:
        description:
        - "Field intercepted_urls"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    server_timeout:
        description:
        - "BrightCloud Servers Timeout in seconds (default= 15s)"
        required: False
    cloud_query_cache_size:
        description:
        - "Maximum cache size for storing cloud query results"
        required: False
    rtu_update_disable:
        description:
        - "Disables real time updates(default enable)"
        required: False
    proxy_server:
        description:
        - "Field proxy_server"
        required: False
        suboptions:
            username:
                description:
                - "Username for proxy authentication"
            domain:
                description:
                - "Realm for NTLM authentication"
            uuid:
                description:
                - "uuid of the object"
            https_port:
                description:
                - "Proxy server HTTPS port(HTTP port will be used if not configured)"
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)"
            proxy_host:
                description:
                - "Proxy server hostname or IP address"
            auth_type:
                description:
                - "'ntlm'= NTLM authentication(default); 'basic'= Basic authentication; "
            http_port:
                description:
                - "Proxy server HTTP port"
            password:
                description:
                - "Password for proxy authentication"
            secret_string:
                description:
                - "password value"
    ssl_port:
        description:
        - "BrightCloud Servers SSL Port(default 443)"
        required: False
    enable:
        description:
        - "Enable BrightCloud SDK"
        required: False
    bypassed_urls:
        description:
        - "Field bypassed_urls"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    remote_syslog_enable:
        description:
        - "Enable data plane logging to a remote syslog server"
        required: False
    rtu_cache_size:
        description:
        - "Maximum cache size for storing RTU updates"
        required: False
    cloud_query_disable:
        description:
        - "Disables cloud queries for URL's not present in local database(default enable)"
        required: False
    use_mgmt_port:
        description:
        - "Use management interface for all communication with BrightCloud"
        required: False
    license:
        description:
        - "Field license"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    db_update_time:
        description:
        - "Time of day to update database (default= 00=00)"
        required: False
    server:
        description:
        - "BrightCloud Query Server"
        required: False
    url:
        description:
        - "Field url"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    category_list_list:
        description:
        - "Field category_list_list"
        required: False
        suboptions:
            streaming_media:
                description:
                - "Category Streaming Media"
            weapons:
                description:
                - "Category Weapons"
            uuid:
                description:
                - "uuid of the object"
            entertainment_and_arts:
                description:
                - "Category Entertainment and Arts"
            cdns:
                description:
                - "Category CDNs"
            financial_services:
                description:
                - "Category Financial Services"
            social_network:
                description:
                - "Category Social Network"
            government:
                description:
                - "Category Government"
            web_advertisements:
                description:
                - "Category Web Advertisements"
            fashion_and_beauty:
                description:
                - "Category Fashion and Beauty"
            computer_and_internet_security:
                description:
                - "Category Computer and Internet Security"
            name:
                description:
                - "Web Category List name"
            real_estate:
                description:
                - "Category Real Estate"
            user_tag:
                description:
                - "Customized tag"
            web_based_email:
                description:
                - "Category Web based email"
            sampling_enable:
                description:
                - "Field sampling_enable"
            recreation_and_hobbies:
                description:
                - "Category Recreation and Hobbies"
            business_and_economy:
                description:
                - "Category Business and Economy"
            confirmed_spam_sources:
                description:
                - "Category Confirmed SPAM Sources"
            philosophy_and_politics:
                description:
                - "Category Philosophy and Political Advocacy"
            society:
                description:
                - "Category Society"
            motor_vehicles:
                description:
                - "Category Motor Vehicles"
            proxy_avoid_and_anonymizers:
                description:
                - "Category Proxy Avoid and Anonymizers"
            gross:
                description:
                - "Category Gross"
            legal:
                description:
                - "Category Legal"
            bot_nets:
                description:
                - "Category Bot Nets"
            religion:
                description:
                - "Category Religion"
            private_ip_addresses:
                description:
                - "Category Private IP Addresses"
            dating:
                description:
                - "Category Dating"
            pay_to_surf:
                description:
                - "Category Pay to Surf"
            reference_and_research:
                description:
                - "Category Reference and Research"
            keyloggers_and_monitoring:
                description:
                - "Category Keyloggers and Monitoring"
            kids:
                description:
                - "Category Kids"
            online_greeting_cards:
                description:
                - "Category Online Greeting cards"
            violence:
                description:
                - "Category Violence"
            games:
                description:
                - "Category Games"
            auctions:
                description:
                - "Category Auctions"
            military:
                description:
                - "Category Military"
            alcohol_and_tobacco:
                description:
                - "Category Alcohol and Tobacco"
            stock_advice_and_tools:
                description:
                - "Category Stock Advice and Tools"
            news_and_media:
                description:
                - "Category News and Media"
            cult_and_occult:
                description:
                - "Category Cult and Occult"
            food_and_dining:
                description:
                - "Category Food and Dining"
            cheating:
                description:
                - "Category Cheating"
            illegal:
                description:
                - "Category Illegal"
            local_information:
                description:
                - "Category Local Information"
            sports:
                description:
                - "Category Sports"
            music:
                description:
                - "Category Music"
            shareware_and_freeware:
                description:
                - "Category Shareware and Freeware"
            spyware_and_adware:
                description:
                - "Category Spyware and Adware"
            questionable:
                description:
                - "Category Questionable"
            shopping:
                description:
                - "Category Shopping"
            drugs:
                description:
                - "Category Abused Drugs"
            web_hosting_sites:
                description:
                - "Category Web Hosting Sites"
            malware_sites:
                description:
                - "Category Malware Sites"
            dynamic_comment:
                description:
                - "Category Dynamic Comment"
            translation:
                description:
                - "Category Translation"
            job_search:
                description:
                - "Category Job Search"
            hunting_and_fishing:
                description:
                - "Category Hunting and Fishing"
            search_engines:
                description:
                - "Category Search Engines"
            educational_institutions:
                description:
                - "Category Educational Institutions"
            internet_portals:
                description:
                - "Category Internet Portals"
            computer_and_internet_info:
                description:
                - "Category Computer and Internet Info"
            abortion:
                description:
                - "Category Abortion"
            hacking:
                description:
                - "Category Hacking"
            adult_and_pornography:
                description:
                - "Category Adult and Pornography"
            phishing_and_other_fraud:
                description:
                - "Category Phishing and Other Frauds"
            nudity:
                description:
                - "Category Nudity"
            health_and_medicine:
                description:
                - "Category Health and Medicine"
            marijuana:
                description:
                - "Category Marijuana"
            home_and_garden:
                description:
                - "Category Home and Garden"
            personal_storage:
                description:
                - "Category Personal Storage"
            sex_education:
                description:
                - "Category Sex Education"
            swimsuits_and_intimate_apparel:
                description:
                - "Category Swimsuits and Intimate Apparel"
            dead_sites:
                description:
                - "Category Dead Sites (db Ops only)"
            travel:
                description:
                - "Category Travel"
            hate_and_racism:
                description:
                - "Category Hate and Racism"
            open_http_proxies:
                description:
                - "Category Open HTTP Proxies"
            internet_communications:
                description:
                - "Category Internet Communications"
            gambling:
                description:
                - "Category Gambling"
            peer_to_peer:
                description:
                - "Category Peer to Peer"
            uncategorized:
                description:
                - "Uncategorized URLs"
            personal_sites_and_blogs:
                description:
                - "Category Personal sites and Blogs"
            spam_urls:
                description:
                - "Category SPAM URLs"
            unconfirmed_spam_sources:
                description:
                - "Category Unconfirmed SPAM Sources"
            image_and_video_search:
                description:
                - "Category Image and Video Search"
            training_and_tools:
                description:
                - "Category Training and Tools"
            parked_domains:
                description:
                - "Category Parked Domains"


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["bypassed_urls","category_list_list","cloud_query_cache_size","cloud_query_disable","database_server","db_update_time","enable","intercepted_urls","license","oper","port","proxy_server","remote_syslog_enable","rtu_cache_size","rtu_update_disable","rtu_update_interval","server","server_timeout","ssl_port","statistics","url","use_mgmt_port","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        rtu_update_interval=dict(type='int', ),
        oper=dict(type='dict', web_cat_connection_status=dict(type='str', ), web_cat_last_update_time=dict(type='str', ), bypassed_urls=dict(type='dict', oper=dict(type='dict', all_urls=dict(type='str', choices=['true']), url_list=dict(type='list', url_name=dict(type='str', )), number_of_urls=dict(type='int', ), url_name=dict(type='str', ))), intercepted_urls=dict(type='dict', oper=dict(type='dict', all_urls=dict(type='str', choices=['true']), url_list=dict(type='list', url_name=dict(type='str', )), number_of_urls=dict(type='int', ), url_name=dict(type='str', ))), license=dict(type='dict', oper=dict(type='dict', license_status=dict(type='str', ), grace_period=dict(type='str', ), is_grace=dict(type='str', ), license_expiry=dict(type='str', ), serial_number=dict(type='str', ), remaining_period=dict(type='str', ), license_type=dict(type='str', ), module_status=dict(type='str', ))), url=dict(type='dict', oper=dict(type='dict', category_list=dict(type='list', category=dict(type='str', )), name=dict(type='str', ), local_db_only=dict(type='int', ))), web_cat_version=dict(type='str', ), web_cat_database_version=dict(type='int', ), web_cat_database_size=dict(type='str', ), statistics=dict(type='dict', oper=dict(type='dict', total_req_processed=dict(type='int', ), num_dplane_threads=dict(type='int', ), num_lookup_threads=dict(type='int', ), total_req_dropped=dict(type='int', ), total_req_queue=dict(type='int', ), per_cpu_list=dict(type='list', req_dropped=dict(type='int', ), req_queue=dict(type='int', ), req_lookup_processed=dict(type='int', ), req_processed=dict(type='int', )), total_req_lookup_processed=dict(type='int', ))), web_cat_next_update_time=dict(type='str', ), web_cat_database_status=dict(type='str', ), web_cat_database_name=dict(type='str', ), web_cat_last_successful_connection=dict(type='str', ), web_cat_failure_reason=dict(type='str', )),
        database_server=dict(type='str', ),
        port=dict(type='int', ),
        statistics=dict(type='dict', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'db-lookup', 'cloud-cache-lookup', 'cloud-lookup', 'rtu-lookup', 'lookup-latency', 'db-mem', 'rtu-cache-mem', 'lookup-cache-mem'])), uuid=dict(type='str', )),
        intercepted_urls=dict(type='dict', uuid=dict(type='str', )),
        uuid=dict(type='str', ),
        server_timeout=dict(type='int', ),
        cloud_query_cache_size=dict(type='int', ),
        rtu_update_disable=dict(type='bool', ),
        proxy_server=dict(type='dict', username=dict(type='str', ), domain=dict(type='str', ), uuid=dict(type='str', ), https_port=dict(type='int', ), encrypted=dict(type='str', ), proxy_host=dict(type='str', ), auth_type=dict(type='str', choices=['ntlm', 'basic']), http_port=dict(type='int', ), password=dict(type='bool', ), secret_string=dict(type='str', )),
        ssl_port=dict(type='int', ),
        enable=dict(type='bool', ),
        bypassed_urls=dict(type='dict', uuid=dict(type='str', )),
        remote_syslog_enable=dict(type='bool', ),
        rtu_cache_size=dict(type='int', ),
        cloud_query_disable=dict(type='bool', ),
        use_mgmt_port=dict(type='bool', ),
        license=dict(type='dict', uuid=dict(type='str', )),
        db_update_time=dict(type='str', ),
        server=dict(type='str', ),
        url=dict(type='dict', uuid=dict(type='str', )),
        category_list_list=dict(type='list', streaming_media=dict(type='bool', ), weapons=dict(type='bool', ), uuid=dict(type='str', ), entertainment_and_arts=dict(type='bool', ), cdns=dict(type='bool', ), financial_services=dict(type='bool', ), social_network=dict(type='bool', ), government=dict(type='bool', ), web_advertisements=dict(type='bool', ), fashion_and_beauty=dict(type='bool', ), computer_and_internet_security=dict(type='bool', ), name=dict(type='str', required=True, ), real_estate=dict(type='bool', ), user_tag=dict(type='str', ), web_based_email=dict(type='bool', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'uncategorized', 'real-estate', 'computer-and-internet-security', 'financial-services', 'business-and-economy', 'computer-and-internet-info', 'auctions', 'shopping', 'cult-and-occult', 'travel', 'drugs', 'adult-and-pornography', 'home-and-garden', 'military', 'social-network', 'dead-sites', 'stock-advice-and-tools', 'training-and-tools', 'dating', 'sex-education', 'religion', 'entertainment-and-arts', 'personal-sites-and-blogs', 'legal', 'local-information', 'streaming-media', 'job-search', 'gambling', 'translation', 'reference-and-research', 'shareware-and-freeware', 'peer-to-peer', 'marijuana', 'hacking', 'games', 'philosophy-and-politics', 'weapons', 'pay-to-surf', 'hunting-and-fishing', 'society', 'educational-institutions', 'online-greeting-cards', 'sports', 'swimsuits-and-intimate-apparel', 'questionable', 'kids', 'hate-and-racism', 'personal-storage', 'violence', 'keyloggers-and-monitoring', 'search-engines', 'internet-portals', 'web-advertisements', 'cheating', 'gross', 'web-based-email', 'malware-sites', 'phishing-and-other-fraud', 'proxy-avoid-and-anonymizers', 'spyware-and-adware', 'music', 'government', 'nudity', 'news-and-media', 'illegal', 'CDNs', 'internet-communications', 'bot-nets', 'abortion', 'health-and-medicine', 'confirmed-SPAM-sources', 'SPAM-URLs', 'unconfirmed-SPAM-sources', 'open-HTTP-proxies', 'dynamic-comment', 'parked-domains', 'alcohol-and-tobacco', 'private-IP-addresses', 'image-and-video-search', 'fashion-and-beauty', 'recreation-and-hobbies', 'motor-vehicles', 'web-hosting-sites', 'food-and-dining'])), recreation_and_hobbies=dict(type='bool', ), business_and_economy=dict(type='bool', ), confirmed_spam_sources=dict(type='bool', ), philosophy_and_politics=dict(type='bool', ), society=dict(type='bool', ), motor_vehicles=dict(type='bool', ), proxy_avoid_and_anonymizers=dict(type='bool', ), gross=dict(type='bool', ), legal=dict(type='bool', ), bot_nets=dict(type='bool', ), religion=dict(type='bool', ), private_ip_addresses=dict(type='bool', ), dating=dict(type='bool', ), pay_to_surf=dict(type='bool', ), reference_and_research=dict(type='bool', ), keyloggers_and_monitoring=dict(type='bool', ), kids=dict(type='bool', ), online_greeting_cards=dict(type='bool', ), violence=dict(type='bool', ), games=dict(type='bool', ), auctions=dict(type='bool', ), military=dict(type='bool', ), alcohol_and_tobacco=dict(type='bool', ), stock_advice_and_tools=dict(type='bool', ), news_and_media=dict(type='bool', ), cult_and_occult=dict(type='bool', ), food_and_dining=dict(type='bool', ), cheating=dict(type='bool', ), illegal=dict(type='bool', ), local_information=dict(type='bool', ), sports=dict(type='bool', ), music=dict(type='bool', ), shareware_and_freeware=dict(type='bool', ), spyware_and_adware=dict(type='bool', ), questionable=dict(type='bool', ), shopping=dict(type='bool', ), drugs=dict(type='bool', ), web_hosting_sites=dict(type='bool', ), malware_sites=dict(type='bool', ), dynamic_comment=dict(type='bool', ), translation=dict(type='bool', ), job_search=dict(type='bool', ), hunting_and_fishing=dict(type='bool', ), search_engines=dict(type='bool', ), educational_institutions=dict(type='bool', ), internet_portals=dict(type='bool', ), computer_and_internet_info=dict(type='bool', ), abortion=dict(type='bool', ), hacking=dict(type='bool', ), adult_and_pornography=dict(type='bool', ), phishing_and_other_fraud=dict(type='bool', ), nudity=dict(type='bool', ), health_and_medicine=dict(type='bool', ), marijuana=dict(type='bool', ), home_and_garden=dict(type='bool', ), personal_storage=dict(type='bool', ), sex_education=dict(type='bool', ), swimsuits_and_intimate_apparel=dict(type='bool', ), dead_sites=dict(type='bool', ), travel=dict(type='bool', ), hate_and_racism=dict(type='bool', ), open_http_proxies=dict(type='bool', ), internet_communications=dict(type='bool', ), gambling=dict(type='bool', ), peer_to_peer=dict(type='bool', ), uncategorized=dict(type='bool', ), personal_sites_and_blogs=dict(type='bool', ), spam_urls=dict(type='bool', ), unconfirmed_spam_sources=dict(type='bool', ), image_and_video_search=dict(type='bool', ), training_and_tools=dict(type='bool', ), parked_domains=dict(type='bool', ))
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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
    url_base = "/axapi/v3/web-category"

    f_dict = {}

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
        for k, v in payload["web-category"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["web-category"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["web-category"][k] = v
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
    payload = build_json("web-category", module)
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
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

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
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