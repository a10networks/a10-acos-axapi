#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_web_category
description:
    - None
short_description: Configures A10 web-category
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
    cloud_query_disable:
        description:
        - "None"
        required: False
    rtu_update_interval:
        description:
        - "None"
        required: False
    enable:
        description:
        - "None"
        required: False
    intercepted_urls:
        description:
        - "Field intercepted_urls"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
    use_mgmt_port:
        description:
        - "None"
        required: False
    database_server:
        description:
        - "None"
        required: False
    db_update_time:
        description:
        - "None"
        required: False
    server_timeout:
        description:
        - "None"
        required: False
    server:
        description:
        - "None"
        required: False
    url:
        description:
        - "Field url"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
    bypassed_urls:
        description:
        - "Field bypassed_urls"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
    remote_syslog_enable:
        description:
        - "None"
        required: False
    rtu_update_disable:
        description:
        - "None"
        required: False
    proxy_server:
        description:
        - "Field proxy_server"
        required: False
        suboptions:
            username:
                description:
                - "None"
            domain:
                description:
                - "None"
            uuid:
                description:
                - "None"
            https_port:
                description:
                - "None"
            encrypted:
                description:
                - "None"
            proxy_host:
                description:
                - "None"
            auth_type:
                description:
                - "None"
            http_port:
                description:
                - "None"
            password:
                description:
                - "None"
            secret_string:
                description:
                - "None"
    license:
        description:
        - "Field license"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
    category_list_list:
        description:
        - "Field category_list_list"
        required: False
        suboptions:
            streaming_media:
                description:
                - "None"
            weapons:
                description:
                - "None"
            uuid:
                description:
                - "None"
            entertainment_and_arts:
                description:
                - "None"
            cdns:
                description:
                - "None"
            financial_services:
                description:
                - "None"
            social_network:
                description:
                - "None"
            government:
                description:
                - "None"
            web_advertisements:
                description:
                - "None"
            fashion_and_beauty:
                description:
                - "None"
            computer_and_internet_security:
                description:
                - "None"
            name:
                description:
                - "None"
            real_estate:
                description:
                - "None"
            user_tag:
                description:
                - "None"
            web_based_email:
                description:
                - "None"
            sampling_enable:
                description:
                - "Field sampling_enable"
            recreation_and_hobbies:
                description:
                - "None"
            business_and_economy:
                description:
                - "None"
            confirmed_spam_sources:
                description:
                - "None"
            philosophy_and_politics:
                description:
                - "None"
            society:
                description:
                - "None"
            motor_vehicles:
                description:
                - "None"
            proxy_avoid_and_anonymizers:
                description:
                - "None"
            gross:
                description:
                - "None"
            legal:
                description:
                - "None"
            bot_nets:
                description:
                - "None"
            religion:
                description:
                - "None"
            private_ip_addresses:
                description:
                - "None"
            dating:
                description:
                - "None"
            pay_to_surf:
                description:
                - "None"
            reference_and_research:
                description:
                - "None"
            keyloggers_and_monitoring:
                description:
                - "None"
            kids:
                description:
                - "None"
            online_greeting_cards:
                description:
                - "None"
            violence:
                description:
                - "None"
            games:
                description:
                - "None"
            auctions:
                description:
                - "None"
            military:
                description:
                - "None"
            alcohol_and_tobacco:
                description:
                - "None"
            stock_advice_and_tools:
                description:
                - "None"
            news_and_media:
                description:
                - "None"
            cult_and_occult:
                description:
                - "None"
            food_and_dining:
                description:
                - "None"
            cheating:
                description:
                - "None"
            illegal:
                description:
                - "None"
            local_information:
                description:
                - "None"
            sports:
                description:
                - "None"
            music:
                description:
                - "None"
            shareware_and_freeware:
                description:
                - "None"
            spyware_and_adware:
                description:
                - "None"
            questionable:
                description:
                - "None"
            shopping:
                description:
                - "None"
            drugs:
                description:
                - "None"
            web_hosting_sites:
                description:
                - "None"
            malware_sites:
                description:
                - "None"
            dynamic_comment:
                description:
                - "None"
            translation:
                description:
                - "None"
            job_search:
                description:
                - "None"
            hunting_and_fishing:
                description:
                - "None"
            search_engines:
                description:
                - "None"
            educational_institutions:
                description:
                - "None"
            internet_portals:
                description:
                - "None"
            computer_and_internet_info:
                description:
                - "None"
            abortion:
                description:
                - "None"
            hacking:
                description:
                - "None"
            adult_and_pornography:
                description:
                - "None"
            phishing_and_other_fraud:
                description:
                - "None"
            nudity:
                description:
                - "None"
            health_and_medicine:
                description:
                - "None"
            marijuana:
                description:
                - "None"
            home_and_garden:
                description:
                - "None"
            personal_storage:
                description:
                - "None"
            sex_education:
                description:
                - "None"
            swimsuits_and_intimate_apparel:
                description:
                - "None"
            dead_sites:
                description:
                - "None"
            travel:
                description:
                - "None"
            hate_and_racism:
                description:
                - "None"
            open_http_proxies:
                description:
                - "None"
            internet_communications:
                description:
                - "None"
            gambling:
                description:
                - "None"
            peer_to_peer:
                description:
                - "None"
            uncategorized:
                description:
                - "None"
            personal_sites_and_blogs:
                description:
                - "None"
            spam_urls:
                description:
                - "None"
            unconfirmed_spam_sources:
                description:
                - "None"
            image_and_video_search:
                description:
                - "None"
            training_and_tools:
                description:
                - "None"
            parked_domains:
                description:
                - "None"
    port:
        description:
        - "None"
        required: False
    ssl_port:
        description:
        - "None"
        required: False
    uuid:
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
AVAILABLE_PROPERTIES = ["bypassed_urls","category_list_list","cloud_query_disable","database_server","db_update_time","enable","intercepted_urls","license","port","proxy_server","remote_syslog_enable","rtu_update_disable","rtu_update_interval","server","server_timeout","ssl_port","url","use_mgmt_port","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        cloud_query_disable=dict(type='bool',),
        rtu_update_interval=dict(type='int',),
        enable=dict(type='bool',),
        intercepted_urls=dict(type='dict',uuid=dict(type='str',)),
        use_mgmt_port=dict(type='bool',),
        database_server=dict(type='str',),
        db_update_time=dict(type='str',),
        server_timeout=dict(type='int',),
        server=dict(type='str',),
        url=dict(type='dict',uuid=dict(type='str',)),
        bypassed_urls=dict(type='dict',uuid=dict(type='str',)),
        remote_syslog_enable=dict(type='bool',),
        rtu_update_disable=dict(type='bool',),
        proxy_server=dict(type='dict',username=dict(type='str',),domain=dict(type='str',),uuid=dict(type='str',),https_port=dict(type='int',),encrypted=dict(type='str',),proxy_host=dict(type='str',),auth_type=dict(type='str',choices=['ntlm','basic']),http_port=dict(type='int',),password=dict(type='bool',),secret_string=dict(type='str',)),
        license=dict(type='dict',uuid=dict(type='str',)),
        category_list_list=dict(type='list',streaming_media=dict(type='bool',),weapons=dict(type='bool',),uuid=dict(type='str',),entertainment_and_arts=dict(type='bool',),cdns=dict(type='bool',),financial_services=dict(type='bool',),social_network=dict(type='bool',),government=dict(type='bool',),web_advertisements=dict(type='bool',),fashion_and_beauty=dict(type='bool',),computer_and_internet_security=dict(type='bool',),name=dict(type='str',required=True,),real_estate=dict(type='bool',),user_tag=dict(type='str',),web_based_email=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','uncategorized','real-estate','computer-and-internet-security','financial-services','business-and-economy','computer-and-internet-info','auctions','shopping','cult-and-occult','travel','drugs','adult-and-pornography','home-and-garden','military','social-network','dead-sites','stock-advice-and-tools','training-and-tools','dating','sex-education','religion','entertainment-and-arts','personal-sites-and-blogs','legal','local-information','streaming-media','job-search','gambling','translation','reference-and-research','shareware-and-freeware','peer-to-peer','marijuana','hacking','games','philosophy-and-politics','weapons','pay-to-surf','hunting-and-fishing','society','educational-institutions','online-greeting-cards','sports','swimsuits-and-intimate-apparel','questionable','kids','hate-and-racism','personal-storage','violence','keyloggers-and-monitoring','search-engines','internet-portals','web-advertisements','cheating','gross','web-based-email','malware-sites','phishing-and-other-fraud','proxy-avoid-and-anonymizers','spyware-and-adware','music','government','nudity','news-and-media','illegal','CDNs','internet-communications','bot-nets','abortion','health-and-medicine','confirmed-SPAM-sources','SPAM-URLs','unconfirmed-SPAM-sources','open-HTTP-proxies','dynamic-comment','parked-domains','alcohol-and-tobacco','private-IP-addresses','image-and-video-search','fashion-and-beauty','recreation-and-hobbies','motor-vehicles','web-hosting-sites','food-and-dining'])),recreation_and_hobbies=dict(type='bool',),business_and_economy=dict(type='bool',),confirmed_spam_sources=dict(type='bool',),philosophy_and_politics=dict(type='bool',),society=dict(type='bool',),motor_vehicles=dict(type='bool',),proxy_avoid_and_anonymizers=dict(type='bool',),gross=dict(type='bool',),legal=dict(type='bool',),bot_nets=dict(type='bool',),religion=dict(type='bool',),private_ip_addresses=dict(type='bool',),dating=dict(type='bool',),pay_to_surf=dict(type='bool',),reference_and_research=dict(type='bool',),keyloggers_and_monitoring=dict(type='bool',),kids=dict(type='bool',),online_greeting_cards=dict(type='bool',),violence=dict(type='bool',),games=dict(type='bool',),auctions=dict(type='bool',),military=dict(type='bool',),alcohol_and_tobacco=dict(type='bool',),stock_advice_and_tools=dict(type='bool',),news_and_media=dict(type='bool',),cult_and_occult=dict(type='bool',),food_and_dining=dict(type='bool',),cheating=dict(type='bool',),illegal=dict(type='bool',),local_information=dict(type='bool',),sports=dict(type='bool',),music=dict(type='bool',),shareware_and_freeware=dict(type='bool',),spyware_and_adware=dict(type='bool',),questionable=dict(type='bool',),shopping=dict(type='bool',),drugs=dict(type='bool',),web_hosting_sites=dict(type='bool',),malware_sites=dict(type='bool',),dynamic_comment=dict(type='bool',),translation=dict(type='bool',),job_search=dict(type='bool',),hunting_and_fishing=dict(type='bool',),search_engines=dict(type='bool',),educational_institutions=dict(type='bool',),internet_portals=dict(type='bool',),computer_and_internet_info=dict(type='bool',),abortion=dict(type='bool',),hacking=dict(type='bool',),adult_and_pornography=dict(type='bool',),phishing_and_other_fraud=dict(type='bool',),nudity=dict(type='bool',),health_and_medicine=dict(type='bool',),marijuana=dict(type='bool',),home_and_garden=dict(type='bool',),personal_storage=dict(type='bool',),sex_education=dict(type='bool',),swimsuits_and_intimate_apparel=dict(type='bool',),dead_sites=dict(type='bool',),travel=dict(type='bool',),hate_and_racism=dict(type='bool',),open_http_proxies=dict(type='bool',),internet_communications=dict(type='bool',),gambling=dict(type='bool',),peer_to_peer=dict(type='bool',),uncategorized=dict(type='bool',),personal_sites_and_blogs=dict(type='bool',),spam_urls=dict(type='bool',),unconfirmed_spam_sources=dict(type='bool',),image_and_video_search=dict(type='bool',),training_and_tools=dict(type='bool',),parked_domains=dict(type='bool',)),
        port=dict(type='int',),
        ssl_port=dict(type='int',),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category"
    f_dict = {}

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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("web-category", module)
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

def update(module, result, existing_config):
    payload = build_json("web-category", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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