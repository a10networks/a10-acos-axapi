#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_web_category_category_list
description:
    - None
short_description: Configures A10 web-category.category-list
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
    streaming_media:
        description:
        - "None"
        required: False
    weapons:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    entertainment_and_arts:
        description:
        - "None"
        required: False
    cdns:
        description:
        - "None"
        required: False
    financial_services:
        description:
        - "None"
        required: False
    social_network:
        description:
        - "None"
        required: False
    government:
        description:
        - "None"
        required: False
    web_advertisements:
        description:
        - "None"
        required: False
    fashion_and_beauty:
        description:
        - "None"
        required: False
    computer_and_internet_security:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    real_estate:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    web_based_email:
        description:
        - "None"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    recreation_and_hobbies:
        description:
        - "None"
        required: False
    business_and_economy:
        description:
        - "None"
        required: False
    confirmed_spam_sources:
        description:
        - "None"
        required: False
    philosophy_and_politics:
        description:
        - "None"
        required: False
    society:
        description:
        - "None"
        required: False
    motor_vehicles:
        description:
        - "None"
        required: False
    proxy_avoid_and_anonymizers:
        description:
        - "None"
        required: False
    gross:
        description:
        - "None"
        required: False
    legal:
        description:
        - "None"
        required: False
    bot_nets:
        description:
        - "None"
        required: False
    religion:
        description:
        - "None"
        required: False
    private_ip_addresses:
        description:
        - "None"
        required: False
    dating:
        description:
        - "None"
        required: False
    pay_to_surf:
        description:
        - "None"
        required: False
    reference_and_research:
        description:
        - "None"
        required: False
    keyloggers_and_monitoring:
        description:
        - "None"
        required: False
    kids:
        description:
        - "None"
        required: False
    online_greeting_cards:
        description:
        - "None"
        required: False
    violence:
        description:
        - "None"
        required: False
    games:
        description:
        - "None"
        required: False
    auctions:
        description:
        - "None"
        required: False
    military:
        description:
        - "None"
        required: False
    alcohol_and_tobacco:
        description:
        - "None"
        required: False
    stock_advice_and_tools:
        description:
        - "None"
        required: False
    news_and_media:
        description:
        - "None"
        required: False
    cult_and_occult:
        description:
        - "None"
        required: False
    food_and_dining:
        description:
        - "None"
        required: False
    cheating:
        description:
        - "None"
        required: False
    illegal:
        description:
        - "None"
        required: False
    local_information:
        description:
        - "None"
        required: False
    sports:
        description:
        - "None"
        required: False
    music:
        description:
        - "None"
        required: False
    shareware_and_freeware:
        description:
        - "None"
        required: False
    spyware_and_adware:
        description:
        - "None"
        required: False
    questionable:
        description:
        - "None"
        required: False
    shopping:
        description:
        - "None"
        required: False
    drugs:
        description:
        - "None"
        required: False
    web_hosting_sites:
        description:
        - "None"
        required: False
    malware_sites:
        description:
        - "None"
        required: False
    dynamic_comment:
        description:
        - "None"
        required: False
    translation:
        description:
        - "None"
        required: False
    job_search:
        description:
        - "None"
        required: False
    hunting_and_fishing:
        description:
        - "None"
        required: False
    search_engines:
        description:
        - "None"
        required: False
    educational_institutions:
        description:
        - "None"
        required: False
    internet_portals:
        description:
        - "None"
        required: False
    computer_and_internet_info:
        description:
        - "None"
        required: False
    abortion:
        description:
        - "None"
        required: False
    hacking:
        description:
        - "None"
        required: False
    adult_and_pornography:
        description:
        - "None"
        required: False
    phishing_and_other_fraud:
        description:
        - "None"
        required: False
    nudity:
        description:
        - "None"
        required: False
    health_and_medicine:
        description:
        - "None"
        required: False
    marijuana:
        description:
        - "None"
        required: False
    home_and_garden:
        description:
        - "None"
        required: False
    personal_storage:
        description:
        - "None"
        required: False
    sex_education:
        description:
        - "None"
        required: False
    swimsuits_and_intimate_apparel:
        description:
        - "None"
        required: False
    dead_sites:
        description:
        - "None"
        required: False
    travel:
        description:
        - "None"
        required: False
    hate_and_racism:
        description:
        - "None"
        required: False
    open_http_proxies:
        description:
        - "None"
        required: False
    internet_communications:
        description:
        - "None"
        required: False
    gambling:
        description:
        - "None"
        required: False
    peer_to_peer:
        description:
        - "None"
        required: False
    uncategorized:
        description:
        - "None"
        required: False
    personal_sites_and_blogs:
        description:
        - "None"
        required: False
    spam_urls:
        description:
        - "None"
        required: False
    unconfirmed_spam_sources:
        description:
        - "None"
        required: False
    image_and_video_search:
        description:
        - "None"
        required: False
    training_and_tools:
        description:
        - "None"
        required: False
    parked_domains:
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
AVAILABLE_PROPERTIES = ["abortion","adult_and_pornography","alcohol_and_tobacco","auctions","bot_nets","business_and_economy","cdns","cheating","computer_and_internet_info","computer_and_internet_security","confirmed_spam_sources","cult_and_occult","dating","dead_sites","drugs","dynamic_comment","educational_institutions","entertainment_and_arts","fashion_and_beauty","financial_services","food_and_dining","gambling","games","government","gross","hacking","hate_and_racism","health_and_medicine","home_and_garden","hunting_and_fishing","illegal","image_and_video_search","internet_communications","internet_portals","job_search","keyloggers_and_monitoring","kids","legal","local_information","malware_sites","marijuana","military","motor_vehicles","music","name","news_and_media","nudity","online_greeting_cards","open_http_proxies","parked_domains","pay_to_surf","peer_to_peer","personal_sites_and_blogs","personal_storage","philosophy_and_politics","phishing_and_other_fraud","private_ip_addresses","proxy_avoid_and_anonymizers","questionable","real_estate","recreation_and_hobbies","reference_and_research","religion","sampling_enable","search_engines","sex_education","shareware_and_freeware","shopping","social_network","society","spam_urls","sports","spyware_and_adware","stock_advice_and_tools","streaming_media","swimsuits_and_intimate_apparel","training_and_tools","translation","travel","uncategorized","unconfirmed_spam_sources","user_tag","uuid","violence","weapons","web_advertisements","web_based_email","web_hosting_sites",]

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
        streaming_media=dict(type='bool',),
        weapons=dict(type='bool',),
        uuid=dict(type='str',),
        entertainment_and_arts=dict(type='bool',),
        cdns=dict(type='bool',),
        financial_services=dict(type='bool',),
        social_network=dict(type='bool',),
        government=dict(type='bool',),
        web_advertisements=dict(type='bool',),
        fashion_and_beauty=dict(type='bool',),
        computer_and_internet_security=dict(type='bool',),
        name=dict(type='str',required=True,),
        real_estate=dict(type='bool',),
        user_tag=dict(type='str',),
        web_based_email=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','uncategorized','real-estate','computer-and-internet-security','financial-services','business-and-economy','computer-and-internet-info','auctions','shopping','cult-and-occult','travel','drugs','adult-and-pornography','home-and-garden','military','social-network','dead-sites','stock-advice-and-tools','training-and-tools','dating','sex-education','religion','entertainment-and-arts','personal-sites-and-blogs','legal','local-information','streaming-media','job-search','gambling','translation','reference-and-research','shareware-and-freeware','peer-to-peer','marijuana','hacking','games','philosophy-and-politics','weapons','pay-to-surf','hunting-and-fishing','society','educational-institutions','online-greeting-cards','sports','swimsuits-and-intimate-apparel','questionable','kids','hate-and-racism','personal-storage','violence','keyloggers-and-monitoring','search-engines','internet-portals','web-advertisements','cheating','gross','web-based-email','malware-sites','phishing-and-other-fraud','proxy-avoid-and-anonymizers','spyware-and-adware','music','government','nudity','news-and-media','illegal','CDNs','internet-communications','bot-nets','abortion','health-and-medicine','confirmed-SPAM-sources','SPAM-URLs','unconfirmed-SPAM-sources','open-HTTP-proxies','dynamic-comment','parked-domains','alcohol-and-tobacco','private-IP-addresses','image-and-video-search','fashion-and-beauty','recreation-and-hobbies','motor-vehicles','web-hosting-sites','food-and-dining'])),
        recreation_and_hobbies=dict(type='bool',),
        business_and_economy=dict(type='bool',),
        confirmed_spam_sources=dict(type='bool',),
        philosophy_and_politics=dict(type='bool',),
        society=dict(type='bool',),
        motor_vehicles=dict(type='bool',),
        proxy_avoid_and_anonymizers=dict(type='bool',),
        gross=dict(type='bool',),
        legal=dict(type='bool',),
        bot_nets=dict(type='bool',),
        religion=dict(type='bool',),
        private_ip_addresses=dict(type='bool',),
        dating=dict(type='bool',),
        pay_to_surf=dict(type='bool',),
        reference_and_research=dict(type='bool',),
        keyloggers_and_monitoring=dict(type='bool',),
        kids=dict(type='bool',),
        online_greeting_cards=dict(type='bool',),
        violence=dict(type='bool',),
        games=dict(type='bool',),
        auctions=dict(type='bool',),
        military=dict(type='bool',),
        alcohol_and_tobacco=dict(type='bool',),
        stock_advice_and_tools=dict(type='bool',),
        news_and_media=dict(type='bool',),
        cult_and_occult=dict(type='bool',),
        food_and_dining=dict(type='bool',),
        cheating=dict(type='bool',),
        illegal=dict(type='bool',),
        local_information=dict(type='bool',),
        sports=dict(type='bool',),
        music=dict(type='bool',),
        shareware_and_freeware=dict(type='bool',),
        spyware_and_adware=dict(type='bool',),
        questionable=dict(type='bool',),
        shopping=dict(type='bool',),
        drugs=dict(type='bool',),
        web_hosting_sites=dict(type='bool',),
        malware_sites=dict(type='bool',),
        dynamic_comment=dict(type='bool',),
        translation=dict(type='bool',),
        job_search=dict(type='bool',),
        hunting_and_fishing=dict(type='bool',),
        search_engines=dict(type='bool',),
        educational_institutions=dict(type='bool',),
        internet_portals=dict(type='bool',),
        computer_and_internet_info=dict(type='bool',),
        abortion=dict(type='bool',),
        hacking=dict(type='bool',),
        adult_and_pornography=dict(type='bool',),
        phishing_and_other_fraud=dict(type='bool',),
        nudity=dict(type='bool',),
        health_and_medicine=dict(type='bool',),
        marijuana=dict(type='bool',),
        home_and_garden=dict(type='bool',),
        personal_storage=dict(type='bool',),
        sex_education=dict(type='bool',),
        swimsuits_and_intimate_apparel=dict(type='bool',),
        dead_sites=dict(type='bool',),
        travel=dict(type='bool',),
        hate_and_racism=dict(type='bool',),
        open_http_proxies=dict(type='bool',),
        internet_communications=dict(type='bool',),
        gambling=dict(type='bool',),
        peer_to_peer=dict(type='bool',),
        uncategorized=dict(type='bool',),
        personal_sites_and_blogs=dict(type='bool',),
        spam_urls=dict(type='bool',),
        unconfirmed_spam_sources=dict(type='bool',),
        image_and_video_search=dict(type='bool',),
        training_and_tools=dict(type='bool',),
        parked_domains=dict(type='bool',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/web-category/category-list/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/web-category/category-list/{name}"
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("category-list", module)
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
    payload = build_json("category-list", module)
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