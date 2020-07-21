#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_ssl_error
description:
    - Error
short_description: Configures A10 slb.ssl-error
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            bad_data_returned_by_callback:
                description:
                - "bad data returned by callback"
            bad_signature:
                description:
                - "bad signature"
            block_cipher_pad_is_wrong:
                description:
                - "block cipher pad is wrong"
            bad_protocol_version_number:
                description:
                - "bad protocol version number"
            null_ssl_method_passed:
                description:
                - "null ssl method passed"
            tls_client_cert_req_with_anon_cipher:
                description:
                - "tls client cert req with anon cipher"
            no_certificates_returned:
                description:
                - "no certificates returned"
            tlsv1_alert_insufficient_security:
                description:
                - "tlsv1 alert insufficient security"
            sslv3_alert_no_certificate:
                description:
                - "sslv3 alert no certificate"
            no_private_key_assigned:
                description:
                - "no private key assigned"
            certificate_verify_failed:
                description:
                - "certificate verify failed"
            krb5_server_tkt_skew:
                description:
                - "krb5 server tkt skew"
            bad_ssl_filetype:
                description:
                - "bad ssl filetype"
            ca_dn_length_mismatch:
                description:
                - "ca dn length mismatch"
            bad_alert_record:
                description:
                - "bad alert record"
            connection_type_not_set:
                description:
                - "connection type not set"
            dh_public_value_length_is_wrong:
                description:
                - "dh public value length is wrong"
            bio_not_set:
                description:
                - "bio not set"
            got_a_fin_before_a_ccs:
                description:
                - "got a fin before a ccs"
            sslv3_alert_decompression_failure:
                description:
                - "sslv3 alert decompression failure"
            unable_to_load_ssl2_md5_routines:
                description:
                - "unable to load ssl2 md5 routines"
            ssl_ctx_has_no_default_ssl_version:
                description:
                - "ssl ctx has no default ssl version"
            krb5_client_mk_req:
                description:
                - "krb5 client mk_req"
            uninitialized:
                description:
                - "uninitialized"
            wrong_cipher_returned:
                description:
                - "wrong cipher returned"
            missing_dh_rsa_cert:
                description:
                - "missing dh rsa cert"
            attempt_to_reuse_sess_in_diff_context:
                description:
                - "attempt to reuse sess in diff context"
            tls_invalid_ecpointformat_list:
                description:
                - "tls invalid ecpointformat list"
            null_ssl_ctx:
                description:
                - "null ssl ctx"
            bad_decompression:
                description:
                - "bad decompression"
            unknown_certificate_type:
                description:
                - "unknown certificate type"
            bad_response_argument:
                description:
                - "bad response argument"
            unknown_pkey_type:
                description:
                - "unknown pkey type"
            bad_message_type:
                description:
                - "bad message type"
            sslv3_alert_bad_record_mac:
                description:
                - "sslv3 alert bad record mac"
            compression_failure:
                description:
                - "compression failure"
            krb5_server_tkt_not_yet_valid:
                description:
                - "krb5 server tkt not yet valid"
            no_certificate_specified:
                description:
                - "no certificate specified"
            bad_hello_request:
                description:
                - "bad hello request"
            read_wrong_packet_type:
                description:
                - "read wrong packet type"
            missing_tmp_dh_key:
                description:
                - "missing tmp dh key"
            peer_did_not_return_a_certificate:
                description:
                - "peer did not return a certificate"
            missing_tmp_rsa_key:
                description:
                - "missing tmp rsa key"
            invalid_challenge_length:
                description:
                - "invalid challenge length"
            old_session_cipher_not_returned:
                description:
                - "old session cipher not returned"
            extra_data_in_message:
                description:
                - "extra data in message"
            missing_dsa_signing_cert:
                description:
                - "missing dsa signing cert"
            packet_length_too_long:
                description:
                - "packet length too long"
            tls_peer_did_not_respond_with_cert_list:
                description:
                - "tls peer did not respond with cert list"
            ssl_session_id_conflict:
                description:
                - "ssl session id conflict"
            unsupported_cipher:
                description:
                - "unsupported cipher"
            no_protocols_available:
                description:
                - "no protocols available"
            bad_change_cipher_spec:
                description:
                - "bad change cipher spec"
            no_compression_specified:
                description:
                - "no compression specified"
            bad_digest_length:
                description:
                - "bad digest length"
            https_proxy_request:
                description:
                - "https proxy request"
            no_required_digest:
                description:
                - "no required digest"
            bad_dh_g_length:
                description:
                - "bad dh g length"
            length_mismatch:
                description:
                - "length mismatch"
            tlsv1_alert_unknown_ca:
                description:
                - "tlsv1 alert unknown ca"
            tlsv1_alert_no_renegotiation:
                description:
                - "tlsv1 alert no renegotiation"
            sslv3_alert_unexpected_msg:
                description:
                - "sslv3 alert unexpected msg"
            missing_rsa_encrypting_cert:
                description:
                - "missing rsa encrypting cert"
            decryption_failed_or_bad_record_mac:
                description:
                - "decryption failed or bad record mac"
            cipher_or_hash_unavailable:
                description:
                - "cipher or hash unavailable"
            wrong_signature_size:
                description:
                - "wrong signature size"
            unable_to_decode_dh_certs:
                description:
                - "unable to decode dh certs"
            data_length_too_long:
                description:
                - "data length too long"
            unsupported_ssl_version:
                description:
                - "unsupported ssl version"
            invalid_command:
                description:
                - "invalid command"
            wrong_ssl_version:
                description:
                - "wrong ssl version"
            cert_length_mismatch:
                description:
                - "cert length mismatch"
            unable_to_find_public_key_parameters:
                description:
                - "unable to find public key parameters"
            data_between_ccs_and_finished:
                description:
                - "data between ccs and finished"
            ssl_library_has_no_ciphers:
                description:
                - "ssl library has no ciphers"
            sslv3_alert_certificate_unknown:
                description:
                - "sslv3 alert certificate unknown"
            protocol_is_shutdown:
                description:
                - "protocol is shutdown"
            no_ciphers_passed:
                description:
                - "no ciphers passed"
            no_certificate_returned:
                description:
                - "no certificate returned"
            invalid_purpose:
                description:
                - "invalid purpose"
            bad_write_retry:
                description:
                - "bad write retry"
            no_certificate_assigned:
                description:
                - "no certificate assigned"
            serverhello_tlsext:
                description:
                - "serverhello tlsext"
            pre_mac_length_too_long:
                description:
                - "pre mac length too long"
            non_sslv2_initial_packet:
                description:
                - "non sslv2 initial packet"
            sslv3_alert_peer_error_no_cert:
                description:
                - "sslv3 alert peer error no cert"
            ssl3_session_id_too_long:
                description:
                - "ssl3 session id too long"
            parse_tlsext:
                description:
                - "parse tlsext"
            bad_handshake_length:
                description:
                - "bad handshake length"
            connection_id_is_different:
                description:
                - "connection id is different"
            unknown_alert_type:
                description:
                - "unknown alert type"
            record_too_small:
                description:
                - "record too small"
            public_key_not_rsa:
                description:
                - "public key not rsa"
            sslv3_alert_peer_error_cert:
                description:
                - "sslv3 alert peer error cert"
            unable_to_load_ssl3_sha1_routines:
                description:
                - "unable to load ssl3 sha1 routines"
            sslv3_alert_handshake_failure:
                description:
                - "sslv3 alert handshake failure"
            short_read:
                description:
                - "short read"
            krb5_server_bad_ticket:
                description:
                - "krb5 server bad ticket"
            challenge_is_different:
                description:
                - "challenge is different"
            tlsv1_alert_decode_error:
                description:
                - "tlsv1 alert decode error"
            compressed_length_too_long:
                description:
                - "compressed length too long"
            missing_rsa_certificate:
                description:
                - "missing rsa certificate"
            ca_dn_too_long:
                description:
                - "ca dn too long"
            required_cipher_missing:
                description:
                - "required cipher missing"
            bad_ecc_cert:
                description:
                - "bad ecc cert"
            krb5_server_rd_req:
                description:
                - "krb5 server rd_req"
            bad_mac_decode:
                description:
                - "bad mac decode"
            no_verify_callback:
                description:
                - "no verify callback"
            ssl3_ext_invalid_servername_type:
                description:
                - "ssl3 ext invalid servername type"
            unexpected_record:
                description:
                - "unexpected record"
            public_key_is_not_rsa:
                description:
                - "public key is not rsa"
            sslv3_alert_certificate_expired:
                description:
                - "sslv3 alert certificate expired"
            length_too_short:
                description:
                - "length too short"
            peer_error_no_cipher:
                description:
                - "peer error no cipher"
            no_shared_cipher:
                description:
                - "no shared cipher"
            missing_tmp_rsa_pkey:
                description:
                - "missing tmp rsa pkey"
            unknown_cipher_type:
                description:
                - "unknown cipher type"
            tlsv1_alert_decrypt_error:
                description:
                - "tlsv1 alert decrypt error"
            unknown_state:
                description:
                - "unknown state"
            bad_dsa_signature:
                description:
                - "bad dsa signature"
            ssl3_session_id_too_short:
                description:
                - "ssl3 session id too short"
            no_cipher_match:
                description:
                - "no cipher match"
            missing_dh_key:
                description:
                - "missing dh key"
            ssl_handshake_failure:
                description:
                - "ssl handshake failure"
            inappropriate_fallback:
                description:
                - "inappropriate fallback"
            bad_checksum:
                description:
                - "bad checksum"
            unknown_cipher_returned:
                description:
                - "unknown cipher returned"
            no_client_cert_received:
                description:
                - "no client cert received"
            encrypted_length_too_long:
                description:
                - "encrypted length too long"
            tlsv1_alert_internal_error:
                description:
                - "tlsv1 alert internal error"
            peer_error_no_certificate:
                description:
                - "peer error no certificate"
            multiple_sgc_restarts:
                description:
                - "multiple sgc restarts"
            no_ciphers_specified:
                description:
                - "no ciphers specified"
            ssl_session_id_callback_failed:
                description:
                - "ssl session id callback failed"
            no_method_specified:
                description:
                - "no method specified"
            ssl_session_id_is_different:
                description:
                - "ssl session id is different"
            missing_rsa_signing_cert:
                description:
                - "missing rsa signing cert"
            krb5_client_init:
                description:
                - "krb5 client init"
            reuse_cert_type_not_zero:
                description:
                - "reuse cert type not zero"
            unable_to_find_dh_parameters:
                description:
                - "unable to find dh parameters"
            digest_check_failed:
                description:
                - "digest check failed"
            http_request:
                description:
                - "http request"
            app_data_in_handshake:
                description:
                - "app data in handshake"
            unsupported_protocol:
                description:
                - "unsupported protocol"
            no_cipher_list:
                description:
                - "no cipher list"
            sslv3_alert_peer_error_unsupp_cert_type:
                description:
                - "sslv3 alert peer error unsupp cert type"
            bad_state:
                description:
                - "bad state"
            unable_to_extract_public_key:
                description:
                - "unable to extract public key"
            peer_error_unsupported_certificate_type:
                description:
                - "peer error unsupported certificate type"
            bad_ecdsa_sig:
                description:
                - "bad ecdsa sig"
            tls_rsa_encrypted_value_length_is_wrong:
                description:
                - "tls rsa encrypted value length is wrong"
            missing_export_tmp_rsa_key:
                description:
                - "missing export tmp rsa key"
            peer_error:
                description:
                - "peer error"
            error_in_received_cipher_list:
                description:
                - "error in received cipher list"
            unable_to_load_ssl3_md5_routines:
                description:
                - "unable to load ssl3 md5 routines"
            cipher_table_src_error:
                description:
                - "cipher table src error"
            sslv3_alert_illegal_parameter:
                description:
                - "sslv3 alert illegal parameter"
            tlsv1_alert_protocol_version:
                description:
                - "tlsv1 alert protocol version"
            problems_mapping_cipher_functions:
                description:
                - "problems mapping cipher functions"
            unsupported_elliptic_curve:
                description:
                - "unsupported elliptic curve"
            bn_lib:
                description:
                - "bn lib"
            ccs_received_early:
                description:
                - "ccs received early"
            bad_rsa_encrypt:
                description:
                - "bad rsa encrypt"
            unsupported_status_type:
                description:
                - "unsupported status type"
            bad_ecpoint:
                description:
                - "bad ecpoint"
            ssl2_connection_id_too_long:
                description:
                - "ssl2 connection id too long"
            reuse_cipher_list_not_zero:
                description:
                - "reuse cipher list not zero"
            krb5:
                description:
                - "krb5"
            tried_to_use_unsupported_cipher:
                description:
                - "tried to use unsupported cipher"
            krb5_client_cc_principal:
                description:
                - "krb5 client cc principal"
            missing_export_tmp_dh_key:
                description:
                - "missing export tmp dh key"
            krb5_client_get_cred:
                description:
                - "krb5 client get cred"
            error_generating_tmp_rsa_key:
                description:
                - "error generating tmp rsa key"
            missing_verify_message:
                description:
                - "missing verify message"
            wrong_version_number:
                description:
                - "wrong version number"
            krb5_server_tkt_expired:
                description:
                - "krb5 server tkt expired"
            x509_lib:
                description:
                - "x509 lib"
            tlsv1_alert_access_denied:
                description:
                - "tlsv1 alert access denied"
            decryption_failed:
                description:
                - "decryption failed"
            tlsv1_alert_export_restriction:
                description:
                - "tlsv1 alert export restriction"
            library_has_no_ciphers:
                description:
                - "library has no ciphers"
            sslv3_alert_certificate_revoked:
                description:
                - "sslv3 alert certificate revoked"
            unknown_protocol:
                description:
                - "unknown protocol"
            bad_rsa_modulus_length:
                description:
                - "bad rsa modulus length"
            bad_authentication_type:
                description:
                - "bad authentication type"
            path_too_long:
                description:
                - "path too long"
            missing_dh_dsa_cert:
                description:
                - "missing dh dsa cert"
            reuse_cert_length_not_zero:
                description:
                - "reuse cert length not zero"
            bad_length:
                description:
                - "bad length"
            peer_error_certificate:
                description:
                - "peer error certificate"
            unsupported_option:
                description:
                - "unsupported option"
            unsupported_digest_type:
                description:
                - "unsupported digest type"
            ssl_session_id_context_too_long:
                description:
                - "ssl session id context too long"
            no_certificate_set:
                description:
                - "no certificate set"
            sslv3_alert_bad_certificate:
                description:
                - "sslv3 alert bad certificate"
            record_too_large:
                description:
                - "record too large"
            key_arg_too_long:
                description:
                - "key arg too long"
            illegal_padding:
                description:
                - "illegal padding"
            sslv3_alert_unspported_cert:
                description:
                - "sslv3 alert unspported cert"
            cipher_code_wrong_length:
                description:
                - "cipher code wrong length"
            no_privatekey:
                description:
                - "no privatekey"
            ssl3_ext_invalid_servername:
                description:
                - "ssl3 ext invalid servername"
            library_bug:
                description:
                - "library bug"
            compression_library_error:
                description:
                - "compression library error"
            write_bio_not_set:
                description:
                - "write bio not set"
            ssl23_doing_session_id_reuse:
                description:
                - "ssl23 doing session id reuse"
            bad_rsa_signature:
                description:
                - "bad rsa signature"
            session_id_context_uninitialized:
                description:
                - "session id context uninitialized"
            signature_for_non_signing_certificate:
                description:
                - "signature for non signing certificate"
            public_key_encrypt_error:
                description:
                - "public key encrypt error"
            x509_verification_setup_problems:
                description:
                - "x509 verification setup problems"
            unknown_ssl_version:
                description:
                - "unknown ssl version"
            mast_key_too_long:
                description:
                - "mast key too long"
            clienthello_tlsext:
                description:
                - "clienthello tlsext"
            tlsv1_alert_decryption_failed:
                description:
                - "tlsv1 alert decryption failed"
            invalid_trust:
                description:
                - "invalid trust"
            sslv3_alert_peer_error_no_cipher:
                description:
                - "sslv3 alert peer error no cipher"
            unable_to_find_ssl_method:
                description:
                - "unable to find ssl method"
            read_bio_not_set:
                description:
                - "read bio not set"
            bad_rsa_e_length:
                description:
                - "bad rsa e length"
            unknown_key_exchange_type:
                description:
                - "unknown key exchange type"
            invalid_status_response:
                description:
                - "invalid status response"
            cookie_mismatch:
                description:
                - "cookie mismatch"
            tlsv1_alert_record_overflow:
                description:
                - "tlsv1 alert record overflow"
            sslv3_alert_unknown_remote_err_type:
                description:
                - "sslv3 alert unknown remote err type"
            bad_packet_length:
                description:
                - "bad packet length"
            wrong_message_type:
                description:
                - "wrong message type"
            unknown_remote_error_type:
                description:
                - "unknown remote error type"
            krb5_server_init:
                description:
                - "krb5 server init"
            bad_rsa_decrypt:
                description:
                - "bad rsa decrypt"
            message_too_long:
                description:
                - "message too long"
            no_ciphers_available:
                description:
                - "no ciphers available"
            bad_ssl_session_id_length:
                description:
                - "bad ssl session id length"
            no_publickey:
                description:
                - "no publickey"
            excessive_message_size:
                description:
                - "excessive message size"
            unexpected_message:
                description:
                - "unexpected message"
            record_length_mismatch:
                description:
                - "record length mismatch"
            ssl_session_id_has_bad_length:
                description:
                - "ssl session id has bad length"
            bad_dh_p_length:
                description:
                - "bad dh p length"
            tlsv1_alert_user_cancelled:
                description:
                - "tlsv1 alert user cancelled"
            wrong_signature_length:
                description:
                - "wrong signature length"
            wrong_number_of_key_bits:
                description:
                - "wrong number of key bits"
            scsv_received_when_renegotiating:
                description:
                - "scsv received when renegotiating"
            unsupported_compression_algorithm:
                description:
                - "unsupported compression algorithm"
            bad_dh_pub_key_length:
                description:
                - "bad dh pub key length"
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
AVAILABLE_PROPERTIES = [
    "oper",
    "uuid",
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
        'oper': {
            'type': 'dict',
            'bad_data_returned_by_callback': {
                'type': 'int',
            },
            'bad_signature': {
                'type': 'int',
            },
            'block_cipher_pad_is_wrong': {
                'type': 'int',
            },
            'bad_protocol_version_number': {
                'type': 'int',
            },
            'null_ssl_method_passed': {
                'type': 'int',
            },
            'tls_client_cert_req_with_anon_cipher': {
                'type': 'int',
            },
            'no_certificates_returned': {
                'type': 'int',
            },
            'tlsv1_alert_insufficient_security': {
                'type': 'int',
            },
            'sslv3_alert_no_certificate': {
                'type': 'int',
            },
            'no_private_key_assigned': {
                'type': 'int',
            },
            'certificate_verify_failed': {
                'type': 'int',
            },
            'krb5_server_tkt_skew': {
                'type': 'int',
            },
            'bad_ssl_filetype': {
                'type': 'int',
            },
            'ca_dn_length_mismatch': {
                'type': 'int',
            },
            'bad_alert_record': {
                'type': 'int',
            },
            'connection_type_not_set': {
                'type': 'int',
            },
            'dh_public_value_length_is_wrong': {
                'type': 'int',
            },
            'bio_not_set': {
                'type': 'int',
            },
            'got_a_fin_before_a_ccs': {
                'type': 'int',
            },
            'sslv3_alert_decompression_failure': {
                'type': 'int',
            },
            'unable_to_load_ssl2_md5_routines': {
                'type': 'int',
            },
            'ssl_ctx_has_no_default_ssl_version': {
                'type': 'int',
            },
            'krb5_client_mk_req': {
                'type': 'int',
            },
            'uninitialized': {
                'type': 'int',
            },
            'wrong_cipher_returned': {
                'type': 'int',
            },
            'missing_dh_rsa_cert': {
                'type': 'int',
            },
            'attempt_to_reuse_sess_in_diff_context': {
                'type': 'int',
            },
            'tls_invalid_ecpointformat_list': {
                'type': 'int',
            },
            'null_ssl_ctx': {
                'type': 'int',
            },
            'bad_decompression': {
                'type': 'int',
            },
            'unknown_certificate_type': {
                'type': 'int',
            },
            'bad_response_argument': {
                'type': 'int',
            },
            'unknown_pkey_type': {
                'type': 'int',
            },
            'bad_message_type': {
                'type': 'int',
            },
            'sslv3_alert_bad_record_mac': {
                'type': 'int',
            },
            'compression_failure': {
                'type': 'int',
            },
            'krb5_server_tkt_not_yet_valid': {
                'type': 'int',
            },
            'no_certificate_specified': {
                'type': 'int',
            },
            'bad_hello_request': {
                'type': 'int',
            },
            'read_wrong_packet_type': {
                'type': 'int',
            },
            'missing_tmp_dh_key': {
                'type': 'int',
            },
            'peer_did_not_return_a_certificate': {
                'type': 'int',
            },
            'missing_tmp_rsa_key': {
                'type': 'int',
            },
            'invalid_challenge_length': {
                'type': 'int',
            },
            'old_session_cipher_not_returned': {
                'type': 'int',
            },
            'extra_data_in_message': {
                'type': 'int',
            },
            'missing_dsa_signing_cert': {
                'type': 'int',
            },
            'packet_length_too_long': {
                'type': 'int',
            },
            'tls_peer_did_not_respond_with_cert_list': {
                'type': 'int',
            },
            'ssl_session_id_conflict': {
                'type': 'int',
            },
            'unsupported_cipher': {
                'type': 'int',
            },
            'no_protocols_available': {
                'type': 'int',
            },
            'bad_change_cipher_spec': {
                'type': 'int',
            },
            'no_compression_specified': {
                'type': 'int',
            },
            'bad_digest_length': {
                'type': 'int',
            },
            'https_proxy_request': {
                'type': 'int',
            },
            'no_required_digest': {
                'type': 'int',
            },
            'bad_dh_g_length': {
                'type': 'int',
            },
            'length_mismatch': {
                'type': 'int',
            },
            'tlsv1_alert_unknown_ca': {
                'type': 'int',
            },
            'tlsv1_alert_no_renegotiation': {
                'type': 'int',
            },
            'sslv3_alert_unexpected_msg': {
                'type': 'int',
            },
            'missing_rsa_encrypting_cert': {
                'type': 'int',
            },
            'decryption_failed_or_bad_record_mac': {
                'type': 'int',
            },
            'cipher_or_hash_unavailable': {
                'type': 'int',
            },
            'wrong_signature_size': {
                'type': 'int',
            },
            'unable_to_decode_dh_certs': {
                'type': 'int',
            },
            'data_length_too_long': {
                'type': 'int',
            },
            'unsupported_ssl_version': {
                'type': 'int',
            },
            'invalid_command': {
                'type': 'int',
            },
            'wrong_ssl_version': {
                'type': 'int',
            },
            'cert_length_mismatch': {
                'type': 'int',
            },
            'unable_to_find_public_key_parameters': {
                'type': 'int',
            },
            'data_between_ccs_and_finished': {
                'type': 'int',
            },
            'ssl_library_has_no_ciphers': {
                'type': 'int',
            },
            'sslv3_alert_certificate_unknown': {
                'type': 'int',
            },
            'protocol_is_shutdown': {
                'type': 'int',
            },
            'no_ciphers_passed': {
                'type': 'int',
            },
            'no_certificate_returned': {
                'type': 'int',
            },
            'invalid_purpose': {
                'type': 'int',
            },
            'bad_write_retry': {
                'type': 'int',
            },
            'no_certificate_assigned': {
                'type': 'int',
            },
            'serverhello_tlsext': {
                'type': 'int',
            },
            'pre_mac_length_too_long': {
                'type': 'int',
            },
            'non_sslv2_initial_packet': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_no_cert': {
                'type': 'int',
            },
            'ssl3_session_id_too_long': {
                'type': 'int',
            },
            'parse_tlsext': {
                'type': 'int',
            },
            'bad_handshake_length': {
                'type': 'int',
            },
            'connection_id_is_different': {
                'type': 'int',
            },
            'unknown_alert_type': {
                'type': 'int',
            },
            'record_too_small': {
                'type': 'int',
            },
            'public_key_not_rsa': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_cert': {
                'type': 'int',
            },
            'unable_to_load_ssl3_sha1_routines': {
                'type': 'int',
            },
            'sslv3_alert_handshake_failure': {
                'type': 'int',
            },
            'short_read': {
                'type': 'int',
            },
            'krb5_server_bad_ticket': {
                'type': 'int',
            },
            'challenge_is_different': {
                'type': 'int',
            },
            'tlsv1_alert_decode_error': {
                'type': 'int',
            },
            'compressed_length_too_long': {
                'type': 'int',
            },
            'missing_rsa_certificate': {
                'type': 'int',
            },
            'ca_dn_too_long': {
                'type': 'int',
            },
            'required_cipher_missing': {
                'type': 'int',
            },
            'bad_ecc_cert': {
                'type': 'int',
            },
            'krb5_server_rd_req': {
                'type': 'int',
            },
            'bad_mac_decode': {
                'type': 'int',
            },
            'no_verify_callback': {
                'type': 'int',
            },
            'ssl3_ext_invalid_servername_type': {
                'type': 'int',
            },
            'unexpected_record': {
                'type': 'int',
            },
            'public_key_is_not_rsa': {
                'type': 'int',
            },
            'sslv3_alert_certificate_expired': {
                'type': 'int',
            },
            'length_too_short': {
                'type': 'int',
            },
            'peer_error_no_cipher': {
                'type': 'int',
            },
            'no_shared_cipher': {
                'type': 'int',
            },
            'missing_tmp_rsa_pkey': {
                'type': 'int',
            },
            'unknown_cipher_type': {
                'type': 'int',
            },
            'tlsv1_alert_decrypt_error': {
                'type': 'int',
            },
            'unknown_state': {
                'type': 'int',
            },
            'bad_dsa_signature': {
                'type': 'int',
            },
            'ssl3_session_id_too_short': {
                'type': 'int',
            },
            'no_cipher_match': {
                'type': 'int',
            },
            'missing_dh_key': {
                'type': 'int',
            },
            'ssl_handshake_failure': {
                'type': 'int',
            },
            'inappropriate_fallback': {
                'type': 'int',
            },
            'bad_checksum': {
                'type': 'int',
            },
            'unknown_cipher_returned': {
                'type': 'int',
            },
            'no_client_cert_received': {
                'type': 'int',
            },
            'encrypted_length_too_long': {
                'type': 'int',
            },
            'tlsv1_alert_internal_error': {
                'type': 'int',
            },
            'peer_error_no_certificate': {
                'type': 'int',
            },
            'multiple_sgc_restarts': {
                'type': 'int',
            },
            'no_ciphers_specified': {
                'type': 'int',
            },
            'ssl_session_id_callback_failed': {
                'type': 'int',
            },
            'no_method_specified': {
                'type': 'int',
            },
            'ssl_session_id_is_different': {
                'type': 'int',
            },
            'missing_rsa_signing_cert': {
                'type': 'int',
            },
            'krb5_client_init': {
                'type': 'int',
            },
            'reuse_cert_type_not_zero': {
                'type': 'int',
            },
            'unable_to_find_dh_parameters': {
                'type': 'int',
            },
            'digest_check_failed': {
                'type': 'int',
            },
            'http_request': {
                'type': 'int',
            },
            'app_data_in_handshake': {
                'type': 'int',
            },
            'unsupported_protocol': {
                'type': 'int',
            },
            'no_cipher_list': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_unsupp_cert_type': {
                'type': 'int',
            },
            'bad_state': {
                'type': 'int',
            },
            'unable_to_extract_public_key': {
                'type': 'int',
            },
            'peer_error_unsupported_certificate_type': {
                'type': 'int',
            },
            'bad_ecdsa_sig': {
                'type': 'int',
            },
            'tls_rsa_encrypted_value_length_is_wrong': {
                'type': 'int',
            },
            'missing_export_tmp_rsa_key': {
                'type': 'int',
            },
            'peer_error': {
                'type': 'int',
            },
            'error_in_received_cipher_list': {
                'type': 'int',
            },
            'unable_to_load_ssl3_md5_routines': {
                'type': 'int',
            },
            'cipher_table_src_error': {
                'type': 'int',
            },
            'sslv3_alert_illegal_parameter': {
                'type': 'int',
            },
            'tlsv1_alert_protocol_version': {
                'type': 'int',
            },
            'problems_mapping_cipher_functions': {
                'type': 'int',
            },
            'unsupported_elliptic_curve': {
                'type': 'int',
            },
            'bn_lib': {
                'type': 'int',
            },
            'ccs_received_early': {
                'type': 'int',
            },
            'bad_rsa_encrypt': {
                'type': 'int',
            },
            'unsupported_status_type': {
                'type': 'int',
            },
            'bad_ecpoint': {
                'type': 'int',
            },
            'ssl2_connection_id_too_long': {
                'type': 'int',
            },
            'reuse_cipher_list_not_zero': {
                'type': 'int',
            },
            'krb5': {
                'type': 'int',
            },
            'tried_to_use_unsupported_cipher': {
                'type': 'int',
            },
            'krb5_client_cc_principal': {
                'type': 'int',
            },
            'missing_export_tmp_dh_key': {
                'type': 'int',
            },
            'krb5_client_get_cred': {
                'type': 'int',
            },
            'error_generating_tmp_rsa_key': {
                'type': 'int',
            },
            'missing_verify_message': {
                'type': 'int',
            },
            'wrong_version_number': {
                'type': 'int',
            },
            'krb5_server_tkt_expired': {
                'type': 'int',
            },
            'x509_lib': {
                'type': 'int',
            },
            'tlsv1_alert_access_denied': {
                'type': 'int',
            },
            'decryption_failed': {
                'type': 'int',
            },
            'tlsv1_alert_export_restriction': {
                'type': 'int',
            },
            'library_has_no_ciphers': {
                'type': 'int',
            },
            'sslv3_alert_certificate_revoked': {
                'type': 'int',
            },
            'unknown_protocol': {
                'type': 'int',
            },
            'bad_rsa_modulus_length': {
                'type': 'int',
            },
            'bad_authentication_type': {
                'type': 'int',
            },
            'path_too_long': {
                'type': 'int',
            },
            'missing_dh_dsa_cert': {
                'type': 'int',
            },
            'reuse_cert_length_not_zero': {
                'type': 'int',
            },
            'bad_length': {
                'type': 'int',
            },
            'peer_error_certificate': {
                'type': 'int',
            },
            'unsupported_option': {
                'type': 'int',
            },
            'unsupported_digest_type': {
                'type': 'int',
            },
            'ssl_session_id_context_too_long': {
                'type': 'int',
            },
            'no_certificate_set': {
                'type': 'int',
            },
            'sslv3_alert_bad_certificate': {
                'type': 'int',
            },
            'record_too_large': {
                'type': 'int',
            },
            'key_arg_too_long': {
                'type': 'int',
            },
            'illegal_padding': {
                'type': 'int',
            },
            'sslv3_alert_unspported_cert': {
                'type': 'int',
            },
            'cipher_code_wrong_length': {
                'type': 'int',
            },
            'no_privatekey': {
                'type': 'int',
            },
            'ssl3_ext_invalid_servername': {
                'type': 'int',
            },
            'library_bug': {
                'type': 'int',
            },
            'compression_library_error': {
                'type': 'int',
            },
            'write_bio_not_set': {
                'type': 'int',
            },
            'ssl23_doing_session_id_reuse': {
                'type': 'int',
            },
            'bad_rsa_signature': {
                'type': 'int',
            },
            'session_id_context_uninitialized': {
                'type': 'int',
            },
            'signature_for_non_signing_certificate': {
                'type': 'int',
            },
            'public_key_encrypt_error': {
                'type': 'int',
            },
            'x509_verification_setup_problems': {
                'type': 'int',
            },
            'unknown_ssl_version': {
                'type': 'int',
            },
            'mast_key_too_long': {
                'type': 'int',
            },
            'clienthello_tlsext': {
                'type': 'int',
            },
            'tlsv1_alert_decryption_failed': {
                'type': 'int',
            },
            'invalid_trust': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_no_cipher': {
                'type': 'int',
            },
            'unable_to_find_ssl_method': {
                'type': 'int',
            },
            'read_bio_not_set': {
                'type': 'int',
            },
            'bad_rsa_e_length': {
                'type': 'int',
            },
            'unknown_key_exchange_type': {
                'type': 'int',
            },
            'invalid_status_response': {
                'type': 'int',
            },
            'cookie_mismatch': {
                'type': 'int',
            },
            'tlsv1_alert_record_overflow': {
                'type': 'int',
            },
            'sslv3_alert_unknown_remote_err_type': {
                'type': 'int',
            },
            'bad_packet_length': {
                'type': 'int',
            },
            'wrong_message_type': {
                'type': 'int',
            },
            'unknown_remote_error_type': {
                'type': 'int',
            },
            'krb5_server_init': {
                'type': 'int',
            },
            'bad_rsa_decrypt': {
                'type': 'int',
            },
            'message_too_long': {
                'type': 'int',
            },
            'no_ciphers_available': {
                'type': 'int',
            },
            'bad_ssl_session_id_length': {
                'type': 'int',
            },
            'no_publickey': {
                'type': 'int',
            },
            'excessive_message_size': {
                'type': 'int',
            },
            'unexpected_message': {
                'type': 'int',
            },
            'record_length_mismatch': {
                'type': 'int',
            },
            'ssl_session_id_has_bad_length': {
                'type': 'int',
            },
            'bad_dh_p_length': {
                'type': 'int',
            },
            'tlsv1_alert_user_cancelled': {
                'type': 'int',
            },
            'wrong_signature_length': {
                'type': 'int',
            },
            'wrong_number_of_key_bits': {
                'type': 'int',
            },
            'scsv_received_when_renegotiating': {
                'type': 'int',
            },
            'unsupported_compression_algorithm': {
                'type': 'int',
            },
            'bad_dh_pub_key_length': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/ssl-error"

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
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
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
    url_base = "/axapi/v3/slb/ssl-error"

    f_dict = {}

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


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config):
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)


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
