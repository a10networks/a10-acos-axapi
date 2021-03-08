#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_ssl_error
description:
    - Error
author: A10 Networks 2021
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            app_data_in_handshake:
                description:
                - "app data in handshake"
                type: int
            attempt_to_reuse_sess_in_diff_context:
                description:
                - "attempt to reuse sess in diff context"
                type: int
            bad_alert_record:
                description:
                - "bad alert record"
                type: int
            bad_authentication_type:
                description:
                - "bad authentication type"
                type: int
            bad_change_cipher_spec:
                description:
                - "bad change cipher spec"
                type: int
            bad_checksum:
                description:
                - "bad checksum"
                type: int
            bad_data_returned_by_callback:
                description:
                - "bad data returned by callback"
                type: int
            bad_decompression:
                description:
                - "bad decompression"
                type: int
            bad_dh_g_length:
                description:
                - "bad dh g length"
                type: int
            bad_dh_pub_key_length:
                description:
                - "bad dh pub key length"
                type: int
            bad_dh_p_length:
                description:
                - "bad dh p length"
                type: int
            bad_digest_length:
                description:
                - "bad digest length"
                type: int
            bad_dsa_signature:
                description:
                - "bad dsa signature"
                type: int
            bad_hello_request:
                description:
                - "bad hello request"
                type: int
            bad_length:
                description:
                - "bad length"
                type: int
            bad_mac_decode:
                description:
                - "bad mac decode"
                type: int
            bad_message_type:
                description:
                - "bad message type"
                type: int
            bad_packet_length:
                description:
                - "bad packet length"
                type: int
            bad_protocol_version_number:
                description:
                - "bad protocol version number"
                type: int
            bad_response_argument:
                description:
                - "bad response argument"
                type: int
            bad_rsa_decrypt:
                description:
                - "bad rsa decrypt"
                type: int
            bad_rsa_encrypt:
                description:
                - "bad rsa encrypt"
                type: int
            bad_rsa_e_length:
                description:
                - "bad rsa e length"
                type: int
            bad_rsa_modulus_length:
                description:
                - "bad rsa modulus length"
                type: int
            bad_rsa_signature:
                description:
                - "bad rsa signature"
                type: int
            bad_signature:
                description:
                - "bad signature"
                type: int
            bad_ssl_filetype:
                description:
                - "bad ssl filetype"
                type: int
            bad_ssl_session_id_length:
                description:
                - "bad ssl session id length"
                type: int
            bad_state:
                description:
                - "bad state"
                type: int
            bad_write_retry:
                description:
                - "bad write retry"
                type: int
            bio_not_set:
                description:
                - "bio not set"
                type: int
            block_cipher_pad_is_wrong:
                description:
                - "block cipher pad is wrong"
                type: int
            bn_lib:
                description:
                - "bn lib"
                type: int
            ca_dn_length_mismatch:
                description:
                - "ca dn length mismatch"
                type: int
            ca_dn_too_long:
                description:
                - "ca dn too long"
                type: int
            ccs_received_early:
                description:
                - "ccs received early"
                type: int
            certificate_verify_failed:
                description:
                - "certificate verify failed"
                type: int
            cert_length_mismatch:
                description:
                - "cert length mismatch"
                type: int
            challenge_is_different:
                description:
                - "challenge is different"
                type: int
            cipher_code_wrong_length:
                description:
                - "cipher code wrong length"
                type: int
            cipher_or_hash_unavailable:
                description:
                - "cipher or hash unavailable"
                type: int
            cipher_table_src_error:
                description:
                - "cipher table src error"
                type: int
            compressed_length_too_long:
                description:
                - "compressed length too long"
                type: int
            compression_failure:
                description:
                - "compression failure"
                type: int
            compression_library_error:
                description:
                - "compression library error"
                type: int
            connection_id_is_different:
                description:
                - "connection id is different"
                type: int
            connection_type_not_set:
                description:
                - "connection type not set"
                type: int
            data_between_ccs_and_finished:
                description:
                - "data between ccs and finished"
                type: int
            data_length_too_long:
                description:
                - "data length too long"
                type: int
            decryption_failed:
                description:
                - "decryption failed"
                type: int
            decryption_failed_or_bad_record_mac:
                description:
                - "decryption failed or bad record mac"
                type: int
            dh_public_value_length_is_wrong:
                description:
                - "dh public value length is wrong"
                type: int
            digest_check_failed:
                description:
                - "digest check failed"
                type: int
            encrypted_length_too_long:
                description:
                - "encrypted length too long"
                type: int
            error_generating_tmp_rsa_key:
                description:
                - "error generating tmp rsa key"
                type: int
            error_in_received_cipher_list:
                description:
                - "error in received cipher list"
                type: int
            excessive_message_size:
                description:
                - "excessive message size"
                type: int
            extra_data_in_message:
                description:
                - "extra data in message"
                type: int
            got_a_fin_before_a_ccs:
                description:
                - "got a fin before a ccs"
                type: int
            https_proxy_request:
                description:
                - "https proxy request"
                type: int
            http_request:
                description:
                - "http request"
                type: int
            illegal_padding:
                description:
                - "illegal padding"
                type: int
            inappropriate_fallback:
                description:
                - "inappropriate fallback"
                type: int
            invalid_challenge_length:
                description:
                - "invalid challenge length"
                type: int
            invalid_command:
                description:
                - "invalid command"
                type: int
            invalid_purpose:
                description:
                - "invalid purpose"
                type: int
            invalid_status_response:
                description:
                - "invalid status response"
                type: int
            invalid_trust:
                description:
                - "invalid trust"
                type: int
            key_arg_too_long:
                description:
                - "key arg too long"
                type: int
            krb5:
                description:
                - "krb5"
                type: int
            krb5_client_cc_principal:
                description:
                - "krb5 client cc principal"
                type: int
            krb5_client_get_cred:
                description:
                - "krb5 client get cred"
                type: int
            krb5_client_init:
                description:
                - "krb5 client init"
                type: int
            krb5_client_mk_req:
                description:
                - "krb5 client mk_req"
                type: int
            krb5_server_bad_ticket:
                description:
                - "krb5 server bad ticket"
                type: int
            krb5_server_init:
                description:
                - "krb5 server init"
                type: int
            krb5_server_rd_req:
                description:
                - "krb5 server rd_req"
                type: int
            krb5_server_tkt_expired:
                description:
                - "krb5 server tkt expired"
                type: int
            krb5_server_tkt_not_yet_valid:
                description:
                - "krb5 server tkt not yet valid"
                type: int
            krb5_server_tkt_skew:
                description:
                - "krb5 server tkt skew"
                type: int
            length_mismatch:
                description:
                - "length mismatch"
                type: int
            length_too_short:
                description:
                - "length too short"
                type: int
            library_bug:
                description:
                - "library bug"
                type: int
            library_has_no_ciphers:
                description:
                - "library has no ciphers"
                type: int
            mast_key_too_long:
                description:
                - "mast key too long"
                type: int
            message_too_long:
                description:
                - "message too long"
                type: int
            missing_dh_dsa_cert:
                description:
                - "missing dh dsa cert"
                type: int
            missing_dh_key:
                description:
                - "missing dh key"
                type: int
            missing_dh_rsa_cert:
                description:
                - "missing dh rsa cert"
                type: int
            missing_dsa_signing_cert:
                description:
                - "missing dsa signing cert"
                type: int
            missing_export_tmp_dh_key:
                description:
                - "missing export tmp dh key"
                type: int
            missing_export_tmp_rsa_key:
                description:
                - "missing export tmp rsa key"
                type: int
            missing_rsa_certificate:
                description:
                - "missing rsa certificate"
                type: int
            missing_rsa_encrypting_cert:
                description:
                - "missing rsa encrypting cert"
                type: int
            missing_rsa_signing_cert:
                description:
                - "missing rsa signing cert"
                type: int
            missing_tmp_dh_key:
                description:
                - "missing tmp dh key"
                type: int
            missing_tmp_rsa_key:
                description:
                - "missing tmp rsa key"
                type: int
            missing_tmp_rsa_pkey:
                description:
                - "missing tmp rsa pkey"
                type: int
            missing_verify_message:
                description:
                - "missing verify message"
                type: int
            non_sslv2_initial_packet:
                description:
                - "non sslv2 initial packet"
                type: int
            no_certificates_returned:
                description:
                - "no certificates returned"
                type: int
            no_certificate_assigned:
                description:
                - "no certificate assigned"
                type: int
            no_certificate_returned:
                description:
                - "no certificate returned"
                type: int
            no_certificate_set:
                description:
                - "no certificate set"
                type: int
            no_certificate_specified:
                description:
                - "no certificate specified"
                type: int
            no_ciphers_available:
                description:
                - "no ciphers available"
                type: int
            no_ciphers_passed:
                description:
                - "no ciphers passed"
                type: int
            no_ciphers_specified:
                description:
                - "no ciphers specified"
                type: int
            no_cipher_list:
                description:
                - "no cipher list"
                type: int
            no_cipher_match:
                description:
                - "no cipher match"
                type: int
            no_client_cert_received:
                description:
                - "no client cert received"
                type: int
            no_compression_specified:
                description:
                - "no compression specified"
                type: int
            no_method_specified:
                description:
                - "no method specified"
                type: int
            no_privatekey:
                description:
                - "no privatekey"
                type: int
            no_private_key_assigned:
                description:
                - "no private key assigned"
                type: int
            no_protocols_available:
                description:
                - "no protocols available"
                type: int
            no_publickey:
                description:
                - "no publickey"
                type: int
            no_shared_cipher:
                description:
                - "no shared cipher"
                type: int
            no_verify_callback:
                description:
                - "no verify callback"
                type: int
            null_ssl_ctx:
                description:
                - "null ssl ctx"
                type: int
            null_ssl_method_passed:
                description:
                - "null ssl method passed"
                type: int
            old_session_cipher_not_returned:
                description:
                - "old session cipher not returned"
                type: int
            packet_length_too_long:
                description:
                - "packet length too long"
                type: int
            path_too_long:
                description:
                - "path too long"
                type: int
            peer_did_not_return_a_certificate:
                description:
                - "peer did not return a certificate"
                type: int
            peer_error:
                description:
                - "peer error"
                type: int
            peer_error_certificate:
                description:
                - "peer error certificate"
                type: int
            peer_error_no_certificate:
                description:
                - "peer error no certificate"
                type: int
            peer_error_no_cipher:
                description:
                - "peer error no cipher"
                type: int
            peer_error_unsupported_certificate_type:
                description:
                - "peer error unsupported certificate type"
                type: int
            pre_mac_length_too_long:
                description:
                - "pre mac length too long"
                type: int
            problems_mapping_cipher_functions:
                description:
                - "problems mapping cipher functions"
                type: int
            protocol_is_shutdown:
                description:
                - "protocol is shutdown"
                type: int
            public_key_encrypt_error:
                description:
                - "public key encrypt error"
                type: int
            public_key_is_not_rsa:
                description:
                - "public key is not rsa"
                type: int
            public_key_not_rsa:
                description:
                - "public key not rsa"
                type: int
            read_bio_not_set:
                description:
                - "read bio not set"
                type: int
            read_wrong_packet_type:
                description:
                - "read wrong packet type"
                type: int
            record_length_mismatch:
                description:
                - "record length mismatch"
                type: int
            record_too_large:
                description:
                - "record too large"
                type: int
            record_too_small:
                description:
                - "record too small"
                type: int
            required_cipher_missing:
                description:
                - "required cipher missing"
                type: int
            reuse_cert_length_not_zero:
                description:
                - "reuse cert length not zero"
                type: int
            reuse_cert_type_not_zero:
                description:
                - "reuse cert type not zero"
                type: int
            reuse_cipher_list_not_zero:
                description:
                - "reuse cipher list not zero"
                type: int
            scsv_received_when_renegotiating:
                description:
                - "scsv received when renegotiating"
                type: int
            session_id_context_uninitialized:
                description:
                - "session id context uninitialized"
                type: int
            short_read:
                description:
                - "short read"
                type: int
            signature_for_non_signing_certificate:
                description:
                - "signature for non signing certificate"
                type: int
            ssl23_doing_session_id_reuse:
                description:
                - "ssl23 doing session id reuse"
                type: int
            ssl2_connection_id_too_long:
                description:
                - "ssl2 connection id too long"
                type: int
            ssl3_session_id_too_long:
                description:
                - "ssl3 session id too long"
                type: int
            ssl3_session_id_too_short:
                description:
                - "ssl3 session id too short"
                type: int
            sslv3_alert_bad_certificate:
                description:
                - "sslv3 alert bad certificate"
                type: int
            sslv3_alert_bad_record_mac:
                description:
                - "sslv3 alert bad record mac"
                type: int
            sslv3_alert_certificate_expired:
                description:
                - "sslv3 alert certificate expired"
                type: int
            sslv3_alert_certificate_revoked:
                description:
                - "sslv3 alert certificate revoked"
                type: int
            sslv3_alert_certificate_unknown:
                description:
                - "sslv3 alert certificate unknown"
                type: int
            sslv3_alert_decompression_failure:
                description:
                - "sslv3 alert decompression failure"
                type: int
            sslv3_alert_handshake_failure:
                description:
                - "sslv3 alert handshake failure"
                type: int
            sslv3_alert_illegal_parameter:
                description:
                - "sslv3 alert illegal parameter"
                type: int
            sslv3_alert_no_certificate:
                description:
                - "sslv3 alert no certificate"
                type: int
            sslv3_alert_peer_error_cert:
                description:
                - "sslv3 alert peer error cert"
                type: int
            sslv3_alert_peer_error_no_cert:
                description:
                - "sslv3 alert peer error no cert"
                type: int
            sslv3_alert_peer_error_no_cipher:
                description:
                - "sslv3 alert peer error no cipher"
                type: int
            sslv3_alert_peer_error_unsupp_cert_type:
                description:
                - "sslv3 alert peer error unsupp cert type"
                type: int
            sslv3_alert_unexpected_msg:
                description:
                - "sslv3 alert unexpected msg"
                type: int
            sslv3_alert_unknown_remote_err_type:
                description:
                - "sslv3 alert unknown remote err type"
                type: int
            sslv3_alert_unspported_cert:
                description:
                - "sslv3 alert unspported cert"
                type: int
            ssl_ctx_has_no_default_ssl_version:
                description:
                - "ssl ctx has no default ssl version"
                type: int
            ssl_handshake_failure:
                description:
                - "ssl handshake failure"
                type: int
            ssl_library_has_no_ciphers:
                description:
                - "ssl library has no ciphers"
                type: int
            ssl_session_id_callback_failed:
                description:
                - "ssl session id callback failed"
                type: int
            ssl_session_id_conflict:
                description:
                - "ssl session id conflict"
                type: int
            ssl_session_id_context_too_long:
                description:
                - "ssl session id context too long"
                type: int
            ssl_session_id_has_bad_length:
                description:
                - "ssl session id has bad length"
                type: int
            ssl_session_id_is_different:
                description:
                - "ssl session id is different"
                type: int
            tlsv1_alert_access_denied:
                description:
                - "tlsv1 alert access denied"
                type: int
            tlsv1_alert_decode_error:
                description:
                - "tlsv1 alert decode error"
                type: int
            tlsv1_alert_decryption_failed:
                description:
                - "tlsv1 alert decryption failed"
                type: int
            tlsv1_alert_decrypt_error:
                description:
                - "tlsv1 alert decrypt error"
                type: int
            tlsv1_alert_export_restriction:
                description:
                - "tlsv1 alert export restriction"
                type: int
            tlsv1_alert_insufficient_security:
                description:
                - "tlsv1 alert insufficient security"
                type: int
            tlsv1_alert_internal_error:
                description:
                - "tlsv1 alert internal error"
                type: int
            tlsv1_alert_no_renegotiation:
                description:
                - "tlsv1 alert no renegotiation"
                type: int
            tlsv1_alert_protocol_version:
                description:
                - "tlsv1 alert protocol version"
                type: int
            tlsv1_alert_record_overflow:
                description:
                - "tlsv1 alert record overflow"
                type: int
            tlsv1_alert_unknown_ca:
                description:
                - "tlsv1 alert unknown ca"
                type: int
            tlsv1_alert_user_cancelled:
                description:
                - "tlsv1 alert user cancelled"
                type: int
            tls_client_cert_req_with_anon_cipher:
                description:
                - "tls client cert req with anon cipher"
                type: int
            tls_peer_did_not_respond_with_cert_list:
                description:
                - "tls peer did not respond with cert list"
                type: int
            tls_rsa_encrypted_value_length_is_wrong:
                description:
                - "tls rsa encrypted value length is wrong"
                type: int
            tried_to_use_unsupported_cipher:
                description:
                - "tried to use unsupported cipher"
                type: int
            unable_to_decode_dh_certs:
                description:
                - "unable to decode dh certs"
                type: int
            unable_to_extract_public_key:
                description:
                - "unable to extract public key"
                type: int
            unable_to_find_dh_parameters:
                description:
                - "unable to find dh parameters"
                type: int
            unable_to_find_public_key_parameters:
                description:
                - "unable to find public key parameters"
                type: int
            unable_to_find_ssl_method:
                description:
                - "unable to find ssl method"
                type: int
            unable_to_load_ssl2_md5_routines:
                description:
                - "unable to load ssl2 md5 routines"
                type: int
            unable_to_load_ssl3_md5_routines:
                description:
                - "unable to load ssl3 md5 routines"
                type: int
            unable_to_load_ssl3_sha1_routines:
                description:
                - "unable to load ssl3 sha1 routines"
                type: int
            unexpected_message:
                description:
                - "unexpected message"
                type: int
            unexpected_record:
                description:
                - "unexpected record"
                type: int
            uninitialized:
                description:
                - "uninitialized"
                type: int
            unknown_alert_type:
                description:
                - "unknown alert type"
                type: int
            unknown_certificate_type:
                description:
                - "unknown certificate type"
                type: int
            unknown_cipher_returned:
                description:
                - "unknown cipher returned"
                type: int
            unknown_cipher_type:
                description:
                - "unknown cipher type"
                type: int
            unknown_key_exchange_type:
                description:
                - "unknown key exchange type"
                type: int
            unknown_pkey_type:
                description:
                - "unknown pkey type"
                type: int
            unknown_protocol:
                description:
                - "unknown protocol"
                type: int
            unknown_remote_error_type:
                description:
                - "unknown remote error type"
                type: int
            unknown_ssl_version:
                description:
                - "unknown ssl version"
                type: int
            unknown_state:
                description:
                - "unknown state"
                type: int
            unsupported_cipher:
                description:
                - "unsupported cipher"
                type: int
            unsupported_compression_algorithm:
                description:
                - "unsupported compression algorithm"
                type: int
            unsupported_option:
                description:
                - "unsupported option"
                type: int
            unsupported_protocol:
                description:
                - "unsupported protocol"
                type: int
            unsupported_ssl_version:
                description:
                - "unsupported ssl version"
                type: int
            unsupported_status_type:
                description:
                - "unsupported status type"
                type: int
            write_bio_not_set:
                description:
                - "write bio not set"
                type: int
            wrong_cipher_returned:
                description:
                - "wrong cipher returned"
                type: int
            wrong_message_type:
                description:
                - "wrong message type"
                type: int
            wrong_number_of_key_bits:
                description:
                - "wrong number of key bits"
                type: int
            wrong_signature_length:
                description:
                - "wrong signature length"
                type: int
            wrong_signature_size:
                description:
                - "wrong signature size"
                type: int
            wrong_ssl_version:
                description:
                - "wrong ssl version"
                type: int
            wrong_version_number:
                description:
                - "wrong version number"
                type: int
            x509_lib:
                description:
                - "x509 lib"
                type: int
            x509_verification_setup_problems:
                description:
                - "x509 verification setup problems"
                type: int
            clienthello_tlsext:
                description:
                - "clienthello tlsext"
                type: int
            parse_tlsext:
                description:
                - "parse tlsext"
                type: int
            serverhello_tlsext:
                description:
                - "serverhello tlsext"
                type: int
            ssl3_ext_invalid_servername:
                description:
                - "ssl3 ext invalid servername"
                type: int
            ssl3_ext_invalid_servername_type:
                description:
                - "ssl3 ext invalid servername type"
                type: int
            multiple_sgc_restarts:
                description:
                - "multiple sgc restarts"
                type: int
            tls_invalid_ecpointformat_list:
                description:
                - "tls invalid ecpointformat list"
                type: int
            bad_ecc_cert:
                description:
                - "bad ecc cert"
                type: int
            bad_ecdsa_sig:
                description:
                - "bad ecdsa sig"
                type: int
            bad_ecpoint:
                description:
                - "bad ecpoint"
                type: int
            cookie_mismatch:
                description:
                - "cookie mismatch"
                type: int
            unsupported_elliptic_curve:
                description:
                - "unsupported elliptic curve"
                type: int
            no_required_digest:
                description:
                - "no required digest"
                type: int
            unsupported_digest_type:
                description:
                - "unsupported digest type"
                type: int
            bad_handshake_length:
                description:
                - "bad handshake length"
                type: int

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
        'uuid': {
            'type': 'str',
        },
        'oper': {
            'type': 'dict',
            'app_data_in_handshake': {
                'type': 'int',
            },
            'attempt_to_reuse_sess_in_diff_context': {
                'type': 'int',
            },
            'bad_alert_record': {
                'type': 'int',
            },
            'bad_authentication_type': {
                'type': 'int',
            },
            'bad_change_cipher_spec': {
                'type': 'int',
            },
            'bad_checksum': {
                'type': 'int',
            },
            'bad_data_returned_by_callback': {
                'type': 'int',
            },
            'bad_decompression': {
                'type': 'int',
            },
            'bad_dh_g_length': {
                'type': 'int',
            },
            'bad_dh_pub_key_length': {
                'type': 'int',
            },
            'bad_dh_p_length': {
                'type': 'int',
            },
            'bad_digest_length': {
                'type': 'int',
            },
            'bad_dsa_signature': {
                'type': 'int',
            },
            'bad_hello_request': {
                'type': 'int',
            },
            'bad_length': {
                'type': 'int',
            },
            'bad_mac_decode': {
                'type': 'int',
            },
            'bad_message_type': {
                'type': 'int',
            },
            'bad_packet_length': {
                'type': 'int',
            },
            'bad_protocol_version_number': {
                'type': 'int',
            },
            'bad_response_argument': {
                'type': 'int',
            },
            'bad_rsa_decrypt': {
                'type': 'int',
            },
            'bad_rsa_encrypt': {
                'type': 'int',
            },
            'bad_rsa_e_length': {
                'type': 'int',
            },
            'bad_rsa_modulus_length': {
                'type': 'int',
            },
            'bad_rsa_signature': {
                'type': 'int',
            },
            'bad_signature': {
                'type': 'int',
            },
            'bad_ssl_filetype': {
                'type': 'int',
            },
            'bad_ssl_session_id_length': {
                'type': 'int',
            },
            'bad_state': {
                'type': 'int',
            },
            'bad_write_retry': {
                'type': 'int',
            },
            'bio_not_set': {
                'type': 'int',
            },
            'block_cipher_pad_is_wrong': {
                'type': 'int',
            },
            'bn_lib': {
                'type': 'int',
            },
            'ca_dn_length_mismatch': {
                'type': 'int',
            },
            'ca_dn_too_long': {
                'type': 'int',
            },
            'ccs_received_early': {
                'type': 'int',
            },
            'certificate_verify_failed': {
                'type': 'int',
            },
            'cert_length_mismatch': {
                'type': 'int',
            },
            'challenge_is_different': {
                'type': 'int',
            },
            'cipher_code_wrong_length': {
                'type': 'int',
            },
            'cipher_or_hash_unavailable': {
                'type': 'int',
            },
            'cipher_table_src_error': {
                'type': 'int',
            },
            'compressed_length_too_long': {
                'type': 'int',
            },
            'compression_failure': {
                'type': 'int',
            },
            'compression_library_error': {
                'type': 'int',
            },
            'connection_id_is_different': {
                'type': 'int',
            },
            'connection_type_not_set': {
                'type': 'int',
            },
            'data_between_ccs_and_finished': {
                'type': 'int',
            },
            'data_length_too_long': {
                'type': 'int',
            },
            'decryption_failed': {
                'type': 'int',
            },
            'decryption_failed_or_bad_record_mac': {
                'type': 'int',
            },
            'dh_public_value_length_is_wrong': {
                'type': 'int',
            },
            'digest_check_failed': {
                'type': 'int',
            },
            'encrypted_length_too_long': {
                'type': 'int',
            },
            'error_generating_tmp_rsa_key': {
                'type': 'int',
            },
            'error_in_received_cipher_list': {
                'type': 'int',
            },
            'excessive_message_size': {
                'type': 'int',
            },
            'extra_data_in_message': {
                'type': 'int',
            },
            'got_a_fin_before_a_ccs': {
                'type': 'int',
            },
            'https_proxy_request': {
                'type': 'int',
            },
            'http_request': {
                'type': 'int',
            },
            'illegal_padding': {
                'type': 'int',
            },
            'inappropriate_fallback': {
                'type': 'int',
            },
            'invalid_challenge_length': {
                'type': 'int',
            },
            'invalid_command': {
                'type': 'int',
            },
            'invalid_purpose': {
                'type': 'int',
            },
            'invalid_status_response': {
                'type': 'int',
            },
            'invalid_trust': {
                'type': 'int',
            },
            'key_arg_too_long': {
                'type': 'int',
            },
            'krb5': {
                'type': 'int',
            },
            'krb5_client_cc_principal': {
                'type': 'int',
            },
            'krb5_client_get_cred': {
                'type': 'int',
            },
            'krb5_client_init': {
                'type': 'int',
            },
            'krb5_client_mk_req': {
                'type': 'int',
            },
            'krb5_server_bad_ticket': {
                'type': 'int',
            },
            'krb5_server_init': {
                'type': 'int',
            },
            'krb5_server_rd_req': {
                'type': 'int',
            },
            'krb5_server_tkt_expired': {
                'type': 'int',
            },
            'krb5_server_tkt_not_yet_valid': {
                'type': 'int',
            },
            'krb5_server_tkt_skew': {
                'type': 'int',
            },
            'length_mismatch': {
                'type': 'int',
            },
            'length_too_short': {
                'type': 'int',
            },
            'library_bug': {
                'type': 'int',
            },
            'library_has_no_ciphers': {
                'type': 'int',
            },
            'mast_key_too_long': {
                'type': 'int',
            },
            'message_too_long': {
                'type': 'int',
            },
            'missing_dh_dsa_cert': {
                'type': 'int',
            },
            'missing_dh_key': {
                'type': 'int',
            },
            'missing_dh_rsa_cert': {
                'type': 'int',
            },
            'missing_dsa_signing_cert': {
                'type': 'int',
            },
            'missing_export_tmp_dh_key': {
                'type': 'int',
            },
            'missing_export_tmp_rsa_key': {
                'type': 'int',
            },
            'missing_rsa_certificate': {
                'type': 'int',
            },
            'missing_rsa_encrypting_cert': {
                'type': 'int',
            },
            'missing_rsa_signing_cert': {
                'type': 'int',
            },
            'missing_tmp_dh_key': {
                'type': 'int',
            },
            'missing_tmp_rsa_key': {
                'type': 'int',
            },
            'missing_tmp_rsa_pkey': {
                'type': 'int',
            },
            'missing_verify_message': {
                'type': 'int',
            },
            'non_sslv2_initial_packet': {
                'type': 'int',
            },
            'no_certificates_returned': {
                'type': 'int',
            },
            'no_certificate_assigned': {
                'type': 'int',
            },
            'no_certificate_returned': {
                'type': 'int',
            },
            'no_certificate_set': {
                'type': 'int',
            },
            'no_certificate_specified': {
                'type': 'int',
            },
            'no_ciphers_available': {
                'type': 'int',
            },
            'no_ciphers_passed': {
                'type': 'int',
            },
            'no_ciphers_specified': {
                'type': 'int',
            },
            'no_cipher_list': {
                'type': 'int',
            },
            'no_cipher_match': {
                'type': 'int',
            },
            'no_client_cert_received': {
                'type': 'int',
            },
            'no_compression_specified': {
                'type': 'int',
            },
            'no_method_specified': {
                'type': 'int',
            },
            'no_privatekey': {
                'type': 'int',
            },
            'no_private_key_assigned': {
                'type': 'int',
            },
            'no_protocols_available': {
                'type': 'int',
            },
            'no_publickey': {
                'type': 'int',
            },
            'no_shared_cipher': {
                'type': 'int',
            },
            'no_verify_callback': {
                'type': 'int',
            },
            'null_ssl_ctx': {
                'type': 'int',
            },
            'null_ssl_method_passed': {
                'type': 'int',
            },
            'old_session_cipher_not_returned': {
                'type': 'int',
            },
            'packet_length_too_long': {
                'type': 'int',
            },
            'path_too_long': {
                'type': 'int',
            },
            'peer_did_not_return_a_certificate': {
                'type': 'int',
            },
            'peer_error': {
                'type': 'int',
            },
            'peer_error_certificate': {
                'type': 'int',
            },
            'peer_error_no_certificate': {
                'type': 'int',
            },
            'peer_error_no_cipher': {
                'type': 'int',
            },
            'peer_error_unsupported_certificate_type': {
                'type': 'int',
            },
            'pre_mac_length_too_long': {
                'type': 'int',
            },
            'problems_mapping_cipher_functions': {
                'type': 'int',
            },
            'protocol_is_shutdown': {
                'type': 'int',
            },
            'public_key_encrypt_error': {
                'type': 'int',
            },
            'public_key_is_not_rsa': {
                'type': 'int',
            },
            'public_key_not_rsa': {
                'type': 'int',
            },
            'read_bio_not_set': {
                'type': 'int',
            },
            'read_wrong_packet_type': {
                'type': 'int',
            },
            'record_length_mismatch': {
                'type': 'int',
            },
            'record_too_large': {
                'type': 'int',
            },
            'record_too_small': {
                'type': 'int',
            },
            'required_cipher_missing': {
                'type': 'int',
            },
            'reuse_cert_length_not_zero': {
                'type': 'int',
            },
            'reuse_cert_type_not_zero': {
                'type': 'int',
            },
            'reuse_cipher_list_not_zero': {
                'type': 'int',
            },
            'scsv_received_when_renegotiating': {
                'type': 'int',
            },
            'session_id_context_uninitialized': {
                'type': 'int',
            },
            'short_read': {
                'type': 'int',
            },
            'signature_for_non_signing_certificate': {
                'type': 'int',
            },
            'ssl23_doing_session_id_reuse': {
                'type': 'int',
            },
            'ssl2_connection_id_too_long': {
                'type': 'int',
            },
            'ssl3_session_id_too_long': {
                'type': 'int',
            },
            'ssl3_session_id_too_short': {
                'type': 'int',
            },
            'sslv3_alert_bad_certificate': {
                'type': 'int',
            },
            'sslv3_alert_bad_record_mac': {
                'type': 'int',
            },
            'sslv3_alert_certificate_expired': {
                'type': 'int',
            },
            'sslv3_alert_certificate_revoked': {
                'type': 'int',
            },
            'sslv3_alert_certificate_unknown': {
                'type': 'int',
            },
            'sslv3_alert_decompression_failure': {
                'type': 'int',
            },
            'sslv3_alert_handshake_failure': {
                'type': 'int',
            },
            'sslv3_alert_illegal_parameter': {
                'type': 'int',
            },
            'sslv3_alert_no_certificate': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_cert': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_no_cert': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_no_cipher': {
                'type': 'int',
            },
            'sslv3_alert_peer_error_unsupp_cert_type': {
                'type': 'int',
            },
            'sslv3_alert_unexpected_msg': {
                'type': 'int',
            },
            'sslv3_alert_unknown_remote_err_type': {
                'type': 'int',
            },
            'sslv3_alert_unspported_cert': {
                'type': 'int',
            },
            'ssl_ctx_has_no_default_ssl_version': {
                'type': 'int',
            },
            'ssl_handshake_failure': {
                'type': 'int',
            },
            'ssl_library_has_no_ciphers': {
                'type': 'int',
            },
            'ssl_session_id_callback_failed': {
                'type': 'int',
            },
            'ssl_session_id_conflict': {
                'type': 'int',
            },
            'ssl_session_id_context_too_long': {
                'type': 'int',
            },
            'ssl_session_id_has_bad_length': {
                'type': 'int',
            },
            'ssl_session_id_is_different': {
                'type': 'int',
            },
            'tlsv1_alert_access_denied': {
                'type': 'int',
            },
            'tlsv1_alert_decode_error': {
                'type': 'int',
            },
            'tlsv1_alert_decryption_failed': {
                'type': 'int',
            },
            'tlsv1_alert_decrypt_error': {
                'type': 'int',
            },
            'tlsv1_alert_export_restriction': {
                'type': 'int',
            },
            'tlsv1_alert_insufficient_security': {
                'type': 'int',
            },
            'tlsv1_alert_internal_error': {
                'type': 'int',
            },
            'tlsv1_alert_no_renegotiation': {
                'type': 'int',
            },
            'tlsv1_alert_protocol_version': {
                'type': 'int',
            },
            'tlsv1_alert_record_overflow': {
                'type': 'int',
            },
            'tlsv1_alert_unknown_ca': {
                'type': 'int',
            },
            'tlsv1_alert_user_cancelled': {
                'type': 'int',
            },
            'tls_client_cert_req_with_anon_cipher': {
                'type': 'int',
            },
            'tls_peer_did_not_respond_with_cert_list': {
                'type': 'int',
            },
            'tls_rsa_encrypted_value_length_is_wrong': {
                'type': 'int',
            },
            'tried_to_use_unsupported_cipher': {
                'type': 'int',
            },
            'unable_to_decode_dh_certs': {
                'type': 'int',
            },
            'unable_to_extract_public_key': {
                'type': 'int',
            },
            'unable_to_find_dh_parameters': {
                'type': 'int',
            },
            'unable_to_find_public_key_parameters': {
                'type': 'int',
            },
            'unable_to_find_ssl_method': {
                'type': 'int',
            },
            'unable_to_load_ssl2_md5_routines': {
                'type': 'int',
            },
            'unable_to_load_ssl3_md5_routines': {
                'type': 'int',
            },
            'unable_to_load_ssl3_sha1_routines': {
                'type': 'int',
            },
            'unexpected_message': {
                'type': 'int',
            },
            'unexpected_record': {
                'type': 'int',
            },
            'uninitialized': {
                'type': 'int',
            },
            'unknown_alert_type': {
                'type': 'int',
            },
            'unknown_certificate_type': {
                'type': 'int',
            },
            'unknown_cipher_returned': {
                'type': 'int',
            },
            'unknown_cipher_type': {
                'type': 'int',
            },
            'unknown_key_exchange_type': {
                'type': 'int',
            },
            'unknown_pkey_type': {
                'type': 'int',
            },
            'unknown_protocol': {
                'type': 'int',
            },
            'unknown_remote_error_type': {
                'type': 'int',
            },
            'unknown_ssl_version': {
                'type': 'int',
            },
            'unknown_state': {
                'type': 'int',
            },
            'unsupported_cipher': {
                'type': 'int',
            },
            'unsupported_compression_algorithm': {
                'type': 'int',
            },
            'unsupported_option': {
                'type': 'int',
            },
            'unsupported_protocol': {
                'type': 'int',
            },
            'unsupported_ssl_version': {
                'type': 'int',
            },
            'unsupported_status_type': {
                'type': 'int',
            },
            'write_bio_not_set': {
                'type': 'int',
            },
            'wrong_cipher_returned': {
                'type': 'int',
            },
            'wrong_message_type': {
                'type': 'int',
            },
            'wrong_number_of_key_bits': {
                'type': 'int',
            },
            'wrong_signature_length': {
                'type': 'int',
            },
            'wrong_signature_size': {
                'type': 'int',
            },
            'wrong_ssl_version': {
                'type': 'int',
            },
            'wrong_version_number': {
                'type': 'int',
            },
            'x509_lib': {
                'type': 'int',
            },
            'x509_verification_setup_problems': {
                'type': 'int',
            },
            'clienthello_tlsext': {
                'type': 'int',
            },
            'parse_tlsext': {
                'type': 'int',
            },
            'serverhello_tlsext': {
                'type': 'int',
            },
            'ssl3_ext_invalid_servername': {
                'type': 'int',
            },
            'ssl3_ext_invalid_servername_type': {
                'type': 'int',
            },
            'multiple_sgc_restarts': {
                'type': 'int',
            },
            'tls_invalid_ecpointformat_list': {
                'type': 'int',
            },
            'bad_ecc_cert': {
                'type': 'int',
            },
            'bad_ecdsa_sig': {
                'type': 'int',
            },
            'bad_ecpoint': {
                'type': 'int',
            },
            'cookie_mismatch': {
                'type': 'int',
            },
            'unsupported_elliptic_curve': {
                'type': 'int',
            },
            'no_required_digest': {
                'type': 'int',
            },
            'unsupported_digest_type': {
                'type': 'int',
            },
            'bad_handshake_length': {
                'type': 'int',
            }
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
