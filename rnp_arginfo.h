/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 4547526c8e5fa6310b98d7cf001d0e873938076c */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_backend_string, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_backend_version arginfo_rnp_backend_string

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_supported_features, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_version_string arginfo_rnp_backend_string

#define arginfo_rnp_version_string_full arginfo_rnp_backend_string

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_rnp_ffi_create, 0, 2, RnpFFI, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, pub_format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, sec_format, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_ffi_destroy, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_load_keys, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_load_keys_from_path, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, input_path, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_save_keys, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(1, output, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_save_keys_to_path, 0, 4, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, output_path, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_dump_packets, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_dump_packets_to_json, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_generate_key, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, userid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key_alg, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sub_alg, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_ffi_set_pass_provider, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, password_callback, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_sign, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, keys_fp, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

#define arginfo_rnp_op_sign_cleartext arginfo_rnp_op_sign

#define arginfo_rnp_op_sign_detached arginfo_rnp_op_sign

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_verify, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_verify_detached, 0, 3, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_encrypt, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, recipient_keys_fp, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_decrypt, 0, 2, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_locate_key, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, identifier_type, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, identifier, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_list_keys, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, identifier_type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_get_info, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_export, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_export_autocrypt, 0, 5, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, subkey_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_import_keys, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, input, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_remove, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_revoke, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_export_revocation, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

#define arginfo_rnp_import_signatures arginfo_rnp_import_keys

#define arginfo_rnp_key_get_signatures arginfo_rnp_key_get_info

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_uid_get_signatures, 0, 3, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_rnp_key_certification_create, 0, 4, RnpKeySignature, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, signer_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, target_key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_rnp_key_direct_signature_create, 0, 2, RnpKeySignature, MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, signer_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, target_key_fp, IS_STRING, 1, "null")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

#define arginfo_rnp_key_revocation_signature_create arginfo_rnp_key_direct_signature_create

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_signature_sign, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, sig, RnpKeySignature, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_key_remove_signatures arginfo_rnp_key_remove

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_add_security_rule, 0, 6, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, from, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, level, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_get_security_rule, 0, 4, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, time, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_remove_security_rule, 0, 6, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, level, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, flags, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, from, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_set_timestamp, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, timestamp, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_request_password, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_protect, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_unprotect, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, password, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_lock, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_key_unlock arginfo_rnp_key_unprotect

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_set_expiration, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, expiration, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_key_add_uid, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

#define arginfo_rnp_uid_get_info arginfo_rnp_uid_get_signatures

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_uid_remove, 0, 3, _IS_BOOL, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, uid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_enarmor, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, type, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_dearmor, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_calculate_iterations, 0, 2, MAY_BE_LONG|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, hash, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, msec, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_to_json, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_key_packets_to_json, 0, 2, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, key_fp, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, secret, _IS_BOOL, 0, "false")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
ZEND_END_ARG_INFO()

ZEND_FUNCTION(rnp_backend_string);
ZEND_FUNCTION(rnp_backend_version);
ZEND_FUNCTION(rnp_supported_features);
ZEND_FUNCTION(rnp_version_string);
ZEND_FUNCTION(rnp_version_string_full);
ZEND_FUNCTION(rnp_ffi_create);
ZEND_FUNCTION(rnp_ffi_destroy);
ZEND_FUNCTION(rnp_load_keys);
ZEND_FUNCTION(rnp_load_keys_from_path);
ZEND_FUNCTION(rnp_save_keys);
ZEND_FUNCTION(rnp_save_keys_to_path);
ZEND_FUNCTION(rnp_dump_packets);
ZEND_FUNCTION(rnp_dump_packets_to_json);
ZEND_FUNCTION(rnp_op_generate_key);
ZEND_FUNCTION(rnp_ffi_set_pass_provider);
ZEND_FUNCTION(rnp_op_sign);
ZEND_FUNCTION(rnp_op_sign_cleartext);
ZEND_FUNCTION(rnp_op_sign_detached);
ZEND_FUNCTION(rnp_op_verify);
ZEND_FUNCTION(rnp_op_verify_detached);
ZEND_FUNCTION(rnp_op_encrypt);
ZEND_FUNCTION(rnp_decrypt);
ZEND_FUNCTION(rnp_locate_key);
ZEND_FUNCTION(rnp_list_keys);
ZEND_FUNCTION(rnp_key_get_info);
ZEND_FUNCTION(rnp_key_export);
ZEND_FUNCTION(rnp_key_export_autocrypt);
ZEND_FUNCTION(rnp_import_keys);
ZEND_FUNCTION(rnp_key_remove);
ZEND_FUNCTION(rnp_key_revoke);
ZEND_FUNCTION(rnp_key_export_revocation);
ZEND_FUNCTION(rnp_import_signatures);
ZEND_FUNCTION(rnp_key_get_signatures);
ZEND_FUNCTION(rnp_uid_get_signatures);
ZEND_FUNCTION(rnp_key_certification_create);
ZEND_FUNCTION(rnp_key_direct_signature_create);
ZEND_FUNCTION(rnp_key_revocation_signature_create);
ZEND_FUNCTION(rnp_key_signature_sign);
ZEND_FUNCTION(rnp_key_remove_signatures);
ZEND_FUNCTION(rnp_add_security_rule);
ZEND_FUNCTION(rnp_get_security_rule);
ZEND_FUNCTION(rnp_remove_security_rule);
ZEND_FUNCTION(rnp_set_timestamp);
ZEND_FUNCTION(rnp_request_password);
ZEND_FUNCTION(rnp_key_protect);
ZEND_FUNCTION(rnp_key_unprotect);
ZEND_FUNCTION(rnp_key_lock);
ZEND_FUNCTION(rnp_key_unlock);
ZEND_FUNCTION(rnp_key_set_expiration);
ZEND_FUNCTION(rnp_key_add_uid);
ZEND_FUNCTION(rnp_uid_get_info);
ZEND_FUNCTION(rnp_uid_remove);
ZEND_FUNCTION(rnp_enarmor);
ZEND_FUNCTION(rnp_dearmor);
ZEND_FUNCTION(rnp_calculate_iterations);
ZEND_FUNCTION(rnp_key_to_json);
ZEND_FUNCTION(rnp_key_packets_to_json);

static const zend_function_entry ext_functions[] = {
	ZEND_FE(rnp_backend_string, arginfo_rnp_backend_string)
	ZEND_FE(rnp_backend_version, arginfo_rnp_backend_version)
	ZEND_FE(rnp_supported_features, arginfo_rnp_supported_features)
	ZEND_FE(rnp_version_string, arginfo_rnp_version_string)
	ZEND_FE(rnp_version_string_full, arginfo_rnp_version_string_full)
	ZEND_FE(rnp_ffi_create, arginfo_rnp_ffi_create)
	ZEND_FE(rnp_ffi_destroy, arginfo_rnp_ffi_destroy)
	ZEND_FE(rnp_load_keys, arginfo_rnp_load_keys)
	ZEND_FE(rnp_load_keys_from_path, arginfo_rnp_load_keys_from_path)
	ZEND_FE(rnp_save_keys, arginfo_rnp_save_keys)
	ZEND_FE(rnp_save_keys_to_path, arginfo_rnp_save_keys_to_path)
	ZEND_FE(rnp_dump_packets, arginfo_rnp_dump_packets)
	ZEND_FE(rnp_dump_packets_to_json, arginfo_rnp_dump_packets_to_json)
	ZEND_FE(rnp_op_generate_key, arginfo_rnp_op_generate_key)
	ZEND_FE(rnp_ffi_set_pass_provider, arginfo_rnp_ffi_set_pass_provider)
	ZEND_FE(rnp_op_sign, arginfo_rnp_op_sign)
	ZEND_FE(rnp_op_sign_cleartext, arginfo_rnp_op_sign_cleartext)
	ZEND_FE(rnp_op_sign_detached, arginfo_rnp_op_sign_detached)
	ZEND_FE(rnp_op_verify, arginfo_rnp_op_verify)
	ZEND_FE(rnp_op_verify_detached, arginfo_rnp_op_verify_detached)
	ZEND_FE(rnp_op_encrypt, arginfo_rnp_op_encrypt)
	ZEND_FE(rnp_decrypt, arginfo_rnp_decrypt)
	ZEND_FE(rnp_locate_key, arginfo_rnp_locate_key)
	ZEND_FE(rnp_list_keys, arginfo_rnp_list_keys)
	ZEND_FE(rnp_key_get_info, arginfo_rnp_key_get_info)
	ZEND_FE(rnp_key_export, arginfo_rnp_key_export)
	ZEND_FE(rnp_key_export_autocrypt, arginfo_rnp_key_export_autocrypt)
	ZEND_FE(rnp_import_keys, arginfo_rnp_import_keys)
	ZEND_FE(rnp_key_remove, arginfo_rnp_key_remove)
	ZEND_FE(rnp_key_revoke, arginfo_rnp_key_revoke)
	ZEND_FE(rnp_key_export_revocation, arginfo_rnp_key_export_revocation)
	ZEND_FE(rnp_import_signatures, arginfo_rnp_import_signatures)
	ZEND_FE(rnp_key_get_signatures, arginfo_rnp_key_get_signatures)
	ZEND_FE(rnp_uid_get_signatures, arginfo_rnp_uid_get_signatures)
	ZEND_FE(rnp_key_certification_create, arginfo_rnp_key_certification_create)
	ZEND_FE(rnp_key_direct_signature_create, arginfo_rnp_key_direct_signature_create)
	ZEND_FE(rnp_key_revocation_signature_create, arginfo_rnp_key_revocation_signature_create)
	ZEND_FE(rnp_key_signature_sign, arginfo_rnp_key_signature_sign)
	ZEND_FE(rnp_key_remove_signatures, arginfo_rnp_key_remove_signatures)
	ZEND_FE(rnp_add_security_rule, arginfo_rnp_add_security_rule)
	ZEND_FE(rnp_get_security_rule, arginfo_rnp_get_security_rule)
	ZEND_FE(rnp_remove_security_rule, arginfo_rnp_remove_security_rule)
	ZEND_FE(rnp_set_timestamp, arginfo_rnp_set_timestamp)
	ZEND_FE(rnp_request_password, arginfo_rnp_request_password)
	ZEND_FE(rnp_key_protect, arginfo_rnp_key_protect)
	ZEND_FE(rnp_key_unprotect, arginfo_rnp_key_unprotect)
	ZEND_FE(rnp_key_lock, arginfo_rnp_key_lock)
	ZEND_FE(rnp_key_unlock, arginfo_rnp_key_unlock)
	ZEND_FE(rnp_key_set_expiration, arginfo_rnp_key_set_expiration)
	ZEND_FE(rnp_key_add_uid, arginfo_rnp_key_add_uid)
	ZEND_FE(rnp_uid_get_info, arginfo_rnp_uid_get_info)
	ZEND_FE(rnp_uid_remove, arginfo_rnp_uid_remove)
	ZEND_FE(rnp_enarmor, arginfo_rnp_enarmor)
	ZEND_FE(rnp_dearmor, arginfo_rnp_dearmor)
	ZEND_FE(rnp_calculate_iterations, arginfo_rnp_calculate_iterations)
	ZEND_FE(rnp_key_to_json, arginfo_rnp_key_to_json)
	ZEND_FE(rnp_key_packets_to_json, arginfo_rnp_key_packets_to_json)
	ZEND_FE_END
};

static zend_class_entry *register_class_RnpFFI(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "RnpFFI", NULL);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL);

	return class_entry;
}

static zend_class_entry *register_class_RnpKeySignature(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "RnpKeySignature", NULL);
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL);

	return class_entry;
}
