/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 62703254b577d12678c1efdb6915deba0d55b26d */

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

#define arginfo_rnp_dump_packets_to_json arginfo_rnp_dump_packets

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_generate_key, 0, 3, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, userid, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key_alg, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, sub_alg, IS_STRING, 0, "null")
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
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_op_verify_detached, 0, 3, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_OBJ_INFO(0, ffi, RnpFFI, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
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
	ZEND_FE_END
};


static const zend_function_entry class_RnpFFI_methods[] = {
	ZEND_FE_END
};

static zend_class_entry *register_class_RnpFFI(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "RnpFFI", class_RnpFFI_methods);
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL;

	return class_entry;
}
