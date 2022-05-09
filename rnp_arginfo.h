/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 211638c72f59a905f986e925cde0b7e8f812d5e1 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_backend_string, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_backend_version arginfo_rnp_backend_string

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_supported_features, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_version_string arginfo_rnp_backend_string

#define arginfo_rnp_version_string_full arginfo_rnp_backend_string

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_TYPE_MASK_EX(arginfo_rnp_ffi_create, 0, 2, rnp_ffi_t, MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, pub_format, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, sec_format, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_ffi_destroy, 0, 1, IS_VOID, 0)
	ZEND_ARG_OBJ_INFO(0, ffi, rnp_ffi_t, 0)
ZEND_END_ARG_INFO()


ZEND_FUNCTION(rnp_backend_string);
ZEND_FUNCTION(rnp_backend_version);
ZEND_FUNCTION(rnp_supported_features);
ZEND_FUNCTION(rnp_version_string);
ZEND_FUNCTION(rnp_version_string_full);
ZEND_FUNCTION(rnp_ffi_create);
ZEND_FUNCTION(rnp_ffi_destroy);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(rnp_backend_string, arginfo_rnp_backend_string)
	ZEND_FE(rnp_backend_version, arginfo_rnp_backend_version)
	ZEND_FE(rnp_supported_features, arginfo_rnp_supported_features)
	ZEND_FE(rnp_version_string, arginfo_rnp_version_string)
	ZEND_FE(rnp_version_string_full, arginfo_rnp_version_string_full)
	ZEND_FE(rnp_ffi_create, arginfo_rnp_ffi_create)
	ZEND_FE(rnp_ffi_destroy, arginfo_rnp_ffi_destroy)
	ZEND_FE_END
};


static const zend_function_entry class_rnp_ffi_t_methods[] = {
	ZEND_FE_END
};

static zend_class_entry *register_class_rnp_ffi_t(void)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "rnp_ffi_t", class_rnp_ffi_t_methods);
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL;

	return class_entry;
}
