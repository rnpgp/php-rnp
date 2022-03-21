/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 76b6f44eb792379a49c80d2277e07ae80f5ce175 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_rnp_backend_string, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_backend_version arginfo_rnp_backend_string

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_rnp_supported_features, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

#define arginfo_rnp_version_string arginfo_rnp_backend_string

#define arginfo_rnp_version_string_full arginfo_rnp_backend_string


ZEND_FUNCTION(rnp_backend_string);
ZEND_FUNCTION(rnp_backend_version);
ZEND_FUNCTION(rnp_supported_features);
ZEND_FUNCTION(rnp_version_string);
ZEND_FUNCTION(rnp_version_string_full);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(rnp_backend_string, arginfo_rnp_backend_string)
	ZEND_FE(rnp_backend_version, arginfo_rnp_backend_version)
	ZEND_FE(rnp_supported_features, arginfo_rnp_supported_features)
	ZEND_FE(rnp_version_string, arginfo_rnp_version_string)
	ZEND_FE(rnp_version_string_full, arginfo_rnp_version_string_full)
	ZEND_FE_END
};
