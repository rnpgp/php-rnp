/*-
 * Copyright (c) 2017-2022, Ribose Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* rnp extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_rnp.h"
#include "rnp_arginfo.h"
#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif


PHP_FUNCTION(rnp_backend_string)
{
	zend_string *retval;
	const char *backend;

	ZEND_PARSE_PARAMETERS_NONE();

	backend = rnp_backend_string();
	retval = zend_string_init(backend, strlen(backend), 0);

	RETURN_STR(retval);
}

PHP_FUNCTION(rnp_backend_version)
{
	zend_string *retval;
	const char *version;

	ZEND_PARSE_PARAMETERS_NONE();

	version = rnp_backend_version();
	retval = zend_string_init(version, strlen(version), 0);

	RETURN_STR(retval);
}

PHP_FUNCTION(rnp_supported_features)
{
	zend_string *retval;
	zend_string *type;
	char *result;

	ZEND_PARSE_PARAMETERS_START(1,1);
		Z_PARAM_STR(type)
	ZEND_PARSE_PARAMETERS_END();

	if (rnp_supported_features(ZSTR_VAL(type), &result) != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	retval = zend_string_init(result, strlen(result), 0);
	rnp_buffer_destroy(result);

	RETURN_STR(retval);
}

PHP_FUNCTION(rnp_version_string)
{
	zend_string *retval;
	const char *version;

	ZEND_PARSE_PARAMETERS_NONE();

	version = rnp_version_string();
	retval = zend_string_init(version, strlen(version), 0);

	RETURN_STR(retval);
}

PHP_FUNCTION(rnp_version_string_full)
{
	zend_string *retval;
	const char *version;

	ZEND_PARSE_PARAMETERS_NONE();

	version = rnp_version_string_full();
	retval = zend_string_init(version, strlen(version), 0);

	RETURN_STR(retval);
}

PHP_FUNCTION(rnp_ffi_create)
{
	zend_string *pub_format;
	zend_string *sec_format;
	rnp_ffi_t ffi;
	php_rnp_ffi_t *pffi;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_STR(pub_format)
		Z_PARAM_STR(sec_format)
	ZEND_PARSE_PARAMETERS_END();

	if (rnp_ffi_create(&ffi, ZSTR_VAL(pub_format), ZSTR_VAL(sec_format)) != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	object_init_ex(return_value, rnp_ffi_t_ce);
	pffi = Z_FFI_P(return_value);
	pffi->ffi = ffi;
}

PHP_FUNCTION(rnp_ffi_destroy)
{
	zval *zffi;
	php_rnp_ffi_t *pffi;

	ZEND_PARSE_PARAMETERS_START(1, 1);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce);
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);
	if (!pffi->ffi) {
		zend_throw_error(NULL, "%s(): Attempt to destroy already destroyed FFI object!", get_active_function_name());
		RETURN_THROWS();
	}

	rnp_ffi_destroy(pffi->ffi);
	pffi->ffi = NULL;
}

PHP_FUNCTION(rnp_load_keys)
{
	zval *zffi;
	zend_string *format;
	zend_string *input;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_input_t mem_input;

	ZEND_PARSE_PARAMETERS_START(4, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(format)
		Z_PARAM_STR(input)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, ZSTR_VAL(input), ZSTR_LEN(input), false);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_load_keys(pffi->ffi, ZSTR_VAL(format), mem_input, flags);

	(void) rnp_input_destroy(mem_input);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_load_keys_from_path)
{
	zval *zffi;
	zend_string *format;
	zend_string *input_path;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_input_t path_input;

	ZEND_PARSE_PARAMETERS_START(4, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(format)
		Z_PARAM_PATH_STR(input_path)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_path(&path_input, ZSTR_VAL(input_path));

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_load_keys(pffi->ffi, ZSTR_VAL(format), path_input, flags);

	(void) rnp_input_destroy(path_input);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_save_keys)
{
	zval *zffi;
	zend_string *format;
	zval *output_ref;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_output_t mem_output;

	ZEND_PARSE_PARAMETERS_START(4, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(format)
		Z_PARAM_ZVAL(output_ref)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_output_to_memory(&mem_output, 0);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_save_keys(pffi->ffi, ZSTR_VAL(format), mem_output, flags);

	if (ret == RNP_SUCCESS) {
		uint8_t *buf;
		size_t len;
		ret = rnp_output_memory_get_buf(mem_output, &buf, &len, false);

		if (ret == RNP_SUCCESS) {
			ZEND_TRY_ASSIGN_REF_STRINGL(output_ref, buf, len);
		}
	}

	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_save_keys_to_path)
{
	zval *zffi;
	zend_string *format;
	zend_string *output_path;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_output_t path_output;

	ZEND_PARSE_PARAMETERS_START(4, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(format)
		Z_PARAM_PATH_STR(output_path)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_output_to_path(&path_output, ZSTR_VAL(output_path));

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_save_keys(pffi->ffi, ZSTR_VAL(format), path_output, flags);

	(void) rnp_output_destroy(path_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_dump_packets)
{
	zend_string *input;
	zend_long flags;

	rnp_result_t ret;
	rnp_input_t mem_input;
	rnp_output_t mem_output;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_STR(input)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	ret = rnp_input_from_memory(&mem_input, ZSTR_VAL(input), ZSTR_LEN(input), false);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);

	if (ret != RNP_SUCCESS) {
		rnp_input_destroy(mem_input);
		RETURN_FALSE;
	}

	ret = rnp_dump_packets_to_output(mem_input, mem_output, flags);

	if (ret == RNP_SUCCESS) {
		uint8_t *buf;
		size_t len;
		ret = rnp_output_memory_get_buf(mem_output, &buf, &len, false);

		if (ret == RNP_SUCCESS) {
			ZVAL_STRINGL(return_value, buf, len);
		}
	}

	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_dump_packets_to_json)
{
	zend_string *input;
	zend_long flags;

	rnp_result_t ret;
	rnp_input_t mem_input;
	char *result;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_STR(input)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	ret = rnp_input_from_memory(&mem_input, ZSTR_VAL(input), ZSTR_LEN(input), false);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_dump_packets_to_json(mem_input, flags, &result);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRING(return_value, result);
		rnp_buffer_destroy(result);
	}

	(void) rnp_input_destroy(mem_input);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_op_generate_key)
{
	zval *zffi;
	zend_string *userid;
	zend_string *key_alg;
	zend_string *sub_alg;
	zval *options = NULL;

	rnp_op_generate_t op = NULL;
	rnp_op_generate_t subop = NULL;
	rnp_key_handle_t  primary = NULL;
	rnp_key_handle_t  subkey = NULL;
	rnp_result_t      ret = RNP_ERROR_KEY_GENERATION;
	php_rnp_ffi_t    *pffi;
	char             *primary_fprint = NULL;
	bool              gen_subkey = false;
	bool              have_options = false;
	const char       *password = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 5);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(userid)
		Z_PARAM_STR(key_alg)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR(sub_alg)
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	if ((ret = rnp_op_generate_create(&op, pffi->ffi, ZSTR_VAL(key_alg)))) {
		RETURN_FALSE;
	}
	if ((ret = rnp_op_generate_set_userid(op, ZSTR_VAL(userid)))) {
		goto done;
	}

	if (ZEND_NUM_ARGS() > 3) {
		gen_subkey = true;
	}
	if (ZEND_NUM_ARGS() > 4 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *data;

		have_options = true;

		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "bits", sizeof("bits") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_LONG) {
			if ((ret = rnp_op_generate_set_bits(op, Z_LVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_STRING) {
			if ((ret = rnp_op_generate_set_hash(op, Z_STRVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "dsa_qbits", sizeof("dsa_qbits") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_LONG) {
			if ((ret = rnp_op_generate_set_dsa_qbits(op, Z_LVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "curve", sizeof("curve") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_STRING) {
			if ((ret = rnp_op_generate_set_curve(op, Z_STRVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "password", sizeof("password") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_STRING) {
			password = Z_STRVAL_P(data);
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "expiration", sizeof("expiration") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_LONG) {
			if ((ret = rnp_op_generate_set_expiration(op, Z_LVAL_P(data)))) {
				goto done;
			}
		}
	}

	if ((ret = rnp_op_generate_execute(op))) {
		goto done;
	}
	if ((ret = rnp_op_generate_get_key(op, &primary))) {
		goto done;
	}
	if (!gen_subkey) {
		goto done;
	}
	if ((ret = rnp_op_generate_subkey_create(&subop, pffi->ffi, primary, ZSTR_VAL(sub_alg)))) {
		goto done;
	}

	if (have_options) {
		zval *data;

		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "sub_bits", sizeof("sub_bits") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_LONG) {
			if ((ret = rnp_op_generate_set_bits(subop, Z_LVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "sub_hash", sizeof("sub_hash") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_STRING) {
			if ((ret = rnp_op_generate_set_hash(subop, Z_STRVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "sub_curve", sizeof("sub_curve") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_STRING) {
			if ((ret = rnp_op_generate_set_curve(subop, Z_STRVAL_P(data)))) {
				goto done;
			}
		}
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "expiration", sizeof("expiration") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_LONG) {
			if ((ret = rnp_op_generate_set_expiration(subop, Z_LVAL_P(data)))) {
				goto done;
			}
		}
	}

	if (password && (ret = rnp_op_generate_set_protection_password(subop, password))) {
		goto done;
	}
	if ((ret = rnp_op_generate_execute(subop))) {
		goto done;
	}
	if ((ret = rnp_op_generate_get_key(subop, &subkey))) {
		goto done;
	}
done:
	if (!ret && password) {
		ret = rnp_key_protect(primary, password, NULL, NULL, NULL, 0);
	}
	if (ret && primary) {
		rnp_key_remove(primary, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
	}
	if (ret && subkey) {
		rnp_key_remove(subkey, RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET);
	}
	rnp_op_generate_destroy(op);
	rnp_op_generate_destroy(subop);
	rnp_key_handle_destroy(subkey);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	if ((ret = rnp_key_get_fprint(primary, &primary_fprint))) {
		rnp_key_handle_destroy(primary);
		RETURN_FALSE;
	}

	ZVAL_STRINGL(return_value, primary_fprint, strlen(primary_fprint));

	rnp_buffer_destroy(primary_fprint);
	rnp_key_handle_destroy(primary);
}

/* {{{ PHP_RINIT_FUNCTION */
PHP_RINIT_FUNCTION(rnp)
{
#if defined(ZTS) && defined(COMPILE_DL_RNP)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(rnp)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "rnp support", "enabled");
	php_info_print_table_end();
}
/* }}} */


zend_class_entry *rnp_ffi_t_ce;
static zend_object_handlers rnp_object_handlers;

static zend_object *rnp_create_object(zend_class_entry *class_type)
{
	php_rnp_ffi_t *intern = zend_object_alloc(sizeof(php_rnp_ffi_t), class_type);

	zend_object_std_init(&intern->std, class_type);
	intern->std.handlers = &rnp_object_handlers;

	return &intern->std;
}

static void rnp_free_obj(zend_object *object)
{
	php_rnp_ffi_t *intern = rnp_ffi_t_from_obj(object);
	rnp_ffi_destroy(intern->ffi);
	zend_object_std_dtor(&intern->std);
}

static zend_function *rnp_get_constructor(zend_object *object)
{
	zend_throw_error(NULL, "Cannot directly construct rnp_ffi_t, use rnp_ffi_create() instead");
	return NULL;
}

PHP_MINIT_FUNCTION(rnp)
{
	rnp_ffi_t_ce = register_class_RnpFFI();
	rnp_ffi_t_ce->create_object = rnp_create_object;

	memcpy(&rnp_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	rnp_object_handlers.offset = XtOffsetOf(php_rnp_ffi_t, std);
	rnp_object_handlers.clone_obj = NULL;
	rnp_object_handlers.free_obj = rnp_free_obj;
	rnp_object_handlers.get_constructor = rnp_get_constructor;

	REGISTER_LONG_CONSTANT("RNP_LOAD_SAVE_PUBLIC_KEYS", RNP_LOAD_SAVE_PUBLIC_KEYS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_LOAD_SAVE_SECRET_KEYS", RNP_LOAD_SAVE_SECRET_KEYS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_LOAD_SAVE_PERMISSIVE", RNP_LOAD_SAVE_PERMISSIVE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_LOAD_SAVE_SINGLE", RNP_LOAD_SAVE_SINGLE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_LOAD_SAVE_BASE64", RNP_LOAD_SAVE_BASE64, CONST_CS | CONST_PERSISTENT);

	REGISTER_STRING_CONSTANT("RNP_FEATURE_SYMM_ALG", RNP_FEATURE_SYMM_ALG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_AEAD_ALG", RNP_FEATURE_AEAD_ALG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_PROT_MODE", RNP_FEATURE_PROT_MODE, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_PK_ALG", RNP_FEATURE_PK_ALG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_HASH_ALG", RNP_FEATURE_HASH_ALG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_COMP_ALG", RNP_FEATURE_COMP_ALG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_FEATURE_CURVE", RNP_FEATURE_CURVE, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("RNP_DUMP_MPI", RNP_DUMP_MPI, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_DUMP_RAW", RNP_DUMP_RAW, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_DUMP_GRIP", RNP_DUMP_GRIP, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("RNP_JSON_DUMP_MPI", RNP_JSON_DUMP_MPI, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_JSON_DUMP_RAW", RNP_JSON_DUMP_RAW, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_JSON_DUMP_GRIP", RNP_JSON_DUMP_GRIP, CONST_CS | CONST_PERSISTENT);
}


/* {{{ rnp_module_entry */
zend_module_entry rnp_module_entry = {
	STANDARD_MODULE_HEADER,
	"rnp",					/* Extension name */
	ext_functions,					/* zend_function_entry */
	PHP_MINIT(rnp),							/* PHP_MINIT - Module initialization */
	NULL,							/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(rnp),			/* PHP_RINIT - Request initialization */
	NULL,							/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(rnp),			/* PHP_MINFO - Module info */
	PHP_RNP_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_RNP
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(rnp)
#endif
