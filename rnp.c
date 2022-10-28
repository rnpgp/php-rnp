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

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);

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
			ZEND_TRY_ASSIGN_REF_STRINGL(output_ref, (char *)buf, len);
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

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);

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
			ZVAL_STRINGL(return_value, (char *)buf, len);
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

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);

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
	bool              request_password = false;
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
		if ((data = zend_hash_str_find(Z_ARRVAL_P(options), "request_password", sizeof("request_password") - 1)) != NULL &&
		        Z_TYPE_P(data) == IS_TRUE) {
			request_password = true;
			if ((ret = rnp_op_generate_set_request_password(op, true))) {
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
		if (request_password) {
			if ((ret = rnp_op_generate_set_request_password(subop, true))) {
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

static bool php_rnp_password_callback(rnp_ffi_t        ffi,
				      void *           app_ctx,
				      rnp_key_handle_t key,
				      const char *     pgp_context,
				      char             buf[],
				      size_t           buf_len)
{
	php_rnp_ffi_t *pffi = (php_rnp_ffi_t*) app_ctx;
	char *key_fp = "";
	rnp_result_t ret;
	size_t pass_len;

	zval retval;
	zval passwordval;
	zval args[3];

	if (!pffi->pass_provider_is_set) {
		return false;
	}

	ZVAL_NULL(&retval);
	ZVAL_STRINGL(&passwordval, buf, buf_len);

	if (key) {
		ret = rnp_key_get_fprint(key, &key_fp);

		if (ret != RNP_SUCCESS) {
			zval_ptr_dtor(&passwordval);
			return false;
		}
	}

	ZVAL_STRING(&args[0], key_fp);
	ZVAL_STRING(&args[1], pgp_context);
	ZVAL_NEW_REF(&args[2], &passwordval);

	pffi->fci.retval = &retval;
	pffi->fci.param_count = 3;
	pffi->fci.params = args;

	ret = RNP_ERROR_GENERIC;

	if (zend_call_function(&pffi->fci, &pffi->fci_cache) != FAILURE) {
		pass_len = Z_STRLEN_P(Z_REFVAL_P(&args[2]));
		if (pass_len < buf_len) {
			memcpy(buf, Z_STRVAL_P(Z_REFVAL_P(&args[2])), pass_len + 1);
			ret = RNP_SUCCESS;
		}
	}

	zval_ptr_dtor(&retval);
	zval_ptr_dtor(&passwordval);
	zval_ptr_dtor_str(&args[0]);
	zval_ptr_dtor_str(&args[1]);
	zval_ptr_dtor(&args[2]);

	if (key) {
		rnp_buffer_destroy(key_fp);
	}

	return (ret == RNP_SUCCESS);
}

PHP_FUNCTION(rnp_ffi_set_pass_provider)
{
	zval *zffi;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_FUNC(Z_FFI_P(zffi)->fci, Z_FFI_P(zffi)->fci_cache)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);
	ret = rnp_ffi_set_pass_provider(pffi->ffi, php_rnp_password_callback, pffi);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	pffi->pass_provider_is_set = true;
	RETURN_TRUE;
}

PHP_FUNCTION(rnp_op_sign)
{
	zval *zffi;
	zend_string *data;
	zval *keysfp;
	zval *options = NULL;
	zval *current_keyfp;

	rnp_result_t   ret = RNP_ERROR_SIGNING_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t mem_output = NULL;
	rnp_op_sign_t sign = NULL;
	uint8_t *sig_buf;
	size_t   sig_len;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(data)
		Z_PARAM_ARRAY(keysfp)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(data), ZSTR_LEN(data), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_sign_create(&sign, pffi->ffi, mem_input, mem_output))) {
		goto done;
	}

	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;
		const char *compression_alg = NULL;
		int compression_level = 0;

		/* Set compression parameters (only relevant for embedded signature) */
		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "compression_alg", sizeof("compression_alg") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			compression_alg = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "compression_level", sizeof("compression_level") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			compression_level = Z_LVAL_P(opt);
		}

		if (compression_alg && compression_level) {
			if ((ret = rnp_op_sign_set_compression(sign, compression_alg, compression_level))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "armor", sizeof("armor")  - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_TRUE) {
			if ((ret = rnp_op_sign_set_armor(sign, true))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_sign_set_hash(sign, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "creation_time", sizeof("creation_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_creation_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "expiration_time", sizeof("expiration_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_expiration_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}
		/* signature file name and file modification time (embedded signature only) */
		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "file_name", sizeof("file_name") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_sign_set_file_name(sign, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "file_mtime", sizeof("file_mtime") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_file_mtime(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}
	}

	/* iterate over keysfp array */
	if (zend_hash_num_elements(Z_ARRVAL_P(keysfp)) == 0) {
		ret = RNP_ERROR_SIGNING_FAILED;
		goto done;
	}
	zend_hash_internal_pointer_reset(Z_ARRVAL_P(keysfp));
	while ((current_keyfp = zend_hash_get_current_data(Z_ARRVAL_P(keysfp)))) {
		zend_hash_move_forward(Z_ARRVAL_P(keysfp));

		rnp_key_handle_t kh = NULL;

		if (Z_TYPE_P(current_keyfp) != IS_STRING) {
			continue;
		}

		ret = rnp_locate_key(pffi->ffi, "fingerprint", Z_STRVAL_P(current_keyfp), &kh);

		if (ret == RNP_SUCCESS) {
			ret = rnp_op_sign_add_signature(sign, kh, NULL);
		}

		rnp_key_handle_destroy(kh);

		if (ret != RNP_SUCCESS) {
			goto done;
		}
	}

	if ((ret = rnp_op_sign_execute(sign)) != RNP_SUCCESS) {
		goto done;
	}

	/* return signature as a PHP string */
	ret = rnp_output_memory_get_buf(mem_output, &sig_buf, &sig_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)sig_buf, sig_len);
	}

done:
	(void) rnp_op_sign_destroy(sign);
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_op_sign_cleartext)
{
	zval *zffi;
	zend_string *data;
	zval *keysfp;
	zval *options = NULL;
	zval *current_keyfp;

	rnp_result_t   ret = RNP_ERROR_SIGNING_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t mem_output = NULL;
	rnp_op_sign_t sign = NULL;
	uint8_t *sig_buf;
	size_t   sig_len;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(data)
		Z_PARAM_ARRAY(keysfp)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(data), ZSTR_LEN(data), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_sign_cleartext_create(&sign, pffi->ffi, mem_input, mem_output))) {
		goto done;
	}

	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "armor", sizeof("armor")  - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_TRUE) {
			if ((ret = rnp_op_sign_set_armor(sign, true))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_sign_set_hash(sign, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "creation_time", sizeof("creation_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_creation_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "expiration_time", sizeof("expiration_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_expiration_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}
	}

	/* iterate over keysfp array */
	if (zend_hash_num_elements(Z_ARRVAL_P(keysfp)) == 0) {
		ret = RNP_ERROR_SIGNING_FAILED;
		goto done;
	}
	zend_hash_internal_pointer_reset(Z_ARRVAL_P(keysfp));
	while ((current_keyfp = zend_hash_get_current_data(Z_ARRVAL_P(keysfp)))) {
		zend_hash_move_forward(Z_ARRVAL_P(keysfp));

		rnp_key_handle_t kh = NULL;

		if (Z_TYPE_P(current_keyfp) != IS_STRING) {
			continue;
		}

		ret = rnp_locate_key(pffi->ffi, "fingerprint", Z_STRVAL_P(current_keyfp), &kh);

		if (ret == RNP_SUCCESS) {
			ret = rnp_op_sign_add_signature(sign, kh, NULL);
		}

		rnp_key_handle_destroy(kh);

		if (ret != RNP_SUCCESS) {
			goto done;
		}
	}

	if ((ret = rnp_op_sign_execute(sign)) != RNP_SUCCESS) {
		goto done;
	}

	/* return signature as a PHP string */
	ret = rnp_output_memory_get_buf(mem_output, &sig_buf, &sig_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)sig_buf, sig_len);
	}

done:
	(void) rnp_op_sign_destroy(sign);
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_op_sign_detached)
{
	zval *zffi;
	zend_string *data;
	zval *keysfp;
	zval *options = NULL;
	zval *current_keyfp;

	rnp_result_t   ret = RNP_ERROR_SIGNING_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t mem_output = NULL;
	rnp_op_sign_t sign = NULL;
	uint8_t *sig_buf;
	size_t   sig_len;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(data)
		Z_PARAM_ARRAY(keysfp)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(data), ZSTR_LEN(data), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_sign_detached_create(&sign, pffi->ffi, mem_input, mem_output))) {
		goto done;
	}

	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "armor", sizeof("armor")  - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_TRUE) {
			if ((ret = rnp_op_sign_set_armor(sign, true))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_sign_set_hash(sign, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "creation_time", sizeof("creation_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_creation_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "expiration_time", sizeof("expiration_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_sign_set_expiration_time(sign, Z_LVAL_P(opt)))) {
				goto done;
			}
		}
	}

	/* iterate over keysfp array */
	if (zend_hash_num_elements(Z_ARRVAL_P(keysfp)) == 0) {
		ret = RNP_ERROR_SIGNING_FAILED;
		goto done;
	}
	zend_hash_internal_pointer_reset(Z_ARRVAL_P(keysfp));
	while ((current_keyfp = zend_hash_get_current_data(Z_ARRVAL_P(keysfp)))) {
		zend_hash_move_forward(Z_ARRVAL_P(keysfp));

		rnp_key_handle_t kh = NULL;

		if (Z_TYPE_P(current_keyfp) != IS_STRING) {
			continue;
		}

		ret = rnp_locate_key(pffi->ffi, "fingerprint", Z_STRVAL_P(current_keyfp), &kh);

		if (ret == RNP_SUCCESS) {
			ret = rnp_op_sign_add_signature(sign, kh, NULL);
		}

		rnp_key_handle_destroy(kh);

		if (ret != RNP_SUCCESS) {
			goto done;
		}
	}

	if ((ret = rnp_op_sign_execute(sign)) != RNP_SUCCESS) {
		goto done;
	}

	/* return signature data as a PHP string */
	ret = rnp_output_memory_get_buf(mem_output, &sig_buf, &sig_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)sig_buf, sig_len);
	}

done:
	(void) rnp_op_sign_destroy(sign);
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

static rnp_result_t php_rnp_fill_verify_retval(zval *return_value,
					       rnp_op_verify_t verify,
					       rnp_result_t verify_result,
					       bool file_info)
{
	zval signatures;
	rnp_result_t ret = RNP_ERROR_VERIFICATION_FAILED;
	char *prt_mode = NULL;
	char *prt_cipher = NULL;
	bool valid_intgr = false;
	size_t sigcount = 0;
	size_t i;

	if ((ret = rnp_op_verify_get_signature_count(verify, &sigcount)) || !sigcount) {
		ret = RNP_ERROR_NO_SIGNATURES_FOUND;
		goto done;
	}

	array_init(return_value);
	add_assoc_string(return_value, "verification_status", rnp_result_to_string(verify_result));

	if (file_info) {
		char *file_name = NULL;
		uint32_t file_mtime = 0;

		if ((ret = rnp_op_verify_get_file_info(verify, &file_name, &file_mtime))) {
			goto done;
		}

		add_assoc_string(return_value, "file_name", file_name ? file_name : "");
		rnp_buffer_destroy(file_name);
		add_assoc_long(return_value, "file_mtime", file_mtime);
	}

	if ((ret = rnp_op_verify_get_protection_info(verify, &prt_mode, &prt_cipher, &valid_intgr))) {
		goto done;
	}
	add_assoc_string(return_value, "mode", prt_mode);
	rnp_buffer_destroy(prt_mode);
	add_assoc_string(return_value, "cipher", prt_cipher);
	rnp_buffer_destroy(prt_cipher);
	add_assoc_bool(return_value, "valid_integrity", valid_intgr);

	array_init_size(&signatures, sigcount);

	for (i = 0; i < sigcount; i++) {
		rnp_op_verify_signature_t sig = NULL;
		char *hash = NULL;
		char *key_fp = NULL;
		rnp_key_handle_t key = NULL;
		rnp_signature_handle_t sighnd = NULL;
		char *sigtype = NULL;
		uint32_t creation;
		uint32_t expiration;
		zval sig_array_item;

		array_init(&sig_array_item);
		add_index_zval(&signatures, i, &sig_array_item);

		if ((ret = rnp_op_verify_get_signature_at(verify, i, &sig))) {
			goto done;
		}
		add_assoc_string(&sig_array_item, "verification_status", rnp_result_to_string(rnp_op_verify_signature_get_status(sig)));

		if ((ret = rnp_op_verify_signature_get_times(sig, &creation, &expiration))) {
			goto done;
		}
		add_assoc_long(&sig_array_item, "creation_time", creation);
		add_assoc_long(&sig_array_item, "expiration_time", expiration);

		if ((ret = rnp_op_verify_signature_get_hash(sig, &hash))) {
			goto done;
		}
		add_assoc_string(&sig_array_item, "hash", hash);
		rnp_buffer_destroy(hash);

		if ((ret = rnp_op_verify_signature_get_key(sig, &key))) {
			add_assoc_string(&sig_array_item, "signing_key", "Not found");
			goto skip_key;
		}
		if ((ret = rnp_key_get_fprint(key, &key_fp))) {
			rnp_key_handle_destroy(key);
			goto done;
		}
		add_assoc_string(&sig_array_item, "signing_key", key_fp);
		rnp_key_handle_destroy(key);
		rnp_buffer_destroy(key_fp);
skip_key:
		if ((ret = rnp_op_verify_signature_get_handle(sig, &sighnd))) {
			goto done;
		}

		if ((ret = rnp_signature_get_type(sighnd, &sigtype))) {
			rnp_signature_handle_destroy(sighnd);
			goto done;
		}
		add_assoc_string(&sig_array_item, "signature_type", sigtype);
		rnp_buffer_destroy(sigtype);
		rnp_signature_handle_destroy(sighnd);
	}

	add_assoc_zval(return_value, "signatures", &signatures);

done:
	return ret;
}

PHP_FUNCTION(rnp_op_verify)
{
	zval *zffi;
	zend_string *data;

	rnp_result_t ret = RNP_ERROR_VERIFICATION_FAILED;
	rnp_result_t verify_result = RNP_ERROR_VERIFICATION_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t null_output = NULL;
	rnp_op_verify_t verify = NULL;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(data), ZSTR_LEN(data), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_null(&null_output);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_verify_create(&verify, pffi->ffi, mem_input, null_output))) {
		goto done;
	}

	verify_result = rnp_op_verify_execute(verify);

	ret = php_rnp_fill_verify_retval(return_value, verify, verify_result, true);
done:
	(void) rnp_op_verify_destroy(verify);
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(null_output);

	if (ret != RNP_SUCCESS) {
		zval_ptr_dtor(return_value);
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_op_verify_detached)
{
	zval *zffi;
	zend_string *data;
	zend_string *signature;

	rnp_result_t   ret = RNP_ERROR_VERIFICATION_FAILED;
	rnp_result_t verify_result = RNP_ERROR_VERIFICATION_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_data_input = NULL;
	rnp_input_t mem_sig_input = NULL;
	rnp_op_verify_t verify = NULL;
	size_t sigcount = 0;
	size_t i;

	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(data)
		Z_PARAM_STR(signature)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_data_input, (uint8_t *)ZSTR_VAL(data), ZSTR_LEN(data), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_input_from_memory(&mem_sig_input, (uint8_t *)ZSTR_VAL(signature), ZSTR_LEN(signature), false);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_verify_detached_create(&verify, pffi->ffi, mem_data_input, mem_sig_input))) {
		goto done;
	}

	verify_result = rnp_op_verify_execute(verify);

	ret = php_rnp_fill_verify_retval(return_value, verify, verify_result, false);
done:
	(void) rnp_op_verify_destroy(verify);
	(void) rnp_input_destroy(mem_data_input);
	(void) rnp_input_destroy(mem_sig_input);

	if (ret != RNP_SUCCESS) {
		zval_ptr_dtor(return_value);
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_op_encrypt)
{
	zval *zffi;
	zend_string *message;
	zval *keysfp;
	zval *options = NULL;
	zval *current_keyfp;

	rnp_result_t   ret = RNP_ERROR_GENERIC;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t mem_output = NULL;
	rnp_op_encrypt_t encrypt = NULL;
	uint8_t *encrypted_buf;
	size_t   encrypted_len;
	bool add_signature = false;
	const char *password = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(message)
		Z_PARAM_ARRAY(keysfp)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(message), ZSTR_LEN(message), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_op_encrypt_create(&encrypt, pffi->ffi, mem_input, mem_output))) {
		goto done;
	}
	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;
		const char *compression_alg = NULL;
		int compression_level = 0;

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "compression_alg", sizeof("compression_alg") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			compression_alg = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "compression_level", sizeof("compression_level") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			compression_level = Z_LVAL_P(opt);
		}

		if (compression_alg && compression_level) {
			if ((ret = rnp_op_encrypt_set_compression(encrypt, compression_alg, compression_level))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "armor", sizeof("armor")  - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_TRUE) {
			if ((ret = rnp_op_encrypt_set_armor(encrypt, true))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "add_signature", sizeof("add_signature")  - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_TRUE) {
			add_signature = true;
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_encrypt_set_hash(encrypt, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "creation_time", sizeof("creation_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_encrypt_set_creation_time(encrypt, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "expiration_time", sizeof("expiration_time") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_encrypt_set_expiration_time(encrypt, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "password", sizeof("password") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_encrypt_add_password(encrypt, Z_STRVAL_P(opt), NULL, 0, NULL))) {
				goto done;
			}
			password = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "cipher", sizeof("cipher") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_encrypt_set_cipher(encrypt, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "aead", sizeof("aead") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_encrypt_set_aead(encrypt, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "aead_bits", sizeof("aead_bits") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_encrypt_set_aead_bits(encrypt, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "flags", sizeof("flags") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_encrypt_set_flags(encrypt, Z_LVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "file_name", sizeof("file_name") - 1)) != NULL &&
		        Z_TYPE_P(opt) == IS_STRING) {
			if ((ret = rnp_op_encrypt_set_file_name(encrypt, Z_STRVAL_P(opt)))) {
				goto done;
			}
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "file_mtime", sizeof("file_mtime") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_LONG) {
			if ((ret = rnp_op_encrypt_set_file_mtime(encrypt, Z_LVAL_P(opt)))) {
				goto done;
			}
		}
	}

	/* iterate over keysfp array */
	if (zend_hash_num_elements(Z_ARRVAL_P(keysfp)) == 0) {
		if (password) {
			/* Array with recipient keys is empty, but password is set,
			 * so encryption operation still can be executed.
			 * */
			goto skip_recipients;
		}
		ret = RNP_ERROR_BAD_PARAMETERS;
		goto done;
	}
	zend_hash_internal_pointer_reset(Z_ARRVAL_P(keysfp));
	while ((current_keyfp = zend_hash_get_current_data(Z_ARRVAL_P(keysfp)))) {
		zend_hash_move_forward(Z_ARRVAL_P(keysfp));

		rnp_key_handle_t kh = NULL;

		if (Z_TYPE_P(current_keyfp) != IS_STRING) {
			continue;
		}

		ret = rnp_locate_key(pffi->ffi, "fingerprint", Z_STRVAL_P(current_keyfp), &kh);

		if (ret == RNP_SUCCESS) {
			ret = rnp_op_encrypt_add_recipient(encrypt, kh);
		}

		if (ret == RNP_SUCCESS && add_signature) {
			ret = rnp_op_encrypt_add_signature(encrypt, kh, NULL);
		}

		rnp_key_handle_destroy(kh);

		if (ret != RNP_SUCCESS) {
			goto done;
		}
	}
skip_recipients:

	if ((ret = rnp_op_encrypt_execute(encrypt)) != RNP_SUCCESS) {
		goto done;
	}

	/* return encrypted data as a PHP string */
	ret = rnp_output_memory_get_buf(mem_output, &encrypted_buf, &encrypted_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)encrypted_buf, encrypted_len);
	}

done:
	(void) rnp_op_encrypt_destroy(encrypt);
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_decrypt)
{
	zval *zffi;
	zend_string *input;

	rnp_result_t   ret = RNP_ERROR_DECRYPT_FAILED;
	php_rnp_ffi_t *pffi;
	rnp_input_t mem_input = NULL;
	rnp_output_t mem_output = NULL;

	uint8_t *decrypted_buf;
	size_t   decrypted_len;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(input)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);
	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if ((ret = rnp_decrypt(pffi->ffi, mem_input, mem_output)) != RNP_SUCCESS) {
		goto done;
	}

	/* return decrypted data as a PHP string */
	ret = rnp_output_memory_get_buf(mem_output, &decrypted_buf, &decrypted_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)decrypted_buf, decrypted_len);
	}
done:
	(void) rnp_input_destroy(mem_input);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_locate_key)
{
	zval *zffi;
	zend_string *identifier_type;
	zend_string *identifier;

	rnp_result_t     ret;
	php_rnp_ffi_t   *pffi;
	rnp_key_handle_t kh = NULL;
	char            *fprint = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(identifier_type)
		Z_PARAM_STR(identifier)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, ZSTR_VAL(identifier_type), ZSTR_VAL(identifier), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	if ((ret = rnp_key_get_fprint(kh, &fprint))) {
		rnp_key_handle_destroy(kh);
		RETURN_FALSE;
	}

	ZVAL_STRINGL(return_value, fprint, strlen(fprint));

	rnp_buffer_destroy(fprint);
	rnp_key_handle_destroy(kh);
}

PHP_FUNCTION(rnp_list_keys)
{
	zval *zffi;
	zend_string *identifier_type;

	rnp_result_t              ret;
	php_rnp_ffi_t            *pffi;
	rnp_key_handle_t          kh = NULL;
	rnp_identifier_iterator_t it = NULL;
	char                     *fprint = NULL;
	const char               *identifier = NULL;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(identifier_type)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_identifier_iterator_create(pffi->ffi, &it, ZSTR_VAL(identifier_type));

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	array_init(return_value);

	while ((ret = rnp_identifier_iterator_next(it, &identifier)) == RNP_SUCCESS) {
		if (!identifier) {
			break;
		}

		ret = rnp_locate_key(pffi->ffi, ZSTR_VAL(identifier_type), identifier, &kh);

		if (ret != RNP_SUCCESS || !kh) {
			goto done;
		}

		ret = rnp_key_get_fprint(kh, &fprint);

		if (ret != RNP_SUCCESS) {
			rnp_key_handle_destroy(kh);
			goto done;
		}

		add_assoc_string(return_value, identifier, fprint);

		rnp_buffer_destroy(fprint);
		rnp_key_handle_destroy(kh);
	}

done:
	rnp_identifier_iterator_destroy(it);
	if (ret != RNP_SUCCESS) {
		zval_ptr_dtor(return_value);
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_key_get_info)
{
	zval *zffi;
	zend_string *key_fp;

	rnp_result_t              ret;
	php_rnp_ffi_t            *pffi;
	rnp_key_handle_t          kh = NULL;
	bool                      boolval = false;
	char                     *strval = NULL;
	char                     *fprint = NULL;
	uint32_t                  val32;
	uint64_t                  val64;
	zval subkeys;
	zval uids;

	ZEND_PARSE_PARAMETERS_START(2, 2);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	array_init(return_value);

	if ((ret = rnp_key_is_primary(kh, &boolval))) {
		goto done;
	}
	if (boolval) {
		size_t count = 0;
		size_t i;

		/* uid-s*/
		ret = rnp_key_get_uid_count(kh, &count);
		if (ret != RNP_SUCCESS) {
			goto done;
		}
		array_init_size(&uids, count);

		for (i = 0; i < count; i++) {
			char *uid_str = NULL;

			ret = rnp_key_get_uid_at(kh, i, &uid_str);

			if (ret != RNP_SUCCESS) {
				continue;
			}

			add_index_string(&uids, i, uid_str);

			rnp_buffer_destroy(uid_str);
		}

		add_assoc_zval(return_value, "uids", &uids);

		/* subkeys */
		ret = rnp_key_get_subkey_count(kh, &count);
		if (ret != RNP_SUCCESS) {
			goto done;
		}
		array_init_size(&subkeys, count);

		for (i = 0; i < count; i++) {
			rnp_key_handle_t sub_kh = NULL;

			ret = rnp_key_get_subkey_at(kh, i, &sub_kh);

			if (ret != RNP_SUCCESS) {
				continue;
			}

			ret = rnp_key_get_fprint(sub_kh, &fprint);

			if (ret != RNP_SUCCESS) {
				rnp_key_handle_destroy(sub_kh);
				continue;
			}

			add_index_string(&subkeys, i, fprint);

			rnp_key_handle_destroy(sub_kh);
			rnp_buffer_destroy(fprint);
		}

		add_assoc_zval(return_value, "subkeys", &subkeys);
	}

	add_assoc_bool(return_value, "is_primary", boolval);


	if ((ret = rnp_key_is_sub(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "is_sub", boolval);

	if ((ret = rnp_key_is_valid(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "is_valid", boolval);

	if ((ret = rnp_key_is_revoked(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "is_revoked", boolval);
	if (boolval) {
		if ((ret = rnp_key_is_superseded(kh, &boolval))) {
			goto done;
		}
		add_assoc_bool(return_value, "is_superseded", boolval);

		if ((ret = rnp_key_is_compromised(kh, &boolval))) {
			goto done;
		}
		add_assoc_bool(return_value, "is_compromised", boolval);

		if ((ret = rnp_key_is_retired(kh, &boolval))) {
			goto done;
		}
		add_assoc_bool(return_value, "is_retired", boolval);
	}

	if ((ret = rnp_key_is_expired(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "is_expired", boolval);

	if ((ret = rnp_key_have_secret(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "have_secret", boolval);
	if (boolval) {
		if ((ret = rnp_key_is_locked(kh, &boolval))) {
			goto done;
		}
		add_assoc_bool(return_value, "is_locked", boolval);

		if ((ret = rnp_key_is_protected(kh, &boolval))) {
			goto done;
		}
		add_assoc_bool(return_value, "is_protected", boolval);
	}

	if ((ret = rnp_key_have_public(kh, &boolval))) {
		goto done;
	}
	add_assoc_bool(return_value, "have_public", boolval);

#ifdef ZEND_ENABLE_ZVAL_LONG64
	if ((ret = rnp_key_valid_till64(kh, &val64))) {
		goto done;
	}
	add_assoc_long(return_value, "valid_till", (zend_long)val64);
#else
	if ((ret = rnp_key_valid_till(kh, &val32))) {
		goto done;
	}
	add_assoc_long(return_value, "valid_till", (zend_long)val32);
#endif

	if ((ret = rnp_key_get_bits(kh, &val32))) {
		goto done;
	}
	add_assoc_long(return_value, "bits", (zend_long)val32);

	if ((ret = rnp_key_get_alg(kh, &strval))) {
		goto done;
	}
	add_assoc_string(return_value, "alg", strval);
	rnp_buffer_destroy(strval);
done:
	if (ret != RNP_SUCCESS) {
		zval_ptr_dtor(return_value);
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_key_export)
{
	zval *zffi;
	zend_string *key_fp;
	zend_long flags;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;
	rnp_output_t mem_output = NULL;
	rnp_key_handle_t kh = NULL;

	uint8_t *exported_buf;
	size_t   exported_len;

	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	ret = rnp_key_export(kh, mem_output, flags);

	if (ret != RNP_SUCCESS) {
		goto done;
	}

	ret = rnp_output_memory_get_buf(mem_output, &exported_buf, &exported_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)exported_buf, exported_len);
	}
done:
	(void) rnp_key_handle_destroy(kh);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_key_export_autocrypt)
{
	zval *zffi;
	zend_string *key_fp;
	zend_string *subkey_fp;
	zend_string *uid;
	zend_long flags;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;
	rnp_output_t mem_output = NULL;
	rnp_key_handle_t kh = NULL;
	rnp_key_handle_t subkh = NULL;
	const char *uid_str = NULL;

	uint8_t *exported_buf;
	size_t   exported_len;

	ZEND_PARSE_PARAMETERS_START(5, 5);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
		Z_PARAM_STR(subkey_fp)
		Z_PARAM_STR(uid)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	if (ZSTR_LEN(subkey_fp) > 0) {
		ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(subkey_fp), &subkh);
		if (ret != RNP_SUCCESS) {
			goto done;
		}
	}

	if (ZSTR_LEN(uid) > 0) {
		uid_str = ZSTR_VAL(uid);
	}

	ret = rnp_key_export_autocrypt(kh, subkh, uid_str, mem_output, flags);

	if (ret != RNP_SUCCESS) {
		goto done;
	}

	ret = rnp_output_memory_get_buf(mem_output, &exported_buf, &exported_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)exported_buf, exported_len);
	}
done:
	(void) rnp_key_handle_destroy(kh);
	(void) rnp_key_handle_destroy(subkh);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_import_keys)
{
	zval *zffi;
	zend_string *input;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_input_t mem_input;
	char *results = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(input)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_import_keys(pffi->ffi, mem_input, flags, &results);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRING(return_value, results);
		rnp_buffer_destroy(results);
	}

	(void) rnp_input_destroy(mem_input);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_key_remove)
{
	zval *zffi;
	zend_string *key_fp;
	zend_long flags;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;
	rnp_key_handle_t kh = NULL;


	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	ret = rnp_key_remove(kh, flags);

	(void) rnp_key_handle_destroy(kh);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_key_revoke)
{
	zval *zffi;
	zend_string *key_fp;
	zend_long flags;
	zval *options = NULL;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;
	rnp_key_handle_t kh = NULL;
	const char *hash = NULL;
	const char *code = NULL;
	const char *reason = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
		Z_PARAM_LONG(flags)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			hash = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "code", sizeof("code") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			code = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "reason", sizeof("reason") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			reason = Z_STRVAL_P(opt);
		}
	}

	ret = rnp_key_revoke(kh, flags, hash, code, reason);

	(void) rnp_key_handle_destroy(kh);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
}

PHP_FUNCTION(rnp_key_export_revocation)
{
	zval *zffi;
	zend_string *key_fp;
	zend_long flags;
	zval *options = NULL;

	rnp_result_t   ret;
	php_rnp_ffi_t *pffi;
	rnp_key_handle_t kh = NULL;
	rnp_output_t mem_output = NULL;
	const char *hash = NULL;
	const char *code = NULL;
	const char *reason = NULL;

	uint8_t *exported_buf;
	size_t   exported_len;

	ZEND_PARSE_PARAMETERS_START(3, 4);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(key_fp)
		Z_PARAM_LONG(flags)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(options)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_locate_key(pffi->ffi, "fingerprint", ZSTR_VAL(key_fp), &kh);

	if (ret != RNP_SUCCESS || !kh) {
		RETURN_FALSE;
	}

	ret = rnp_output_to_memory(&mem_output, 0);
	if (ret != RNP_SUCCESS) {
		goto done;
	}

	/* apply options*/
	if (ZEND_NUM_ARGS() > 3 && options && Z_TYPE_P(options) == IS_ARRAY) {
		zval *opt;

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "hash", sizeof("hash") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			hash = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "code", sizeof("code") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			code = Z_STRVAL_P(opt);
		}

		if ((opt = zend_hash_str_find(Z_ARRVAL_P(options), "reason", sizeof("reason") - 1)) != NULL &&
			Z_TYPE_P(opt) == IS_STRING) {
			reason = Z_STRVAL_P(opt);
		}
	}

	ret = rnp_key_export_revocation(kh, mem_output, flags, hash, code, reason);

	if (ret != RNP_SUCCESS) {
		goto done;
	}

	ret = rnp_output_memory_get_buf(mem_output, &exported_buf, &exported_len, false);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRINGL(return_value, (char *)exported_buf, exported_len);
	}
done:
	(void) rnp_key_handle_destroy(kh);
	(void) rnp_output_destroy(mem_output);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
}

PHP_FUNCTION(rnp_import_signatures)
{
	zval *zffi;
	zend_string *input;
	zend_long flags;

	php_rnp_ffi_t *pffi;
	rnp_result_t ret;
	rnp_input_t mem_input;
	char *results = NULL;

	ZEND_PARSE_PARAMETERS_START(3, 3);
		Z_PARAM_OBJECT_OF_CLASS(zffi, rnp_ffi_t_ce)
		Z_PARAM_STR(input)
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	pffi = Z_FFI_P(zffi);

	ret = rnp_input_from_memory(&mem_input, (uint8_t *)ZSTR_VAL(input), ZSTR_LEN(input), false);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}

	ret = rnp_import_signatures(pffi->ffi, mem_input, flags, &results);

	if (ret == RNP_SUCCESS) {
		ZVAL_STRING(return_value, results);
		rnp_buffer_destroy(results);
	}

	(void) rnp_input_destroy(mem_input);

	if (ret != RNP_SUCCESS) {
		RETURN_FALSE;
	}
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
	php_info_print_table_row(2, "rnp extension version", PHP_RNP_VERSION);
	php_info_print_table_row(2, "rnp library version", rnp_version_string());
	php_info_print_table_end();
}
/* }}} */


zend_class_entry *rnp_ffi_t_ce;
static zend_object_handlers rnp_object_handlers;

static zend_object *rnp_create_object(zend_class_entry *class_type)
{
	php_rnp_ffi_t *intern = zend_object_alloc(sizeof(php_rnp_ffi_t), class_type);
	intern->pass_provider_is_set = false;

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

	REGISTER_LONG_CONSTANT("RNP_ENCRYPT_NOWRAP", RNP_ENCRYPT_NOWRAP, CONST_CS | CONST_PERSISTENT);

	REGISTER_STRING_CONSTANT("RNP_KEYSTORE_GPG", RNP_KEYSTORE_GPG, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_KEYSTORE_KBX", RNP_KEYSTORE_KBX, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("RNP_KEYSTORE_G10", RNP_KEYSTORE_G10, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("RNP_KEY_EXPORT_ARMORED", RNP_KEY_EXPORT_ARMORED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_EXPORT_PUBLIC", RNP_KEY_EXPORT_PUBLIC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_EXPORT_SECRET", RNP_KEY_EXPORT_SECRET, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_EXPORT_SUBKEYS", RNP_KEY_EXPORT_SUBKEYS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_EXPORT_BASE64", RNP_KEY_EXPORT_BASE64, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("RNP_KEY_REMOVE_PUBLIC", RNP_KEY_REMOVE_PUBLIC, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_REMOVE_SECRET", RNP_KEY_REMOVE_SECRET, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RNP_KEY_REMOVE_SUBKEYS", RNP_KEY_REMOVE_SUBKEYS, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;
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
