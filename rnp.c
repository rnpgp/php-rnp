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

	if (rnp_supported_features(ZSTR_VAL(type), &result) != RNP_SUCCESS)
	{
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
		Z_PARAM_STR(pub_format);
		Z_PARAM_STR(sec_format);
	ZEND_PARSE_PARAMETERS_END();

	if (rnp_ffi_create(&ffi, ZSTR_VAL(pub_format), ZSTR_VAL(sec_format)) != RNP_SUCCESS)
	{
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
        if (!pffi->ffi)
	{
		zend_throw_error(NULL, "%s(): Attempt to destroy already destroyed FFI object!", get_active_function_name());
		RETURN_THROWS();
	}

	rnp_ffi_destroy(pffi->ffi);
	pffi->ffi = NULL;
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

static zend_object *rnp_create_object(zend_class_entry *class_type) {
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
	rnp_ffi_t_ce = register_class_rnp_ffi_t();
	rnp_ffi_t_ce->create_object = rnp_create_object;

	memcpy(&rnp_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
        rnp_object_handlers.offset = XtOffsetOf(php_rnp_ffi_t, std);
	rnp_object_handlers.clone_obj = NULL;
	rnp_object_handlers.free_obj = rnp_free_obj;
	rnp_object_handlers.get_constructor = rnp_get_constructor;
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
