/* rnp extension for PHP */

#ifndef PHP_RNP_H
# define PHP_RNP_H

#include "php.h"
#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

#ifdef PHP_WIN32
# ifdef PHP_RNP_EXPORTS
#  define PHP_RNP_API __declspec(dllexport)
# else
#  define PHP_RNP_API __declspec(dllimport)
# endif
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_RNP_API __attribute__ ((visibility("default")))
#else
# define PHP_RNP_API
#endif

extern zend_module_entry rnp_module_entry;
# define phpext_rnp_ptr &rnp_module_entry

typedef struct php_rnp_ffi
{
	rnp_ffi_t ffi;
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;
	bool pass_provider_is_set;
	zend_object std;
} php_rnp_ffi_t;

#define Z_FFI_P(zv) \
    ((php_rnp_ffi_t*)((char*)(Z_OBJ_P(zv)) - XtOffsetOf(php_rnp_ffi_t, std)))

static inline php_rnp_ffi_t *rnp_ffi_t_from_obj(zend_object *obj)
{
	return ((php_rnp_ffi_t*)((char*)(obj) - XtOffsetOf(php_rnp_ffi_t, std)));
}

PHP_RNP_API extern zend_class_entry *rnp_ffi_t_ce;

# define PHP_RNP_VERSION "0.2.0"

# if defined(ZTS) && defined(COMPILE_DL_RNP)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_RNP_H */
