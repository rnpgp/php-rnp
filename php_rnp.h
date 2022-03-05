/* rnp extension for PHP */

#ifndef PHP_RNP_H
# define PHP_RNP_H

extern zend_module_entry rnp_module_entry;
# define phpext_rnp_ptr &rnp_module_entry

# define PHP_RNP_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_RNP)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_RNP_H */
