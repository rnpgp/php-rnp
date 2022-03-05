PHP_ARG_WITH([rnp],
   [for rnp support],
   [AS_HELP_STRING([--with-rnp],
     [Include rnp support])])



if test "$PHP_RNP" != "no"; then

   PKG_CHECK_MODULES([LIBRNP], [librnp])
   PHP_EVAL_INCLINE($LIBRNP_CFLAGS)
   PHP_EVAL_LIBLINE($LIBRNP_LIBS, RNP_SHARED_LIBADD)

  PHP_SUBST(RNP_SHARED_LIBADD)

  AC_DEFINE(HAVE_RNP, 1, [ Have rnp support ])

  PHP_NEW_EXTENSION(rnp, rnp.c, $ext_shared)
fi
