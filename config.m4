PHP_ARG_WITH([rnp],
   [for rnp support],
   [AS_HELP_STRING([--with-rnp],
     [Include rnp support])])



if test "$PHP_RNP" != "no"; then

   dnl librnp 0.18.1 is the security baseline (fixes CVE-2025-13470)
   PKG_CHECK_MODULES([LIBRNP], [librnp >= 0.18.1])
   PHP_EVAL_INCLINE($LIBRNP_CFLAGS)
   PHP_EVAL_LIBLINE($LIBRNP_LIBS, RNP_SHARED_LIBADD)

  PHP_SUBST(RNP_SHARED_LIBADD)

  AC_DEFINE(HAVE_RNP, 1, [ Have rnp support ])

  PHP_NEW_EXTENSION(rnp, rnp.c, $ext_shared)
fi
