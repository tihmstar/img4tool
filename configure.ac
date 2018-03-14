AC_PREREQ([2.69])
AC_INIT([img4tool], [1.0.0], [tihmstar@gmail.com])
AM_INIT_AUTOMAKE([foreign])


AC_CONFIG_SRCDIR([img4tool/all_img4tool.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
CFLAGS+=" -std=c11"
AC_PROG_INSTALL

CFLAGS+=" -D IMG4TOOL_VERSION_COMMIT_COUNT=\\\"$(git rev-list --count HEAD | tr -d '\n')\\\""
CFLAGS+=" -D IMG4TOOL_VERSION_COMMIT_SHA=\\\"$(git rev-parse HEAD | tr -d '\n')\\\""



# Checks for libraries.

AC_ARG_WITH([openssl],
            [AS_HELP_STRING([--without-openssl],
            [disable openssl (only works w/ apple)])],
          [],
          [with_openssl=yes])

AS_IF([test "x$with_openssl" != xno],
      [PKG_CHECK_MODULES(libcrypto, libcrypto >= 1.0)])

AS_IF([test "x$with_openssl" == xno],
      [AC_DEFINE([IMG4TOOL_NOOPENSSL], [1], [FUCKOFFYOUTRASHFIRE])])

AC_ARG_WITH([lzfse],
            [AS_HELP_STRING([--without-lzfse],
            [disable lzfse decompression support])],
          [],
          [with_lzfse=yes])

AS_IF([test "x$with_lzfse" != xno],
      [
        AC_CHECK_LIB([compression], [compression_decode_buffer],
                     [LDFLAGS+=" -lcompression"
                      AC_DEFINE([HAVE_LIBCOMPRESSION], [], [why doesnt it])
                     ],
          [AC_CHECK_LIB([lzfse], [lzfse_decode_buffer],
                        [LDFLAGS+=" -llzfse"
                         AC_DEFINE([HAVE_LIBLZFSE], [], [do this automatically])],
            [AC_MSG_ERROR([Either libcompression or liblzfse is needed])])
          ]
        )
      ])

AS_IF([test "x$with_lzfse" == xno],
      [AC_DEFINE([IMG4TOOL_NOLZFSE], [], [FUCKYOUAUTOHEADER])])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([memmove memset])

case $CFLAGS in
  *IMG4TOOL_NOMAIN*)
    nomain=true
  ;;
  *)
  ;;
esac

AM_CONDITIONAL(NOMAIN, test x$nomain == xtrue)

AS_IF([test x$nomain != xtrue],
  [PKG_CHECK_MODULES(libplist, libplist >= 1.0)])

AM_CONDITIONAL(OPENSSL, test x$with_openssl == xyes)
AM_CONDITIONAL(LZFSE, test x$with_lzfse == xyes)

AC_CONFIG_FILES([Makefile img4tool/Makefile])
AC_OUTPUT
