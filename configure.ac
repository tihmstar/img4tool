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

# Checks for libraries.
PKG_CHECK_MODULES(libplist, libplist >= 1.0)
PKG_CHECK_MODULES(libcrypto, libcrypto >= 1.0)


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

AC_CONFIG_FILES([Makefile img4tool/Makefile])
AC_OUTPUT
