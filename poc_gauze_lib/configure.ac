AC_INIT([libparse], [1.0], [you@example.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/parsing.c])
AC_CONFIG_HEADERS([config.h])


AM_PROG_LIBTOOL
AC_PROG_INSTALL

AC_ENABLE_SHARED
AC_DISABLE_STATIC

# Checks for programs
AC_PROG_CC
LT_INIT  # initialize libtool for shared library support

# Check for pkg-config dependency
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([PGAUZE], [pmacct_gauze_lib >= 0.1])
PKG_CHECK_MODULES([PMACCT], [pmacct])

AC_SUBST([PMACCT_CFLAGS])
AC_SUBST([PMACCT_LIBS])


# Substitute flags for Makefiles
AC_SUBST([PGAUZE_CFLAGS])
AC_SUBST([PGAUZE_LIBS])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT