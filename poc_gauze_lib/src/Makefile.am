# Compiler flags from pkg-config
AM_CPPFLAGS = $(PGAUZE_CFLAGS) -I$(PMACCT_INCLUDE_DIR) -I/usr/local/include/ndpi/
AM_LDFLAGS  = $(PGAUZE_LIBS)

ACLOCAL_AMFLAGS = -I m4

# Build shared library libfoo.la
lib_LTLIBRARIES = libparse.la
libparse_la_SOURCES = parsing.c
libparse_la_LDFLAGS = -version-info 1:0:0 -no-undefined -module -avoid-version -export-dynamic
libparse_la_LIBADD = -l:libpmacct_gauze_lib.a
