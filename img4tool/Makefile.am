if OPENSSL
AM_CFLAGS = $(libcrypto_CFLAGS)
AM_LDFLAGS = $(libcrypto_LIBS)
else
AM_CFLAGS =
AM_LDFLAGS =
endif

if NOMAIN
noinst_LTLIBRARIES = libimg4tool.la
libimg4tool_la_SOURCES = img4tool.c img4.c lzssdec.c
libimg4tool_la_CFLAGS = $(AM_CFLAGS) -DIMG4TOOL_NOMAIN
libimg4tool_la_LIBADD = $(AM_LDFLAGS)
else
AM_LDFLAGS += $(libplist_LIBS) $(libplistmm_LDFLAGS)
bin_PROGRAMS    = img4tool
img4tool_CFLAGS = $(AM_CFLAGS)
img4tool_LDADD = $(AM_LDFLAGS)
img4tool_SOURCES = img4tool.c img4.c lzssdec.c
endif
