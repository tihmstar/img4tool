AM_CFLAGS = $(libplist_CFLAGS) $(libplistmm_CFLAGS) $(libcrypto_CFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(libplistmm_LDFLAGS) $(libcrypto_LIBS)

if NOMAIN
noinst_LTLIBRARIES = libimg4tool.la
libimg4tool_la_SOURCES = img4tool.c img4.c lzssdec.c
libimg4tool_la_CFLAGS = $(AM_CFLAGS) -DIMG4TOOL_NOMAIN
libimg4tool_la_LIBADD = $(AM_LDFLAGS)
else
bin_PROGRAMS    = img4tool
img4tool_CFLAGS = $(AM_CFLAGS)
img4tool_LDADD = $(AM_LDFLAGS)
img4tool_SOURCES = img4tool.c img4.c lzssdec.c
endif
