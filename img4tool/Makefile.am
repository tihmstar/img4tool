AM_CFLAGS = $(libplist_CFLAGS) $(libplistmm_CFLAGS) $(libcrypto_CFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(libplistmm_LDFLAGS) $(libcrypto_LIBS)

bin_PROGRAMS    = img4tool_tool
img4tool_tool_CFLAGS = $(AM_CFLAGS)
img4tool_tool_LDADD = $(AM_LDFLAGS)
img4tool_tool_SOURCES = img4tool.c img4.c
