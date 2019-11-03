AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/include/img4tool $(GLOBAL_CFLAGS) $(libplist_CFLAGS) $(openssl_CFLAGS) $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(openssl_LIBS) $(libgeneral_LIBS)

lib_LTLIBRARIES = libimg4tool.la
bin_PROGRAMS = img4tool

libimg4tool_la_CFLAGS = $(AM_CFLAGS)
libimg4tool_la_CXXFLAGS = $(AM_CXXFLAGS)
libimg4tool_la_LDFLAGS = $(AM_LDFLAGS)
libimg4tool_la_SOURCES = 	ASN1DERElement.cpp \
													lzssdec.c \
													img4tool.cpp

img4tool_CFLAGS = $(AM_CFLAGS)
img4tool_CXXFLAGS = $(AM_CXXFLAGS)
img4tool_LDFLAGS = $(AM_LDFLAGS)
img4tool_LDADD = libimg4tool.la
img4tool_SOURCES = 	main.cpp
