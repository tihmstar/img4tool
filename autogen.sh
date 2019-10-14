#!/bin/bash

aclocal -I m4
autoconf
autoheader
automake --add-missing
autoreconf -i
./configure "$@"
