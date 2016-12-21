#!/bin/bash

aclocal
autoconf
autoheader
automake --add-missing
./configure "$@"
./setBuildVersion.sh
