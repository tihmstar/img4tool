#!/usr/bin/env bash
set -euo pipefail

OUT=img4tool-termux-tarball.tar.gz
mkdir -p out
tar -czf out/${OUT} -C dsbug dsbug -C ../tools img4tool-termux/img4tool-termux
echo "Created out/${OUT}" 
