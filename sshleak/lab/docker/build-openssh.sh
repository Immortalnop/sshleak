#!/bin/sh
# Build vanilla OpenSSH portable releases, each verified against a pinned SHA256.
set -eu
cd /build
grep -v '^#' versions.txt | while read -r ver sha; do
  [ -n "$ver" ] || continue
  tarball="openssh-${ver}.tar.gz"
  curl -fsSLO "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${tarball}"
  echo "${sha}  ${tarball}" | sha256sum -c -
  tar xzf "${tarball}"
  cd "openssh-${ver}"
  ./configure --prefix="/opt/openssh-${ver}" --with-privsep-path=/var/empty --with-privsep-user=sshd \
      --without-pam --with-zlib >/dev/null
  make -j"$(nproc)" >/dev/null
  make install-nokeys >/dev/null
  cd /build
  rm -rf "openssh-${ver}" "${tarball}"
  "/opt/openssh-${ver}/bin/ssh" -V
done
