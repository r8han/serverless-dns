#!/bin/sh
# Linux x86-64 release tools. Verify the entire archive before extracting a
# single named executable to a private directory, never sudo or curl | sh.
set -eu
name=$1
dest=$2
case "$name" in
  gh) repo=cli/cli; ver=2.105.0; file=gh_2.105.0_linux_amd64.tar.gz; digest=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f;;
  viceroy) repo=fastly/Viceroy; ver=0.22.0; file=viceroy_v0.22.0_linux-amd64.tar.gz; digest=03f66f27275e8adc0c1857c4f571bd6f5ae997e38cc43760b19c6840a92b298d;;
  flyctl) repo=superfly/flyctl; ver=0.5.12; file=flyctl_0.5.12_Linux_x86_64.tar.gz; digest=41e3194dde966648e0943c13230c7a9c9874a7a235ac507dbf4ad4f575fa54fc;;
  syft) repo=anchore/syft; ver=1.57.2; file=syft_1.57.2_linux_amd64.tar.gz; digest=ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b;;
  grype) repo=anchore/grype; ver=0.122.1; file=grype_0.122.1_linux_amd64.tar.gz; digest=f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538;;
  weval) repo=bytecodealliance/weval; ver=0.5.1; file=weval-v0.5.1-x86_64-linux.tar.xz; digest=ed36a23a4e7f5fdd72659c68647427ab9aee137278e2439bddd813de7db1e2c8;;
  *) exit 2;;
esac
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --max-time 120 "https://github.com/$repo/releases/download/v$ver/$file" -o "$tmp/archive"
printf '%s  %s\n' "$digest" "$tmp/archive" | sha256sum -c - >&2
member=$(tar tf "$tmp/archive" | grep -E "(^|/)$name\$")
mkdir -p "$dest"
tar xOf "$tmp/archive" "$member" > "$dest/$name"
chmod 755 "$dest/$name"
