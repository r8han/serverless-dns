#!/bin/sh
# Linux x86-64 release tools. Verify the entire archive before extracting a
# single named executable to a private directory, never sudo or curl | sh.
set -eu
name=$1
dest=$2
case "$name" in
  gh) repo=cli/cli; ver=2.105.0; file=gh_2.105.0_linux_amd64.tar.gz; digest=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f;;
  syft) repo=anchore/syft; ver=1.57.2; file=syft_1.57.2_linux_amd64.tar.gz; digest=ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b;;
  grype) repo=anchore/grype; ver=0.122.1; file=grype_0.122.1_linux_amd64.tar.gz; digest=f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538;;
  *) exit 2;;
esac
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --max-time 120 "https://github.com/$repo/releases/download/v$ver/$file" -o "$tmp/archive"
printf '%s  %s\n' "$digest" "$tmp/archive" | sha256sum -c - >&2
member=$(tar tf "$tmp/archive" | grep -E "(^|/)$name\$")
mkdir -p "$dest"
tar xOf "$tmp/archive" "$member" > "$dest/$name"
chmod 755 "$dest/$name"
