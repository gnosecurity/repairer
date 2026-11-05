#!/bin/bash
# images.sh RIG: fetch the rig's cloud images into $RIG/images and check each
# against its vendor's checksums: Ubuntu's SHA256SUMS signed with the Ubuntu
# cloud image key (gpgv), Debian's SHA512SUMS over HTTPS from cloud.debian.org.
# Prints the lines for scripts/rig/images.tsv, which pins each image by
# sha256; rig.sh boots only an image whose sha256 is pinned there. Then it
# fetches the packages scripts/rig/debs.tsv pins into $RIG/debs and checks
# each against its pinned sha256.
set -euo pipefail
R=${1:?the rig directory}
mkdir -p "$R/images"
cd "$R/images"
ubuntu() { # release
  local rel=$1 f=ubuntu-$1-server-cloudimg-amd64.img base=https://cloud-images.ubuntu.com/releases/$1/release
  curl -sfL -o "SHA256SUMS-$rel" "$base/SHA256SUMS"
  curl -sfL -o "SHA256SUMS-$rel.gpg" "$base/SHA256SUMS.gpg"
  gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg "SHA256SUMS-$rel.gpg" "SHA256SUMS-$rel" 2>/dev/null \
    || { echo "images.sh: Ubuntu $rel's SHA256SUMS signature doesn't verify" >&2; exit 1; }
  [ -f "$f" ] || curl -sfL -o "$f" "$base/$f"
  grep " \*$f\$" "SHA256SUMS-$rel" | sed 's/ \*/  /' | sha256sum -c --quiet - || { echo "images.sh: $f doesn't match" >&2; exit 1; }
  printf 'ubuntu %s\t%s\t%s\t%s\n' "$rel" "$f" "$(sha256sum "$f" | cut -d' ' -f1)" "$base/$f"
}
debian() { # version codename
  local ver=$1 code=$2 f=debian-$1-genericcloud-amd64.qcow2 base=https://cloud.debian.org/images/cloud/$2/latest
  curl -sfL -o "SHA512SUMS-$code" "$base/SHA512SUMS"
  [ -f "$f" ] || curl -sfL -o "$f" "$base/$f"
  grep "  $f\$" "SHA512SUMS-$code" | sha512sum -c --quiet - || { echo "images.sh: $f doesn't match" >&2; exit 1; }
  printf 'debian %s\t%s\t%s\t%s\n' "$ver" "$f" "$(sha256sum "$f" | cut -d' ' -f1)" "$base/$f"
}
ubuntu 22.04
ubuntu 24.04
ubuntu 26.04
debian 12 bookworm
debian 13 trixie
mkdir -p "$R/debs"
grep -v '^#' "$(dirname "$(readlink -f "$0")")/debs.tsv" | while IFS=$'\t' read -r sys f sum url; do
  [ -f "$R/debs/$f" ] || curl -sfL -o "$R/debs/$f" "$url"
  [ "$(sha256sum "$R/debs/$f" | cut -d' ' -f1)" = "$sum" ] || { echo "images.sh: $f isn't the pinned package" >&2; exit 1; }
done
