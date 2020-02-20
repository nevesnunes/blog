#!/bin/sh

set -eu

url=$1
out=${2:-$(mktemp --suffix .pdf)}

pandoc \
  -o "$out" \
  --pdf-engine=wkhtmltopdf \
  --css '_site/assets/main.css' \
  --css '_site/assets/css/custom.css' \
  --css '_site/assets/css/print.css' \
  "$url"
echo "$out"
