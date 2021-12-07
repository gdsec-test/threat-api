#!/bin/bash

set -eu

if [ ! -f GeoLite2-City.mmdb ]; then
    # Pull last free version of GeoLite2 DB from Fedora archives

    echo "Downloading GeoLite2-City_20191217.tar.gz"

    wget -nv https://src.fedoraproject.org/repo/pkgs/geolite2/GeoLite2-City_20191217.tar.gz/sha512/b90d98901a2906465e69c69d9ddc95a4d5945deba683a856bc858229e9a7358acf46b4e73b131c7bd497ce4029848e1431fc0efb8bfdc417bd3241d9965e2dae/GeoLite2-City_20191217.tar.gz

    tar zxf GeoLite2-City_20191217.tar.gz GeoLite2-City_20191217/GeoLite2-City.mmdb

    rm GeoLite2-City_20191217.tar.gz

    mv GeoLite2-City_20191217/GeoLite2-City.mmdb GeoLite2-City.mmdb

    rmdir GeoLite2-City_20191217
fi

env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build
rm -f function.zip
zip -9q function.zip geoip GeoLite2-City.mmdb
