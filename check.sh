#!/bin/bash
set -euxo pipefail
cd $(dirname "$0")
PWD=$(pwd)

# Remove metadata
# IMGDIRS=$(find "${PWD}/src/img" -type d)
IMGS=$(find "${PWD}/src/img" -type f)

for IMG in ${IMGS}
do
    echo "${IMG}"
    exiftool -overwrite_original_in_place -all= ${IMG}
done

exit 0