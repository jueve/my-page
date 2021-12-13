#!/bin/bash
set -euxo pipefail
cd $(dirname "$0")

curl -fsSL https://deno.land/x/install/install.sh | sh
export DENO_INSTALL="/opt/buildhome/.deno"
export PATH="$DENO_INSTALL/bin:$PATH"

deno run -A https://deno.land/x/lume/install.ts
export PATH="/opt/buildhome/.deno/bin:$PATH"
lume

exit 0
