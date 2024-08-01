#!/bin/bash
set -xe
ECR_URL="${ECR_URL:-local}"
python3 -m pip install toml --user
VERSION=$(python3 -c "import toml; import sys; values = toml.loads(sys.stdin.read()); print(values['package']['version'])" < Cargo.toml)
URL="$ECR_URL/qdrant:v$VERSION-$QDRANT_BRANCH-$BUILD_ID"
docker build --no-cache -t "$URL" .
if [ "$ECR_URL" != "local" ];then
    docker push "$URL"
fi
