#!/usr/bin/env bash

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# Script to handle exoticisms related to 'docker login' and 'docker push'.
#
# Log in to docker.elastic.co if the namespace eck, eck-ci or eck-snapshots is used
# Log in to gcloud if GCR is used

set -euo pipefail

S3_ECK_DIR=s3://download.elasticsearch.org/downloads/eck
VAULT_AWS_CREDS=secret/cloud-team/cloud-ci/eck-release
access_key=$(vault read -address="$VAULT_ADDR" -field=access-key-id "$VAULT_AWS_CREDS")
export AWS_ACCESS_KEY_ID=$access_key
secret_access_key=$(vault read -address="$VAULT_ADDR" -field=secret-access-key "$VAULT_AWS_CREDS")
export AWS_SECRET_ACCESS_KEY=$secret_access_key
src=elastic-operator-1.2.1
srcsum=$src.sha512
dst="$S3_ECK_DIR/$src"
dstsum="$S3_ECK_DIR/$srcsum"
aws s3 cp "$src" "$dst"
aws s3 cp "$srcsum" "$dstsum"
