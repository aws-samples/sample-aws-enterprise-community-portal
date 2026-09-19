#!/usr/bin/env bash
#
# Deploy the whole portal to one account/region.
#
# Why this script exists
# ---------------------
# The root template references its nested stacks by flat filename under
# ${TemplateBaseUrl}, so every nested template must already live in one S3
# prefix, and any nested template that declares CodeUri must have that CodeUri
# ALREADY REWRITTEN to an s3:// URI — CloudFormation cannot resolve a relative
# path from a template it fetched from S3. That is a two-step job (sam package
# per template, then upload) and it had been done by hand, which is how the
# committed `.deploy-staging/` copies came to exist. Doing it by hand is how you
# get a half-uploaded prefix and a confusing rollback, so it lives here.
#
# Steps:
#   1. sam package  every template that has CodeUri  -> .deploy-staging/
#   2. plain copy   every template that does not     -> .deploy-staging/
#   3. upload .deploy-staging/*.yaml                 -> s3://<bucket>/<prefix>/
#   4. sam deploy the root template (nested stacks resolve from that prefix)
#
# Usage:
#   infra/tools/deploy.sh                       # deploy with recorded params
#   TEMPLATES_ONLY=1 infra/tools/deploy.sh      # stage + upload, no deploy
#
set -euo pipefail

STACK=${STACK:-community-portal-dev}
REGION=${REGION:-us-east-1}
STAGE=${STAGE:-dev}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET=${BUCKET:-community-portal-artifacts-${ACCOUNT}-${REGION}}
PREFIX=${PREFIX:-cp}
STAGING=.deploy-staging

ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
OPS_EMAIL=${OPS_EMAIL:-admin@example.com}
# Becomes ALLOWED_EMAIL_DOMAINS on identity-access. This is the FAIL-SOFT
# FALLBACK, not the live value: SettingsClient reads the real allow-list from
# GET /internal/settings and only drops to this env var when that read fails.
# It must therefore mirror the admin-configured list, or an outage in Settings
# silently narrows who can self-register. It had drifted to `amazon.com` while
# the stored value was `amazon.com,cognizant.com`, so any Settings outage
# blocked cognizant.com registrations (2026-08-28).
# Check before deploying:
#   aws lambda invoke --function-name settings-dev ... GET /settings
#   -> .allowedEmailDomains  must equal this list
ALLOWED_DOMAINS=${ALLOWED_DOMAINS:-example.com}

# Observability gating (both default OFF). Set to true to deploy dashboards /
# Application Signals. When ENABLE_APP_SIGNALS=true you MUST also supply
# APP_SIGNALS_LAYER_ARN (region+runtime-specific ADOT layer), or the instrumented
# functions will fail to start (missing /opt/otel-instrument wrapper).
ENABLE_DASHBOARDS=${ENABLE_DASHBOARDS:-false}
ENABLE_APP_SIGNALS=${ENABLE_APP_SIGNALS:-false}
# Non-empty placeholder so `sam deploy --parameter-overrides` accepts it (empty
# values are rejected). Inert while ENABLE_APP_SIGNALS=false; override with the
# real region/runtime ADOT layer ARN when enabling Application Signals.
APP_SIGNALS_LAYER_ARN=${APP_SIGNALS_LAYER_ARN:-arn:aws:lambda:us-east-1:000000000000:layer:SET_APP_SIGNALS_LAYER_ARN:1}

echo "account=$ACCOUNT region=$REGION stack=$STACK bucket=$BUCKET prefix=$PREFIX"

aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 || {
  echo "creating artifacts bucket $BUCKET"
  aws s3 mb "s3://$BUCKET" --region "$REGION"
}

mkdir -p "$STAGING"

# ---------------------------------------------------------------------------
# Stage the built SPA into the seed Lambda's payload.
#
# The SPA is published by a custom resource (platform/seed/spa_deploy_handler.py)
# that uploads whatever is bundled at ./spa/ inside its own package. That
# directory is git-ignored and populated at deploy time from frontend/dist/, so
# if it is not refreshed here the deploy succeeds and silently republishes the
# PREVIOUS bundle — the stack says UPDATE_COMPLETE, the Lambdas are new, and the
# UI is stale. Caught exactly that way on 2026-08-06.
#
# `rsync --delete` mirrors rather than merges, so a removed or renamed asset does
# not linger in the payload forever. config.json is intentionally included: the
# handler overwrites it with the real API endpoint and Cognito ids after upload,
# so the local dev placeholders never reach the bucket.
# ---------------------------------------------------------------------------
echo
echo "== 0/4 staging SPA bundle =="
if [ ! -f frontend/dist/index.html ]; then
  echo "  frontend/dist is missing — run: cd frontend && npm run build" >&2
  exit 1
fi
mkdir -p platform/seed/spa
rsync -a --delete --exclude '.gitkeep' frontend/dist/ platform/seed/spa/
echo "  staged $(find platform/seed/spa -type f | wc -l | tr -d ' ') file(s); bundle: $(ls -1 platform/seed/spa/assets/*.js | xargs -n1 basename | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Refuse to deploy a stale service artifact.
#
# Every service template declares CodeUri: ../../dist/<service>.zip, so
# `sam package` uploads whatever pre-built zip is already sitting in dist/ — it
# does NOT build from services/*/src. Nothing in this script ever ran
# `make build`, so editing a service and deploying published the PREVIOUS code:
# every stack reports UPDATE_COMPLETE, sam even prints "File with same data
# already exists, skipping upload", and the old handler keeps serving. The same
# silent failure mode as the stale SPA bundle above.
#
# Caught on 2026-08-29: the contributions-scoring evidence-URL fix deployed
# "successfully" while the deployed Lambda still ran require_str, so a
# javascript: URI was still accepted with a 201.
#
# Fails loudly rather than building automatically, so it stays obvious which
# code is going out.
# ---------------------------------------------------------------------------
echo
echo "== 0b/4 checking artifact freshness =="
stale=""
for svc_dir in services/*/; do
  svc=$(basename "$svc_dir")
  zip="dist/$svc.zip"
  [ -d "${svc_dir}src" ] || continue
  if [ ! -f "$zip" ]; then
    stale="$stale
  MISSING  $zip"
    continue
  fi
  newer=$(find "${svc_dir}src" -name '*.py' -newer "$zip" 2>/dev/null | head -3)
  if [ -n "$newer" ]; then
    stale="$stale
  STALE    $zip is older than:
$(echo "$newer" | sed 's/^/             /')"
  fi
done
if [ -n "$stale" ]; then
  echo "$stale" >&2
  echo >&2
  echo "  Refusing to deploy: dist/ does not match services/*/src." >&2
  echo "  These templates deploy dist/*.zip, not the source tree — run: make build" >&2
  exit 1
fi
echo "  all $(ls -1 dist/*.zip 2>/dev/null | wc -l | tr -d ' ') service artifact(s) newer than their sources"

newest_src=$(find frontend/src -type f \( -name '*.ts' -o -name '*.tsx' \) -newer frontend/dist/index.html 2>/dev/null | head -1)
if [ -n "$newest_src" ]; then
  echo "  frontend/dist is older than $newest_src — run: cd frontend && npm run build" >&2
  exit 1
fi
echo "  SPA bundle newer than frontend/src"

echo
echo "== 1/4 packaging nested templates =="
for f in infra/*.yaml infra/services/*.yaml; do
  base=$(basename "$f")
  [ "$base" = "root-template.yaml" ] && continue   # deployed directly, not nested
  if grep -qE "CodeUri|DefinitionUri" "$f"; then
    printf '  package  %-44s' "$base"
    sam package -t "$f" \
      --s3-bucket "$BUCKET" --s3-prefix "$PREFIX/code" \
      --output-template-file "$STAGING/$base" --region "$REGION" >/dev/null
    echo "ok"
  else
    printf '  copy     %-44s' "$base"
    cp "$f" "$STAGING/$base"
    echo "ok"
  fi
done

echo
echo "== 2/4 uploading nested templates =="
aws s3 cp "$STAGING/" "s3://$BUCKET/$PREFIX/" --recursive \
  --exclude "*" --include "*.yaml" --region "$REGION" --only-show-errors
echo "  uploaded $(ls -1 $STAGING/*.yaml | wc -l | tr -d ' ') templates"

if [ "${TEMPLATES_ONLY:-0}" = "1" ]; then
  echo; echo "TEMPLATES_ONLY=1 — stopping before deploy."; exit 0
fi

echo
echo "== 3/4 deploying root stack =="
# DeployNonce forces the nested stacks to be re-evaluated even when only the
# Lambda code changed: CloudFormation compares templates, and a nested template
# whose S3 URL is unchanged is skipped entirely.
sam deploy -t infra/root-template.yaml \
  --stack-name "$STACK" --region "$REGION" \
  --s3-bucket "$BUCKET" --s3-prefix "$PREFIX/root" \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "Stage=$STAGE" \
    "AdminEmail=$ADMIN_EMAIL" \
    "OpsEmail=$OPS_EMAIL" \
    "AllowedEmailDomains=$ALLOWED_DOMAINS" \
    "EnableSemanticSearch=false" \
    "EnableObservabilityDashboards=$ENABLE_DASHBOARDS" \
    "EnableApplicationSignals=$ENABLE_APP_SIGNALS" \
    "AppSignalsLayerArn=$APP_SIGNALS_LAYER_ARN" \
    "TemplateBaseUrl=https://$BUCKET.s3.$REGION.amazonaws.com/$PREFIX" \
    "DeployNonce=$(date +%s)"

echo
echo "== 4/4 outputs =="
aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query 'Stacks[0].Outputs' --output table
