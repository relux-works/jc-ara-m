#!/usr/bin/env bash
# Build signed v0.1.1 rollback, multi-rule standard, and alternate-AID canary
# CAP artifacts plus reproducible toolchain manifests. No card is accessed.
#
# Usage:
#   scripts/build-migration-assets.sh \
#     --output-dir .temp/migration-assets/release \
#     --toolchain /abs/path/to/cap-toolchain \
#     --signing-key /secure/path/release-signing.pem \
#     --canary-package-aid A00000015141434D \
#     --canary-instance-aid A00000015141434D00 \
#     [--rollback-ref v0.1.1] [--capacity 16] [--dry-run]
#
# The output directory must not already contain files. It receives three CAPs,
# detached signatures, one public key, per-CAP toolchain manifests, an unsigned
# canary-evidence template (all physical checks false), and a migration-config
# template. Keep the output task-scoped and access-controlled.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR=""
TOOLCHAIN_DIR="${JC_CAP_TOOLCHAIN:-}"
SIGNING_KEY=""
ROLLBACK_REF="v0.1.1"
CANARY_PACKAGE_AID=""
CANARY_INSTANCE_AID=""
CAPACITY="16"
DRY_RUN="false"

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --toolchain) TOOLCHAIN_DIR="$2"; shift 2 ;;
    --signing-key) SIGNING_KEY="$2"; shift 2 ;;
    --rollback-ref) ROLLBACK_REF="$2"; shift 2 ;;
    --canary-package-aid) CANARY_PACKAGE_AID="$2"; shift 2 ;;
    --canary-instance-aid) CANARY_INSTANCE_AID="$2"; shift 2 ;;
    --capacity) CAPACITY="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$OUTPUT_DIR" ] || [ -z "$TOOLCHAIN_DIR" ] || [ -z "$SIGNING_KEY" ] || \
   [ -z "$CANARY_PACKAGE_AID" ] || [ -z "$CANARY_INSTANCE_AID" ]; then
  echo "missing required arguments; run --help" >&2
  exit 2
fi
if [[ ! "$ROLLBACK_REF" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "invalid --rollback-ref" >&2
  exit 2
fi
if [[ ! "$CANARY_PACKAGE_AID" =~ ^[0-9A-Fa-f]{10,32}$ ]] || (( ${#CANARY_PACKAGE_AID} % 2 != 0 )); then
  echo "invalid --canary-package-aid" >&2
  exit 2
fi
if [[ ! "$CANARY_INSTANCE_AID" =~ ^[0-9A-Fa-f]{10,32}$ ]] || (( ${#CANARY_INSTANCE_AID} % 2 != 0 )); then
  echo "invalid --canary-instance-aid" >&2
  exit 2
fi
if [ "$CANARY_PACKAGE_AID" = "A00000015141434C" ] || [ "$CANARY_INSTANCE_AID" = "A00000015141434C00" ]; then
  echo "canary AIDs must differ from the standard ARA-M identity" >&2
  exit 2
fi
if [[ ! "$CAPACITY" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid --capacity" >&2
  exit 2
fi

if [ "$DRY_RUN" = "true" ]; then
  printf '{"ok":true,"dry_run":true,"steps":["build-v0.1.1-rollback","build-multirule-standard","build-alternate-aid-canary","sha256-and-detached-signatures","toolchain-manifests","canary-evidence-template","migration-config-template"],"rollback_ref":"%s","capacity":%s}\n' "$ROLLBACK_REF" "$CAPACITY"
  exit 0
fi

for required_command in git openssl shasum ant; do
  command -v "$required_command" >/dev/null
done
if [ ! -f "$TOOLCHAIN_DIR/ant-javacard.jar" ] || [ ! -d "$TOOLCHAIN_DIR/oracle_javacard_sdks/jc304_kit" ]; then
  echo "invalid Java Card toolchain directory" >&2
  exit 1
fi
if [ ! -f "$SIGNING_KEY" ]; then
  echo "signing key does not exist" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
if find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "output directory must be empty" >&2
  exit 1
fi

mkdir -p "$REPO_ROOT/.temp/migration-assets"
BUILD_DIR="$(mktemp -d "$REPO_ROOT/.temp/migration-assets/build.XXXXXX")"
ROLLBACK_WORKTREE="$BUILD_DIR/rollback-source"
WORKTREE_ADDED="false"
cleanup() {
  if [ "$WORKTREE_ADDED" = "true" ]; then
    git -C "$REPO_ROOT" worktree remove --force "$ROLLBACK_WORKTREE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$ROLLBACK_WORKTREE" "$ROLLBACK_REF"
WORKTREE_ADDED="true"

JC_CAP_TOOLCHAIN="$TOOLCHAIN_DIR" "$ROLLBACK_WORKTREE/jc/build-cap.sh"
JC_CAP_TOOLCHAIN="$TOOLCHAIN_DIR" "$REPO_ROOT/jc/build-cap.sh" \
  --output-name jc-ara-m-multirule --suffix -jc304
JC_CAP_TOOLCHAIN="$TOOLCHAIN_DIR" "$REPO_ROOT/jc/build-cap.sh" \
  --package-aid "$CANARY_PACKAGE_AID" \
  --applet-aid "$CANARY_INSTANCE_AID" \
  --output-name jc-ara-m-multirule-canary --suffix -jc304

cp "$ROLLBACK_WORKTREE/jc/artifacts/caps/jc-ara-m-0.1-jc304.cap" "$OUTPUT_DIR/jc-ara-m-v0.1.1-rollback.cap"
cp "$REPO_ROOT/jc/artifacts/caps/jc-ara-m-multirule-jc304.cap" "$OUTPUT_DIR/jc-ara-m-multirule-standard.cap"
cp "$REPO_ROOT/jc/artifacts/caps/jc-ara-m-multirule-canary-jc304.cap" "$OUTPUT_DIR/jc-ara-m-multirule-canary.cap"

openssl pkey -in "$SIGNING_KEY" -pubout -out "$OUTPUT_DIR/release-signing.pub"
for cap_path in "$OUTPUT_DIR"/*.cap; do
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$cap_path.sig" "$cap_path"
done

ANT_HASH="$(shasum -a 256 "$TOOLCHAIN_DIR/ant-javacard.jar" | awk '{print $1}')"
ROLLBACK_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$ROLLBACK_REF^{commit}")"
RELEASE_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
ROLLBACK_DIFF_HASH="$(git -C "$ROLLBACK_WORKTREE" diff --binary HEAD -- jc | shasum -a 256 | awk '{print $1}')"
RELEASE_DIFF_HASH="$(git -C "$REPO_ROOT" diff --binary HEAD -- jc | shasum -a 256 | awk '{print $1}')"
JAVA11_HOME_VALUE="${JAVA11_HOME:-/opt/homebrew/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home}"
JAVA_VERSION="$($JAVA11_HOME_VALUE/bin/java -version 2>&1 | sed -n '1p' | tr -d '"')"

write_manifest() {
  local cap_path="$1"
  local manifest_path="$2"
  local source_ref="$3"
  local source_commit="$4"
  local package_aid="$5"
  local applet_aid="$6"
  local source_diff_sha256="$7"
  local digest
  digest="$(shasum -a 256 "$cap_path" | awk '{print $1}')"
  printf '{\n  "artifact_sha256": "%s",\n  "source_ref": "%s",\n  "source_commit": "%s",\n  "source_diff_sha256": "%s",\n  "java_version": "%s",\n  "javacard_kit": "jc304_kit",\n  "ant_javacard_sha256": "%s",\n  "package_aid": "%s",\n  "applet_aid": "%s"\n}\n' \
    "$digest" "$source_ref" "$source_commit" "$source_diff_sha256" "$JAVA_VERSION" "$ANT_HASH" "$package_aid" "$applet_aid" > "$manifest_path"
}

write_manifest "$OUTPUT_DIR/jc-ara-m-v0.1.1-rollback.cap" "$OUTPUT_DIR/rollback-toolchain.json" "$ROLLBACK_REF" "$ROLLBACK_COMMIT" "A00000015141434C" "A00000015141434C00" "$ROLLBACK_DIFF_HASH"
write_manifest "$OUTPUT_DIR/jc-ara-m-multirule-standard.cap" "$OUTPUT_DIR/release-toolchain.json" "working-tree" "$RELEASE_COMMIT" "A00000015141434C" "A00000015141434C00" "$RELEASE_DIFF_HASH"
write_manifest "$OUTPUT_DIR/jc-ara-m-multirule-canary.cap" "$OUTPUT_DIR/canary-toolchain.json" "working-tree" "$RELEASE_COMMIT" "$CANARY_PACKAGE_AID" "$CANARY_INSTANCE_AID" "$RELEASE_DIFF_HASH"

ROLLBACK_HASH="$(shasum -a 256 "$OUTPUT_DIR/jc-ara-m-v0.1.1-rollback.cap" | awk '{print $1}')"
RELEASE_HASH="$(shasum -a 256 "$OUTPUT_DIR/jc-ara-m-multirule-standard.cap" | awk '{print $1}')"
CANARY_HASH="$(shasum -a 256 "$OUTPUT_DIR/jc-ara-m-multirule-canary.cap" | awk '{print $1}')"

printf '{\n  "canary_sha256": "%s",\n  "capacity": %s,\n  "checks": {\n    "rollback_install_restore": false,\n    "canary_install": false,\n    "add": false,\n    "overwrite": false,\n    "delete": false,\n    "ff40_ff60": false,\n    "refresh_changes": false,\n    "interruption_recovery": false,\n    "owned_transaction": false,\n    "caller_owned_transaction": false,\n    "raw_store_denied": false\n  }\n}\n' "$CANARY_HASH" "$CAPACITY" > "$OUTPUT_DIR/canary-evidence.template.json"

printf '{\n  "standard_package_aid": "A00000015141434C",\n  "standard_instance_aid": "A00000015141434C00",\n  "canary_package_aid": "%s",\n  "canary_instance_aid": "%s",\n  "rollback": {"path":"jc-ara-m-v0.1.1-rollback.cap","sha256":"%s","package_aid":"A00000015141434C","applet_aid":"A00000015141434C00","signature_path":"jc-ara-m-v0.1.1-rollback.cap.sig","public_key_path":"release-signing.pub","toolchain_manifest_path":"rollback-toolchain.json"},\n  "canary": {"path":"jc-ara-m-multirule-canary.cap","sha256":"%s","package_aid":"%s","applet_aid":"%s","signature_path":"jc-ara-m-multirule-canary.cap.sig","public_key_path":"release-signing.pub","toolchain_manifest_path":"canary-toolchain.json"},\n  "release": {"path":"jc-ara-m-multirule-standard.cap","sha256":"%s","package_aid":"A00000015141434C","applet_aid":"A00000015141434C00","signature_path":"jc-ara-m-multirule-standard.cap.sig","public_key_path":"release-signing.pub","toolchain_manifest_path":"release-toolchain.json"},\n  "canary_evidence_path": "canary-evidence.json",\n  "export_path": "secure-exported-v0.1.1-rule.json"\n}\n' "$CANARY_PACKAGE_AID" "$CANARY_INSTANCE_AID" "$ROLLBACK_HASH" "$CANARY_HASH" "$CANARY_PACKAGE_AID" "$CANARY_INSTANCE_AID" "$RELEASE_HASH" > "$OUTPUT_DIR/migration-config.template.json"

chmod 600 "$OUTPUT_DIR"/*
printf '{"ok":true,"dry_run":false,"output_dir":"%s","rollback_sha256":"%s","release_sha256":"%s","canary_sha256":"%s"}\n' "$OUTPUT_DIR" "$ROLLBACK_HASH" "$RELEASE_HASH" "$CANARY_HASH"
