#!/usr/bin/env bash
#
# Build the jc-ara-m Java Card CAP on the fly.
#
# The CAP is a build artifact and is intentionally NOT stored in the repo.
# This script wires the external Java Card toolchain and JDK, then runs the
# Ant converter target in cap-build.xml.
#
# Prerequisites (external, not vendored):
#   - JDK 11 (the JC 3.0.4 converter needs it). Point JAVA11_HOME at it, or let
#     the script probe the common Homebrew location.
#   - A CAP toolchain dir containing ant-javacard.jar and oracle_javacard_sdks/.
#     Provide it via JC_CAP_TOOLCHAIN (or -Dtoolchain.dir=... passed through).
#   - ant on PATH.
#
# Usage:
#   JC_CAP_TOOLCHAIN=/abs/path/to/cap-toolchain ./build-cap.sh
#   JC_CAP_TOOLCHAIN=... ./build-cap.sh --jckit jc304_kit --suffix -jc304   # default
#   JC_CAP_TOOLCHAIN=... ./build-cap.sh --jckit jc320v25.1_kit --suffix ''
#
# Output (created fresh under ./artifacts/caps/, which is gitignored):
#   artifacts/caps/jc-ara-m-0.1<suffix>.cap
#   artifacts/caps/jc-ara-m-0.1<suffix>.jca
set -euo pipefail

cd "$(dirname "$0")"

JCKIT="jc304_kit"
SUFFIX="-jc304"
while [ $# -gt 0 ]; do
  case "$1" in
    --jckit)  JCKIT="$2"; shift 2 ;;
    --suffix) SUFFIX="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- resolve toolchain ---
if [ -z "${JC_CAP_TOOLCHAIN:-}" ] && [ ! -d ".toolchain" ]; then
  echo "ERROR: no Java Card toolchain. Set JC_CAP_TOOLCHAIN=/abs/path or place one at ./.toolchain" >&2
  echo "       (expected layout: <toolchain>/ant-javacard.jar and <toolchain>/oracle_javacard_sdks/<kit>)" >&2
  exit 1
fi

# --- resolve JDK 11 ---
JDK11="${JAVA11_HOME:-/opt/homebrew/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home}"
if [ ! -x "$JDK11/bin/javac" ]; then
  echo "ERROR: JDK 11 not found at '$JDK11'. Set JAVA11_HOME to a JDK 11 home." >&2
  exit 1
fi

echo "jckit=$JCKIT suffix='$SUFFIX' toolchain=${JC_CAP_TOOLCHAIN:-./.toolchain} jdk11=$JDK11"
JAVA_HOME="$JDK11" PATH="$JDK11/bin:$PATH" \
  ant -f cap-build.xml -Djckit.name="$JCKIT" -Dcap.suffix="$SUFFIX" dist

echo "built: artifacts/caps/jc-ara-m-0.1${SUFFIX}.cap"
