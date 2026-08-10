#!/usr/bin/env bash
set -euo pipefail

: "${CVLT_E2E_REF_A:?Set CVLT_E2E_REF_A to the first vlt:// reference}"
: "${CVLT_E2E_REF_B:?Set CVLT_E2E_REF_B to the second vlt:// reference}"

cvlt_bin=${CVLT_BIN:-cvlt}
profile_args=()
if [[ -n ${CVLT_E2E_PROFILE:-} ]]; then
  profile_args=(--profile "$CVLT_E2E_PROFILE")
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

"$cvlt_bin" "${profile_args[@]}" read "$CVLT_E2E_REF_A" --out-file "$work_dir/a"
"$cvlt_bin" "${profile_args[@]}" read "$CVLT_E2E_REF_B" --out-file "$work_dir/b"
if cmp -s "$work_dir/a" "$work_dir/b"; then
  echo "Mixed-owner fixtures must contain distinct values" >&2
  exit 1
fi

printf '{{%s}}\n---CVLT-MIXED-OWNER---\n{{%s}}' "$CVLT_E2E_REF_A" "$CVLT_E2E_REF_B" > "$work_dir/template"
{
  cat "$work_dir/a"
  printf '\n---CVLT-MIXED-OWNER---\n'
  cat "$work_dir/b"
} > "$work_dir/expected"
"$cvlt_bin" "${profile_args[@]}" inject --in-file "$work_dir/template" --out-file "$work_dir/injected"
cmp "$work_dir/expected" "$work_dir/injected"

printf 'CVLT_E2E_A=%s\nCVLT_E2E_B=%s\n' "$CVLT_E2E_REF_A" "$CVLT_E2E_REF_B" > "$work_dir/env"
CVLT_E2E_A_FILE="$work_dir/a" CVLT_E2E_B_FILE="$work_dir/b" \
  "$cvlt_bin" "${profile_args[@]}" run --env-file "$work_dir/env" -- sh -c \
  'printf %s "$CVLT_E2E_A" | cmp - "$CVLT_E2E_A_FILE" && printf %s "$CVLT_E2E_B" | cmp - "$CVLT_E2E_B_FILE"'

echo "Mixed-owner read, inject, and run passed"
