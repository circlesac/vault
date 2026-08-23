#!/usr/bin/env bash
#
# Development two-client enrollment harness.
#
# Runs the candidate CLI against two genuinely independent key stores and
# verifies enroll, list, revoke, re-enroll, and audit readback against a live
# development deployment. Values are compared by hash only and never printed.
# The test client and canary item are removed on exit.
#
# The recovery envelope is deliberately not inspected here: no client route
# exposes it. That comparison belongs to the service-side rollout runbook.
set -euo pipefail

: "${CVLT_E2E_ORG:?Set CVLT_E2E_ORG to the development organization slug}"
: "${CVLT_E2E_VAULT:?Set CVLT_E2E_VAULT to a vault name in that organization}"
: "${CVLT_E2E_STORE_A:?Set CVLT_E2E_STORE_A to the first key store XDG_CONFIG_HOME}"
: "${CVLT_E2E_STORE_B:?Set CVLT_E2E_STORE_B to the second key store XDG_CONFIG_HOME}"
: "${CVLT_E2E_PASSPHRASE_A:?Set CVLT_E2E_PASSPHRASE_A to the first key store passphrase}"
: "${CVLT_E2E_PASSPHRASE_B:?Set CVLT_E2E_PASSPHRASE_B to the second key store passphrase}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required for the audit readback" >&2; exit 1; }
command -v script >/dev/null || { echo "script is required for interactive approval" >&2; exit 1; }
if [[ $(uname -s) != Linux ]]; then
  echo "This single-host harness requires Linux with GNU script and encrypted-file key stores; use the documented manual cross-device sequence on macOS" >&2
  exit 1
fi
cvlt_bin=${CVLT_BIN:-cvlt}

if [[ $CVLT_E2E_VAULT == */* ]]; then
  echo "CVLT_E2E_VAULT must be a plain vault name so op:// can address the canary" >&2
  exit 1
fi
if [[ $CVLT_E2E_STORE_A == "$CVLT_E2E_STORE_B" ]]; then
  echo "CVLT_E2E_STORE_A and CVLT_E2E_STORE_B must be different key stores" >&2
  exit 1
fi
if [[ $CVLT_E2E_PASSPHRASE_A == "$CVLT_E2E_PASSPHRASE_B" ]]; then
  echo "The two key stores must use different passphrases" >&2
  exit 1
fi

global_args=()
if [[ -n ${CVLT_E2E_PROFILE:-} ]]; then
  global_args+=(--profile "$CVLT_E2E_PROFILE")
fi
global_args+=(--org "$CVLT_E2E_ORG")

a() {
  XDG_CONFIG_HOME="$CVLT_E2E_STORE_A" CVLT_KEYSTORE_PASSPHRASE="$CVLT_E2E_PASSPHRASE_A" \
    "$cvlt_bin" "${global_args[@]}" "$@"
}
b() {
  XDG_CONFIG_HOME="$CVLT_E2E_STORE_B" CVLT_KEYSTORE_PASSPHRASE="$CVLT_E2E_PASSPHRASE_B" \
    "$cvlt_bin" "${global_args[@]}" "$@"
}

# Enrollment approval deliberately has no non-interactive bypass. GNU script
# gives the child a real PTY while the harness types the same explicit answer a
# user does after comparing fingerprints.
approve_on_a() {
  local request=$1 command
  printf -v command '%q ' "$cvlt_bin" "${global_args[@]}" client approve "$request"
  printf 'yes\n' | XDG_CONFIG_HOME="$CVLT_E2E_STORE_A" \
    CVLT_KEYSTORE_PASSPHRASE="$CVLT_E2E_PASSPHRASE_A" \
    script -qec "$command" /dev/null
}

digest() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

work_dir=$(mktemp -d)
canary_title="CVLT_E2E_TWO_CLIENT_$$_${RANDOM}"
canary_created=0
enrolled_client=""

cleanup() {
  local status=$?
  local cleanup_failed=0
  if [[ -n $enrolled_client ]]; then
    if ! a client revoke "$enrolled_client" >/dev/null 2>&1; then
      echo "Cleanup failed to revoke installation $enrolled_client" >&2
      cleanup_failed=1
    fi
  fi
  if [[ $canary_created == 1 ]]; then
    if ! a item delete "$canary_title" --vault "$CVLT_E2E_VAULT" >/dev/null 2>&1; then
      echo "Cleanup failed to delete the canary item" >&2
      cleanup_failed=1
    fi
  fi
  rm -rf "$work_dir"
  if [[ $status == 0 && $cleanup_failed != 0 ]]; then status=1; fi
  exit $status
}
trap cleanup EXIT

mkdir -p "$CVLT_E2E_STORE_A" "$CVLT_E2E_STORE_B"

echo "== A: check the registered installation"
a doctor --format json > "$work_dir/doctor-a.json"
jq -e '.initialized and .client_registered' "$work_dir/doctor-a.json" >/dev/null \
  || { echo "Store A must already hold a registered installation" >&2; exit 1; }
a client list --format json > "$work_dir/clients-initial.json"
client_a=$(jq -r '.[] | select(.is_current) | .id' "$work_dir/clients-initial.json")
[[ -n $client_a ]] || { echo "A's client list did not mark a current installation" >&2; exit 1; }

# Independence pre-flight, before B is allowed to create anything. If A's key
# is not in its own encrypted file, this host keeps installation keys in a
# shared OS credential store with one slot per Vault origin. B would then
# overwrite A's key instead of becoming a second installation.
if ! compgen -G "$CVLT_E2E_STORE_A/cvlt/keys/*.json.enc" >/dev/null; then
  cat >&2 <<'MSG'
Store A holds no encrypted key file, so this host keeps installation keys in an
OS credential store with a single slot per Vault origin. Running store B here
would overwrite store A's key rather than enroll a second installation.
Use two machines, two OS user accounts, or a host whose Secret Service is
unavailable so both stores fall back to encrypted files.
MSG
  exit 1
fi

echo "== A: create the canary item"
a item create --vault "$CVLT_E2E_VAULT" --title "$canary_title" \
  --category password --generate-password 32 >/dev/null
canary_created=1

a read "op://$CVLT_E2E_VAULT/$canary_title/password" --out-file "$work_dir/canary-a"
hash_a=$(digest "$work_dir/canary-a")

echo "== B: create the enrollment request"
b client request --name "cvlt-e2e-second-store" --format json > "$work_dir/request-b.json"
[[ $(jq -r '.status' "$work_dir/request-b.json") == request ]] \
  || { echo "B is already registered; start from a store with no registration" >&2; exit 1; }
client_b=$(jq -r '.client_id' "$work_dir/request-b.json")
token_b=$(jq -r '.request' "$work_dir/request-b.json")
[[ $client_b != "$client_a" ]] \
  || { echo "Both stores produced the same installation key: they are not independent" >&2; exit 1; }
compgen -G "$CVLT_E2E_STORE_B/cvlt/keys/*.json.enc" >/dev/null \
  || { echo "Store B has no encrypted key file: this host shares one OS key-store slot per Vault origin, so two processes here are not independent installations" >&2; exit 1; }

echo "== B: repeating the request is deterministic"
# Compare the request itself: the surrounding report also states whether this
# call had to create the origin key, which is true only the first time.
b client request --name "cvlt-e2e-second-store" --format json > "$work_dir/request-b-again.json"
[[ $(jq -r '.request' "$work_dir/request-b-again.json") == "$token_b" ]] \
  || { echo "Repeated client request was not deterministic" >&2; exit 1; }
[[ $(jq -r '.created_key' "$work_dir/request-b-again.json") == false ]] \
  || { echo "Repeated client request replaced the stored key" >&2; exit 1; }

echo "== B: unapproved installation is denied"
if b client list >/dev/null 2>"$work_dir/denied-before.txt"; then
  echo "B could manage clients before approval" >&2
  exit 1
fi
grep -q "not registered" "$work_dir/denied-before.txt" \
  || { echo "Unexpected pre-approval failure: $(cat "$work_dir/denied-before.txt")" >&2; exit 1; }

echo "== A: approve B"
approve_on_a "$token_b" >/dev/null
enrolled_client=$client_b

echo "== B: read the canary and compare hashes only"
b read "op://$CVLT_E2E_VAULT/$canary_title/password" --out-file "$work_dir/canary-b"
[[ $(digest "$work_dir/canary-b") == "$hash_a" ]] \
  || { echo "B decrypted a different value than A" >&2; exit 1; }

echo "== A: both installations are active, exactly one is current"
a client list --format json > "$work_dir/clients-enrolled.json"
jq -e --arg a "$client_a" --arg b "$client_b" \
  '([.[].id] | index($a)) != null and ([.[].id] | index($b)) != null
   and ([.[] | select(.is_current)] | length) == 1
   and (.[] | select(.is_current) | .id) == $a' "$work_dir/clients-enrolled.json" >/dev/null \
  || { echo "Unexpected client list after enrollment" >&2; exit 1; }
if grep -Eq '"(public_key|wrapped_account_key|ciphertext|proof)"' "$work_dir/clients-enrolled.json"; then
  echo "client list returned key or proof material" >&2
  exit 1
fi

echo "== audit: CLIENT_ENROLL readback"
host=$(a whoami | awk '/^Host:/ {print $2}')
if [[ -n ${OP_CONNECT_TOKEN:-} ]]; then
  activity_token=$OP_CONNECT_TOKEN
else
  activity_token=$(a auth token)
fi
activity_curl_config="$work_dir/activity-curl.conf"
printf 'header = "Authorization: Bearer %s"\n' "$activity_token" > "$activity_curl_config"
chmod 600 "$activity_curl_config"
unset activity_token
read_activity() {
  curl -fsS --config "$activity_curl_config" "$host/v1/activity?action=$1&limit=50"
}
read_activity CLIENT_ENROLL > "$work_dir/activity-enroll.json"
jq -e --arg b "$client_b" \
  'any(.[]?; .action == "CLIENT_ENROLL" and .resource_type == "client" and .resource_id == $b)' \
  "$work_dir/activity-enroll.json" >/dev/null \
  || { echo "No CLIENT_ENROLL event for $client_b" >&2; exit 1; }
if grep -Eq '"(public_key|wrapped_account_key|proof|request)"' "$work_dir/activity-enroll.json"; then
  echo "Activity readback exposed key, proof, or enrollment-request material" >&2
  exit 1
fi

echo "== A: revoke B"
a client revoke "$client_b" >/dev/null
enrolled_client=""

if b read "op://$CVLT_E2E_VAULT/$canary_title/password" --out-file "$work_dir/canary-b-denied" 2>"$work_dir/denied-after.txt"; then
  echo "B could still read after revocation" >&2
  exit 1
fi
grep -q "not registered" "$work_dir/denied-after.txt" \
  || { echo "Unexpected post-revocation failure: $(cat "$work_dir/denied-after.txt")" >&2; exit 1; }

a read "op://$CVLT_E2E_VAULT/$canary_title/password" --out-file "$work_dir/canary-a-after"
[[ $(digest "$work_dir/canary-a-after") == "$hash_a" ]] \
  || { echo "A stopped reading its own canary" >&2; exit 1; }
a client list --format json > "$work_dir/clients-revoked.json"
jq -e --arg b "$client_b" '[.[].id] | index($b) == null' "$work_dir/clients-revoked.json" >/dev/null \
  || { echo "B is still listed after revocation" >&2; exit 1; }

echo "== audit: CLIENT_REVOKE readback"
read_activity CLIENT_REVOKE > "$work_dir/activity-revoke.json"
jq -e --arg b "$client_b" \
  'any(.[]?; .action == "CLIENT_REVOKE" and .resource_type == "client" and .resource_id == $b)' \
  "$work_dir/activity-revoke.json" >/dev/null \
  || { echo "No CLIENT_REVOKE event for $client_b" >&2; exit 1; }

echo "== A: revoking itself is rejected"
if a client revoke "$client_a" >/dev/null 2>&1; then
  echo "A revoked itself" >&2
  exit 1
fi

echo "== B: re-enroll the same stored key without recovery"
b client request --name "cvlt-e2e-second-store" --format json > "$work_dir/request-b-reenroll.json"
[[ $(jq -r '.client_id' "$work_dir/request-b-reenroll.json") == "$client_b" ]] \
  || { echo "Re-enrollment produced a different installation key" >&2; exit 1; }
[[ $(jq -r '.request' "$work_dir/request-b-reenroll.json") == "$token_b" ]] \
  || { echo "Revocation changed B's enrollment request" >&2; exit 1; }
approve_on_a "$token_b" >/dev/null
enrolled_client=$client_b
b read "op://$CVLT_E2E_VAULT/$canary_title/password" --out-file "$work_dir/canary-b-again"
[[ $(digest "$work_dir/canary-b-again") == "$hash_a" ]] \
  || { echo "Re-enrolled B decrypted a different value" >&2; exit 1; }

echo "Two-client enroll, list, revoke, re-enroll, and audit readback passed"
