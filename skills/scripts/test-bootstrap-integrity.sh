#!/usr/bin/env bash
# Test only the reviewed hash-verification function, never source the bootstrap.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
function_source="$(python3 - "$here/bootstrap-reverse.sh" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
start = text.index('verify_sha256() {')
end = text.index('\nextract_archive()', start)
print(text[start:end])
PY
)"
eval "$function_source"
log_err() { printf '%s\n' "$*" >&2; }
log_warn() { printf '%s\n' "$*" >&2; }
log_ok() { :; }
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
printf 'synthetic artifact\n' > "$scratch/artifact"
digest="$(sha256sum "$scratch/artifact" | awk '{print $1}')"
verify_sha256 "$scratch/artifact" "$digest"
verify_sha256 "$scratch/artifact" '' "sha256:$digest"
if verify_sha256 "$scratch/artifact" ''; then echo 'Missing digest accepted' >&2; exit 1; fi
if (PATH='' verify_sha256 "$scratch/artifact" "$digest"); then echo 'Missing hash utility accepted' >&2; exit 1; fi
if verify_sha256 "$scratch/artifact" "$(printf '%064d' 0)"; then echo 'Mismatched digest accepted' >&2; exit 1; fi
[[ ! -e "$scratch/artifact" ]]
echo 'BOOTSTRAP_INTEGRITY_OK synthetic local artifact only'
