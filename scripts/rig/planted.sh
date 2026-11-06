#!/bin/bash
# planted.sh OUT: the rig's negative controls (REPAIRER.md D1: "the planted
# guards fail"). Each guard in scripts/rig/planted is either refused before
# it goes on (repairer-agent fmt, or apply in the VM) or run through the
# rig; a failing check, or a refusal, is "caught". expect.tsv says which
# the single-VM rig must catch and which it can't see yet (a gap D1's client
# VM and router close). Exit 1 when an outcome differs from expect.tsv.
# Needs RIG and AGENT as rig.sh does.
set -uo pipefail
out=${1:?the output folder}
here=$(dirname "$(readlink -f "$0")")
AGENT=$(readlink -f "${AGENT:?the agent binary}")
mkdir -p "$out"
bad=0
while IFS=$'\t' read -r name want; do
  [[ $name == \#* || -z $name ]] && continue
  raw=$here/planted/$name.json
  if ! "$AGENT" fmt "$raw" > "$out/$name.json" 2> "$out/$name.fmt"; then
    got="caught: refused by the guard format: $(tail -1 "$out/$name.fmt")"
  elif ! bash "$here/rig.sh" "$out/$name.json" "$out/$name.transcript.json" 2> "$out/$name.err" < /dev/null; then # ssh in rig.sh would eat the list
    got="ERROR: the rig didn't run: $(tail -3 "$out/$name.err" | tr '\n' ' ')"
  else
    failed=$(python3 -I -c 'import json,sys; t=json.load(open(sys.argv[1])); print(", ".join(k + " (" + "; ".join(v["evidence"])[:160] + ")" for k,v in sorted(t["checks"].items()) if v["pass"] is False))' "$out/$name.transcript.json")
    if [ -n "$failed" ]; then got="caught: $failed"; else got="passed every check"; fi
  fi
  case "$want:$got" in
    caught:caught*|gap*:"passed every check") verdict=ok ;;
    gap*:caught*) verdict="ok (caught after all: update expect.tsv)" ;;
    *) verdict=WRONG; bad=1 ;;
  esac
  printf '%s\t%s\t%s\n' "$name" "$verdict" "$got"
done < "$here/planted/expect.tsv"
exit $bad
