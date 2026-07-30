#!/usr/bin/env bash
# Mutation test test_voice_transport. Object files are deleted before
# each rebuild: earlier agents on this repo got misattributed results
# because make's same-second mtime comparison skipped the recompile and
# they were re-running the OLD binary.
set -uo pipefail
cd /Users/josh/dev/gamechat/client
SRC=src/voice/VoiceTransportSelector.cpp
BD=build-livekit
cp $SRC /tmp/vts.orig

run() {
  local name="$1"
  # Delete OBJECT FILES ONLY (not the .dir — that holds build.make).
  # make compares mtimes at 1-second granularity, so a rewrite inside
  # the same second as the last build is silently skipped and the OLD
  # binary gets re-run. That is how earlier mutation runs on this repo
  # produced misattributed results.
  find $BD/tests/CMakeFiles/test_voice_transport.dir -name '*.o' -delete 2>/dev/null
  rm -f $BD/tests/test_voice_transport
  cmake --build $BD --target test_voice_transport -j8 >/tmp/mut-build.log 2>&1
  if [ $? -ne 0 ]; then echo "[$name] BUILD FAILED (mutation did not compile)"; return; fi
  out=$(./$BD/tests/test_voice_transport 2>&1)
  fails=$(echo "$out" | grep -E '^FAIL!' | sed -E 's/^FAIL!  : TestVoiceTransport::([a-zA-Z]+).*/\1/' | sort -u | tr '\n' ' ')
  tot=$(echo "$out" | grep -E '^Totals:' )
  if [ -z "$fails" ]; then echo "[$name] *** SURVIVED — no test failed ***  $tot";
  else echo "[$name] caught by: $fails"; fi
}

mutate() { python3 -c "
import sys
p='$SRC'; s=open('/tmp/vts.orig').read()
old=sys.argv[1]; new=sys.argv[2]
assert old in s, 'pattern miss: '+old[:50]
open(p,'w').write(s.replace(old,new,1))
" "$1" "$2"; }

echo "=== baseline (unmutated) ==="; cp /tmp/vts.orig $SRC; run baseline

mutate '++out.unlabelled;' '++out.livekit;'
run "M1 unlabelled-counts-as-livekit"

mutate 'if (!row.value(QStringLiteral("active")).toBool(false)) {
            continue;
        }' 'if (false) {
            continue;
        }'
run "M2 ignore-active-flag"

mutate 'return {TransportChoice::Refuse,' 'return {TransportChoice::Mesh,'
run "M3 join-anyway-instead-of-refuse"

mutate 'if (!localUserId.isEmpty() && uid == localUserId) {' 'if (!localUserId.isEmpty() && QString::compare(uid, localUserId, Qt::CaseInsensitive) == 0) {'
run "M4 local-user-case-insensitive-match"

mutate 'if (!localUserId.isEmpty() && uid == localUserId) {' 'if (uid == localUserId) {'
run "M7 drop-empty-localuser-guard"

mutate 'if (!localUserId.isEmpty() && uid == localUserId) {' 'if (false) {'
run "M8 never-exclude-own-row"

mutate 'in.clientSupportsLiveKit && in.serverOfferedLiveKitToken;' 'in.clientSupportsLiveKit || in.serverOfferedLiveKitToken;'
run "M5 either-signal-enables-livekit"

mutate 'if (roster.meshTotal() > 0) {
        return {TransportChoice::Mesh, {}};
    }' 'if (roster.meshTotal() > 0 && roster.livekit == 0) {
        return {TransportChoice::Mesh, {}};
    }'
run "M6 mixed-channel-resolves-to-livekit"

cp /tmp/vts.orig $SRC
echo "=== restored; rebuild + confirm green ==="; run "restored"
