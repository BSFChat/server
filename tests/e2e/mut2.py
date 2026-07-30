import pathlib, subprocess, sys, shutil, os
G = "/Users/josh/dev/gamechat"
B = f"{G}/server/build-fix"

MUTATIONS = [
 # label, file, old, new, gtest binary, filter
 ("M3 LiveKitConfig.configured() only checks url",
  f"{G}/server/src/core/Config.h",
  "return !url.empty() && !api_key.empty() && !api_secret.empty();",
  "return !url.empty();",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M4 device_id '|' sanitisation removed",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "    for (auto& c : device_id) {\n        if (c == '|') c = '_';\n    }",
  "    // mutated: no sanitisation",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M5 SFU room name uses the raw Matrix room id",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "    const std::string input = server_name + '\\x1f' + room_id;",
  "    const std::string input = server_name + '\\x1f' + room_id;\n    return \"bsfchat-\" + room_id;",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M6 server_name dropped from the room-name digest",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "    const std::string input = server_name + '\\x1f' + room_id;",
  "    const std::string input = room_id;",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M7 roomAdmin granted unconditionally",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "grants.room_admin = permission::has(flags, permission::kManageChannels);",
  "grants.room_admin = true;",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M8 heartbeat not recorded on token issue",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "    record_heartbeat(room_id, *user_id);",
  "    // mutated: no heartbeat",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M9 voice-capability gate removed",
  f"{G}/server/src/api/VoiceHandler.cpp",
  "    if (!voice_state) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden(\"Room is not voice-capable\").to_json().dump(), \"application/json\");\n        return;\n    }\n    VoiceChannelContent voice_channel;",
  "    if (!voice_state) {\n        res.status = 403;\n        res.set_content(MatrixError::forbidden(\"Room is not voice-capable\").to_json().dump(), \"application/json\");\n        return;\n    }\n    VoiceChannelContent voice_channel;\n    voice_channel.enabled = true;",
  "tests/server_tests", "LiveKitTokenTest*"),

 ("M10 canPublishData omitted when false (LiveKit omitempty trap)",
  f"{G}/protocol/src/JwtUtils.cpp",
  '    video["canPublishData"] = picojson::value(grants.can_publish_data);',
  '    if (grants.can_publish_data) video["canPublishData"] = picojson::value(grants.can_publish_data);',
  "tests/protocol_tests", "LiveKitToken*"),

 ("M11 TTL clamping removed",
  f"{G}/protocol/src/JwtUtils.cpp",
  "    if (ttl_seconds < kLiveKitMinTtl) ttl_seconds = kLiveKitMinTtl;\n    if (ttl_seconds > kLiveKitMaxTtl) ttl_seconds = kLiveKitMaxTtl;",
  "    // mutated: no clamping",
  "tests/protocol_tests", "LiveKitToken*"),

 ("M12 empty-room join guard removed from signer",
  f"{G}/protocol/src/JwtUtils.cpp",
  "    if ((grants.room_join || grants.room_admin) && grants.room.empty()) {",
  "    if (false) {",
  "tests/protocol_tests", "LiveKitToken*"),

 ("M13 signer accepts an empty api_secret",
  f"{G}/protocol/src/JwtUtils.cpp",
  'if (api_secret.empty()) throw std::invalid_argument("livekit_token_sign: empty api_secret");',
  '// mutated: no api_secret check',
  "tests/protocol_tests", "LiveKitToken*"),
]

for label, f, old, new, binary, filt in MUTATIONS:
    p = pathlib.Path(f)
    orig = p.read_text()
    if orig.count(old) != 1:
        print(f"{label} :: SKIP (target occurs {orig.count(old)}x)"); continue
    p.write_text(orig.replace(old, new, 1))
    try:
        b = subprocess.run(["cmake","--build",B,"-j8"], capture_output=True, text=True)
        if b.returncode != 0:
            errs = [l for l in (b.stdout+b.stderr).splitlines() if "error:" in l][:2]
            print(f"{label} :: BUILD FAILED under mutation ({errs})"); continue
        r = subprocess.run([f"{B}/{binary}", f"--gtest_filter={filt}"], capture_output=True, text=True)
        failed = [l.split("] ",1)[1].split(" (")[0] for l in r.stdout.splitlines()
                  if l.startswith("[  FAILED  ]") and "test" not in l.split("] ",1)[1][:6]]
        failed = sorted(set(failed))
        if failed:
            print(f"{label} :: CAUGHT by {failed}")
        else:
            print(f"{label} :: *** NOT CAUGHT — no test detects this ***")
    finally:
        p.write_text(orig)
        os.utime(f, None)

# Restore baseline build
subprocess.run(["cmake","--build",B,"-j8"], capture_output=True)
print("baseline rebuilt")
