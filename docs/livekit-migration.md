# LiveKit SFU migration plan

Status: **feasibility confirmed, phase 0 (server-side token issuance) implemented.**
No client code has been changed.

Written 2026-07-30. Every external fact in this document was verified against a
primary source (upstream repository, release metadata, or upstream source code)
on that date; the "Verified facts" section lists what and where. Anything not
verified is labelled **UNVERIFIED** inline. Please keep that discipline when
editing — a fabricated version pin cost this project real debugging time.

---

## 1. Why

Voice currently uses a full mesh: one `rtc::PeerConnection` per peer *pair*
(`client/src/voice/PeerConnectionManager.cpp`), orchestrated by
`client/src/voice/VoiceEngine.cpp`. Each client encodes once and uploads N-1
copies, so upload bandwidth and encoder cost grow linearly per participant and
the call's total cost grows quadratically. The practical ceiling is about four
participants, which has been the product ceiling since April.

An SFU inverts this: each client uploads once, the server fans out. LiveKit is
self-hostable under Apache-2.0, which preserves the "no vendor lock-in, fully
self-hosted" promise.

---

## 2. Verified facts

| Fact | Source |
| --- | --- |
| An official C++ client SDK exists: `livekit/client-sdk-cpp` | GitHub repo metadata; description "Official native C++ client SDK for LiveKit" |
| Licence: Apache-2.0. LiveKit server (`livekit/livekit`) also Apache-2.0 | GitHub API `license.spdx_id` on both repos |
| Actively developed: v1.5.0 released 2026-07-28; repo pushed 2026-07-29 | GitHub releases + repo metadata |
| Release cadence: v0.4.0 (2026-05-27) → v1.0.0 (2026-06-01) → v1.5.0 (2026-07-28) — nine releases in ~two months | GitHub releases list |
| Prebuilt binaries published per release for `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `windows-x64` | Release asset names, e.g. `livekit-sdk-macos-arm64-1.5.0.tar.gz` |
| Supported platforms: Linux (x64, arm64), macOS 12.3+ (Intel + Apple Silicon), Windows x64. **Android and iOS are not supported** | `README.md`, `docs/building.md`; no Android/iOS release assets |
| Building from source needs CMake ≥3.20 **and a stable Rust toolchain** (the SDK wraps the Rust core via `livekit-ffi`) | `docs/building.md` |
| Build output: static `liblivekit.a`/`livekit.lib` **plus a dynamic `livekit_ffi` library** | `docs/building.md`, `DEPENDENCIES.md` |
| Declared vcpkg deps: `protobuf` (>= 5.29.5), `abseil`, `spdlog`, `nlohmann-json`; plus system OpenSSL | `vcpkg.json`, `DEPENDENCIES.md` |
| Audio in/out is **raw PCM only**: `AudioFrame` holds `std::vector<std::int16_t>` interleaved samples with `sample_rate`, `num_channels`, `samples_per_channel`. `AudioSource::captureFrame(const AudioFrame&, int timeout_ms)` | `include/livekit/audio_frame.h`, `include/livekit/audio_source.h` |
| Video in is **raw pixel buffers only**: `VideoBufferType` = RGBA, ABGR, ARGB, BGRA, RGB24, I420, I420A, I422, I444, I010, NV12. No encoded-bitstream ingest path exists | `include/livekit/video_frame.h`, `include/livekit/video_source.h` |
| `PlatformAudio` can own mic capture + speaker playout with built-in echo cancellation, noise suppression and AGC; `AudioSource` is the alternative for app-supplied PCM | `include/livekit/platform_audio.h` |
| Token auth: HS256 over the API secret; `iss` = API key, `sub` = participant identity, `iat`/`nbf`/`exp` set, no `jti`. Grants are a nested `video` object claim. Go SDK default TTL is 6h | `livekit/protocol` `auth/accesstoken.go`, `auth/grants.go` |
| `VideoGrant` JSON tags: `roomCreate`, `roomList`, `roomRecord`, `roomAdmin`, `roomJoin`, `room`, `canPublish`, `canSubscribe`, `canPublishData`, `canPublishSources`, `canUpdateOwnMetadata`, `ingressAdmin`, `hidden`, `recorder`, `agent`, … | `livekit/protocol` `auth/grants.go` |
| `canPublish`/`canSubscribe`/`canPublishData` are `*bool` with `omitempty` — an **absent** key means *true* | `auth/grants.go` struct tags |
| `canPublishSources` accepts `camera`, `microphone`, `screen_share`, `screen_share_audio` | LiveKit docs, "Access tokens & grants" |
| Token `exp` is checked at connect time; already-connected participants are not disconnected when it lapses, and the server issues refreshed tokens to connected clients. A *reconnect* after a drop needs a valid token | LiveKit docs (token troubleshooting / tokens-grants) |
| The SDK has a `TokenSource` abstraction it re-invokes for reconnect/renewal: `EndpointTokenSource::create(endpoint_url, options)`, `CustomTokenSource::create(provider)`, `CachingTokenSource` | `include/livekit/token_source.h` |
| LiveKit server ships an **embedded TURN** server (TURN/UDP 3478, TURN/TLS 5349 or 443) | LiveKit self-hosting docs |
| Server ports: signalling 7880 (behind a TLS-terminating LB); WebRTC either UDP 50000-60000 or single UDP 7882; TCP fallback 7881; TURN optional | LiveKit ports/firewall docs |

### Licensing conclusion

LiveKit server and the C++ client SDK are both **Apache-2.0**, which is
permissive and compatible with shipping a self-hosted product and its desktop
client. Two caveats:

- Apache-2.0 requires preserving `NOTICE`/attribution. The client's
  third-party notices will need a LiveKit entry.
- The SDK bundles a Rust core built on libwebrtc. libwebrtc is BSD-3 and
  patent-encumbered in the usual WebRTC way (the same exposure the project
  already has via libdatachannel + openh264 + libaom). The SDK's
  `DEPENDENCIES.md` does **not** enumerate transitive licences, so
  **UNVERIFIED**: a full transitive licence audit of the shipped binaries has
  not been done. Do that before a release build ships, not before a prototype.

---

## 3. Feasibility verdict

**A C++/Qt LiveKit client is viable on desktop, and is not viable on Android
via this SDK.**

Favourable:

- An official, actively maintained, Apache-2.0 C++ SDK exists with prebuilt
  binaries for exactly the three desktop platforms this product targets.
- libdatachannel is confined to **two files** — `VoiceEngine.h:14` and
  `PeerConnectionManager.h:12` are the only `#include <rtc/rtc.hpp>` sites in
  the entire client. `VoiceEngine` is already the sole seam between
  `ServerConnection` and the transport. That is an unusually clean swap point.
- The existing capture and render layers (`ScreenShareController`,
  `CameraController`, `MacScreenCapturer`, `MacCameraCapturer`,
  `VideoStreamRegistry`, `FrameConverter`) are transport-agnostic and survive.

Unfavourable, and these are the decisions the owner needs to make:

1. **Android voice regresses.** `client/CMakeLists.txt:32` enables voice on
   Android today and it works over the mesh. `client-sdk-cpp` does not support
   Android — no release assets, no mention in `docs/building.md`. The options
   are (a) keep Android on mesh permanently behind the coexistence flag,
   (b) write a JNI bridge to LiveKit's separate Kotlin SDK
   (`livekit/client-sdk-android`), or (c) attempt an Android build of the Rust
   `livekit-ffi` core — the Rust SDK does list Android support, but wiring it
   into `client-sdk-cpp`'s C++ layer is unsupported territory
   (**UNVERIFIED**, and I would not plan around it). Recommendation: (a) now,
   (b) later if Android voice matters.

2. **Today's media pipeline is largely written off.** The SDK's ingest surface
   is raw PCM and raw pixel buffers. There is no encoded-frame path. That means
   Opus encode/decode, the jitter buffer, PLC, RTP packetisation and every
   video codec backend move inside the SDK. See the table in §4 — roughly
   **4,000–4,500 of the ~9,900 lines** under `client/src/voice/` become
   redundant, including work that landed today (`JitterBuffer.cpp`, 322 lines,
   with its per-peer Opus decoder and playout-time PLC).

   This is not wasted in the sense of being wrong — it is wasted in the sense
   that a mature SFU stack already does it, better (NetEQ, real RTCP,
   server-side bandwidth estimation, simulcast). But it is a real sunk cost and
   the owner should decide with eyes open.

3. **A dynamic library re-enters the packaging story.** `livekit_ffi` is a
   shared library. `client/cmake/Dependencies.cmake:19-27` records that
   `BUILD_SHARED_LIBS` was force-set OFF precisely because non-Qt runtime DLLs
   are not gathered by `windeployqt` and `aom.dll` shipped missing from the
   v0.0.42 Windows installer. `livekit_ffi.dll`/`.dylib`/`.so` will need
   explicit install/copy rules and a macOS codesign + `@rpath` fix-up. Treat
   this as a known, previously-painful class of bug, not a footnote.

4. **The SDK is young.** v1.0.0 is eight weeks old (2026-06-01) and there have
   been five minor releases since, with at least one release note describing a
   division-by-zero/overflow fix in `AudioFrame` validation. Nine releases in
   two months is healthy velocity but also implies API churn: the README states
   v1.0.0 introduced breaking changes to align with other LiveKit SDKs. Pin a
   version, expect to bump it, and do not spread SDK types through the codebase
   (see §5, the `IVoiceTransport` seam).

Verdict: **proceed on desktop**, with Android explicitly staying on mesh.

---

## 4. Component-by-component: replaced vs retained

Line counts are current `wc -l`.

### Replaced (delete once the SFU path is default)

| Component | Lines | Why |
| --- | --- | --- |
| `PeerConnectionManager.{h,cpp}` | 259 + 993 | The entire libdatachannel transport: SDP/ICE, SCTP data channels, RTP packetise/depacketise, NACK/PLI/pacing handlers. LiveKit owns all of it. |
| `VoiceEngine.{h,cpp}` mesh internals | 257 + 1013 | Peer map, glare tie-break, candidate batching, per-peer watchdogs, capability fan-out. The *class* survives as a facade (§5); its mesh guts do not. |
| `JitterBuffer.{h,cpp}` | 220 + 322 | Reorder + Opus PLC + adaptive playout, with a per-peer Opus decoder. libwebrtc's NetEQ does this inside the SDK and cannot be bypassed, because ingest is decoded PCM. **This is today's work.** |
| Opus encoder in `AudioWorker.cpp` | ~40 of 526 | `opus_encoder_create`/`opus_encode` at `AudioWorker.cpp:73,319`. The SDK encodes. |
| `AudioPacketQueue.{h,cpp}` | 102 + 53 | Existed to hand hand-framed Opus packets between the transport and the audio thread. No packets to hand over any more. |
| `AudioMixer.{h,cpp}` | 56 + 40 | Per-peer mixing. `PlatformAudio` mixes; even with per-track `AudioStream`s the SDK's playout path handles it. |
| Video codec backends: `OpenH264Encoder/Decoder`, `MacVTEncoder/Decoder`, `MFEncoder/Decoder`, `AomLosslessEncoder/Decoder`, `VideoCodecFactory` | 1,436 + 108 | No encoded-video ingest exists. The SDK encodes with its own hardware acceleration. |
| `VideoSendPipeline`, `VideoReceivePipeline` | 62+146, 102+157 | Encode/decode worker threads with AU queues and keyframe-request throttling. Subsumed. |
| `VideoRateController.{h,cpp}` | 97 + 189 | App-level AIMD congestion control fed by hand-rolled `{"t":"rr"}` receiver reports. LiveKit has real RTCP, server-side BWE and simulcast. Strictly worse than what replaces it. |
| `PeerCaps.h` | 61 | Peer-to-peer capability discovery. Meaningless with an SFU, which negotiates per-participant. |
| Mesh signalling: `m.call.invite`/`answer`/`candidates`/`bsfchat.call.negotiate` send+receive | `VoiceEngine.cpp:871-938`, `ServerConnection.cpp:2304-2358` | Replaced by one token fetch plus LiveKit's own signalling WebSocket. |
| Dependencies: `libdatachannel`, `opus`, `openh264`, `libaom` | — | Removable from `client/cmake/Dependencies.cmake` once mesh is gone. `libyuv` is *retained* — still needed for `QVideoFrame` → I420/NV12 before handing frames to `VideoSource`. |

**Third-party build simplification is a genuine win**: libdatachannel (+ its
vendored libsrtp, with the warnings-as-errors workarounds at
`Dependencies.cmake:47-56`), opus, openh264 (which needs a hand-run
`scripts/build-openh264.sh` and vendored prebuilts per platform) and libaom
(which needs nasm, and whose CMake fights the project's flag handling per the
comments at `client/CMakeLists.txt:53-60`) all go away. That is a real
maintenance dividend, partially offset by needing Rust or prebuilt-binary
vendoring for LiveKit.

### Retained essentially unchanged

| Component | Lines | Note |
| --- | --- | --- |
| `AudioEngine.{h,cpp}` | 133 + 137 | GUI-thread facade and thread ownership. Signal surface (`micLevelChanged`, `peerLevelChanged`) is what QML binds to; keep it and re-point its internals. |
| `AudioWorker.{h,cpp}` minus Opus | ~490 of 526 | Qt Multimedia `QAudioSource`/`QAudioSink` device IO, device selection by description, level metering, mute/deafen. **Retain if we supply PCM via `AudioSource`; delete if we adopt `PlatformAudio`.** See the open question in §9. |
| `AndroidAudioRouting.{h,cpp}` | 29 + 178 | `MODE_IN_COMMUNICATION` / speakerphone / audio focus. Needed regardless, and needed *more* if Android stays on mesh. |
| `ScreenShareController.{h,cpp}` | 166 + 733 | Capture stays ours (Qt `QScreenCapture`/`QWindowCapture`, `MacScreenCapturer` because Homebrew Qt lacks `QT_FEATURE_screen_capture`). Only the sink changes: instead of owning a `VideoSendPipeline` + `VideoRateController`, it pushes converted frames into a LiveKit `VideoSource`. |
| `CameraController.{h,cpp}` | 107 + 363 | Same shape. |
| `MacScreenCapturer.{h,mm}`, `MacCameraCapturer.{h,mm}`, `MacCameraPermission.{h,mm}`, `AndroidScreenShareController` | 90+329, 54+156, 13+37, 70+276 | Platform capture and TCC. Untouched. |
| `FrameConverter.{h,cpp}` | 21 + 217 | Still needed: `QVideoFrame` → I420/NV12 to build a `VideoFrame`. |
| `VideoStreamRegistry.{h,cpp}` | 80 + 132 | Main-thread render-surface registry and liveness sweep. Its input becomes decoded frames from a LiveKit `VideoStream` instead of `VideoReceivePipeline`. Interface unchanged. |
| `NotificationSounds`, `SoundGenerator` | 38+55, 24+110 | Chat chimes. Unrelated to transport; already compiled outside the voice gate. |

### Lost capability to decide on

The **AV1 mathematically-lossless screen-share tier** (`AomLosslessEncoder`,
`AOM_LOSSLESS` + identity-matrix I444, gated on `allPeersSupportLossless()`) has
no equivalent through a raw-frame ingest API. You can push I444 frames, but the
SDK chooses the encoder and its settings; there is no documented "encode this
losslessly" control. **UNVERIFIED** whether LiveKit exposes per-track encoder
tuning sufficient for a visually-lossless (let alone mathematically lossless)
tier. If the lossless tier is a differentiator worth keeping, this needs a
prototype before committing, and it may be the strongest argument for keeping
the mesh path alive for two-person "share my terminal" sessions.

---

## 5. Coexistence: mesh and SFU behind one flag

Yes, and this should be the design, not a transitional hack.

The server already tells clients what it supports. `GET /voip/turnServer`
returns `allow_p2p`, and the new
`POST /_matrix/client/v3/rooms/{roomId}/voice/livekit_token` **404s when
`[voice.livekit]` is unconfigured**. That 404 is the capability probe: a client
tries for a token, and on 404 falls back to mesh. No new discovery endpoint, no
version negotiation.

Client-side, introduce a narrow interface — call it `IVoiceTransport` — with
roughly the surface `ServerConnection` already uses:

```
start(roomId, members) / stop()
setMuted(bool) / setDeafened(bool)
publishVideoFrame(streamId, frame) / stopVideo(streamId)
connectedParticipants()
signals: participantsChanged, audioLevelChanged, videoFrameReceived, stateChanged
```

Two implementations: `MeshVoiceTransport` (today's `VoiceEngine`, renamed) and
`LiveKitVoiceTransport`. `ServerConnection` picks one per call based on whether
the token fetch succeeded. This also contains SDK churn: LiveKit types appear
in exactly one translation unit.

Rules for the flag:

- Decision is **per call**, taken at join. Do not try to switch mid-call.
- A voice channel must be all-mesh or all-SFU. Mixed-mode is a genuine
  architectural trap: a mesh peer expects `m.call.invite` from everyone, and an
  SFU participant will never send one, so the mesh clients would sit in a
  permanent connecting state. Guard this: if any active `m.call.member` in the
  channel was published by a mesh client, new joiners must use mesh too. Add a
  `transport: "mesh" | "livekit"` field to `VoiceMemberContent` in
  `protocol/include/bsfchat/MatrixTypes.h` and have the server refuse to issue
  a token when the channel already has active mesh members (and vice versa).
  **This is not implemented yet** — it is the first thing phase 2 must do.
- Android forces mesh regardless of server capability.

---

## 6. Participant tracking: `m.call.member`, the reaper, and LiveKit

Today there are two overlapping sources of truth:

- `m.call.member` state events, written **only by the server**
  (`VoiceHandler.cpp:207-215` join, `:268-276` leave, `:92-99` reaper) with
  content `{active, muted, deafened, screen_sharing, camera_on, device_id,
  joined_at}`.
- The client's `m_voiceMembers` (`ServerConnection.h:754`), refreshed by a 5 s
  poll of `GET .../voice/members` (`ServerConnection.cpp:324-331`) and
  immediately on any `m.call.member` sync event (`:2044`, `:2129`). The same
  poll also drives mesh reconciliation (`:546-560`).
- The **ghost reaper** (`VoiceHandler.cpp:66-134`, `kHeartbeatTtl = 30s`,
  `kReapInterval = 10s`) exists because in a mesh nobody authoritatively knows
  who is still connected. It infers liveness from HTTP heartbeats and flips
  `active: false` when one goes stale.

With an SFU, **LiveKit becomes the authority on liveness.** The recommended end
state:

- `m.call.member` **stays** as the durable projection. It is what drives the
  channel-list badge, the sidebar member list, and unread/presence UI, and it
  is what a client sees before it has connected to anything. Do not replace it
  with LiveKit participant events in the UI layer.
- Liveness stops being inferred. Two options:
  1. **Webhooks (preferred).** LiveKit can POST room/participant events to a
     configured endpoint. The server consumes `participant_joined` /
     `participant_left` and writes `m.call.member` directly, and the reaper is
     retired for SFU channels. **UNVERIFIED**: the exact webhook payload
     schema and its authentication mechanism were not confirmed against
     upstream source for this document. Confirm before implementing.
  2. **Polling the LiveKit server API** (`RoomService.ListParticipants`) from
     the reaper thread instead of using heartbeats. Less elegant, no new
     inbound endpoint to secure, and it reuses the thread that already exists.
- Either way the **reaper must survive for mesh channels**, so it becomes
  per-channel-transport rather than global. Note that the new token endpoint
  already records a heartbeat (`handle_livekit_token` → `record_heartbeat`), so
  a token-renewing SFU client is not reaped in the interim — that is
  deliberate, and it is what keeps phase 1 safe before webhooks land.
- The 5 s member poll can drop to a slow reconciliation safety net (30-60 s)
  for SFU channels, since LiveKit pushes participant events to the client
  directly. Keep it for mesh.

Identity mapping matters here. The token endpoint sets LiveKit identity to
`@user:server` or `@user:server|DEVICE` when a `device_id` is supplied, because
LiveKit treats one identity as one participant and **disconnects the older
connection** on a collision — a user's second device would otherwise silently
kick their first. The client must split on the first `|` to recover the user id.
`|` cannot occur in a Matrix user id and is stripped from client-supplied
device ids (see `LiveKitTokenTest.DeviceIdCannotForgeAnotherIdentity`).

---

## 7. Screen share and camera

Both keep their existing capture front end and lose their encode/transport back
end.

- Publish two separate LiveKit tracks with distinct sources
  (`screen_share`, `camera`) rather than the current
  `VideoStreamId{Screen=0, Camera=1}` multiplexing over one data path. The
  token already grants `canPublishSources: ["microphone", "camera",
  "screen_share", "screen_share_audio"]`.
- `screen_share_audio` is granted but unused today — the mesh path has no
  screen audio. It becomes available for free; treat it as a follow-up feature,
  not part of the migration.
- `ScreenShareController` currently owns a `VideoSendPipeline` and a
  `VideoRateController`. Both are deleted; the controller instead holds a
  `std::shared_ptr<livekit::VideoSource>` and pushes `FrameConverter` output
  into it. Resolution/framerate policy moves from `VideoRateController` to
  LiveKit's publish options and its own BWE.
- The `screen_sharing` / `camera_on` flags in `m.call.member` stay — they are
  what `reconcileAnnouncedMedia` (`ServerConnection.cpp:1494-1495`) uses to
  render placeholders before frames arrive, and LiveKit track events arrive
  later than the state event.
- The AV1 lossless tier is at risk. See §4.

---

## 8. Deployment

New moving part: a `livekit` service. Slots naturally next to the existing
`coturn` service in `docker-compose.yml` and `deploy/docker-compose.yml`.

Ports (from LiveKit's own ports/firewall docs):

| Port | Purpose | Required |
| --- | --- | --- |
| 7880/tcp | Signalling + API. Behind the existing nginx, TLS-terminated | Yes |
| 50000-60000/udp *or* 7882/udp | WebRTC media. The single-port mode is far friendlier to Docker, which publishes UDP ports one at a time — the existing compose file already notes this problem for coturn's 101-port relay range | Yes (one of them) |
| 7881/tcp | WebRTC TCP fallback | Recommended |
| 3478/udp, 5349/tcp | Embedded TURN | Optional |

**TURN gets simpler, not harder.** LiveKit ships an embedded TURN server with
authentication integrated into its own participant auth. That means the
separate `coturn` service, its `--static-auth-secret` shared with
`voice.turn_secret`, the ~2000-port relay range in production, the
`--external-ip` bridge-networking workaround documented in
`docker-compose.yml:56-63`, and the ephemeral-credential HMAC in
`handle_turn_server` can **all retire** once mesh is gone. Until then, coturn
stays for mesh clients and Android. Net: one service swapped for another during
transition, one service removed at the end.

Resource cost is a genuine new operational burden and the honest downside of an
SFU: the server now decodes nothing but does relay every stream, so egress
scales with participants². For a self-hosted product this lands on the person
running the box. **UNVERIFIED**: no capacity numbers were measured. Do not
publish sizing guidance without measuring it.

Config (implemented, see `server/config/bsfchat-server.example.toml`):

```toml
[voice.livekit]
url = "wss://sfu.yourdomain.com"
api_key = "<livekit-api-key>"
api_secret = "<livekit-api-secret>"
token_ttl = 600
```

All three of url/api_key/api_secret are required; a partial block is ignored
with a warning and voice keeps using mesh. `api_secret` is never logged and
never returned by any endpoint.

---

## 9. Phases and effort

Effort is in engineer-days for someone fluent in this codebase, and is a
range because the SDK is new and its rough edges are not yet known.

### Phase 0 — server-side token issuance ✅ done

`POST /_matrix/client/v3/rooms/{roomId}/voice/livekit_token`, `[voice.livekit]`
config, HS256 signer in `protocol`, 40 tests. No client change, no behaviour
change on an unconfigured server. **~1 day, complete.**

### Phase 1 — vendoring spike and a throwaway client (3-5 days)

The goal is to de-risk, not to ship. Get `client-sdk-cpp` linking into the
existing CMake build on macOS arm64 and one other platform, and get *one*
participant publishing microphone audio into a locally-hosted LiveKit using a
token from phase 0.

Vendoring: follow the **openh264 precedent** at
`client/cmake/Dependencies.cmake:103-129` — a per-platform prebuilt dropped
into `client/deps/`, wrapped in an `IMPORTED` target. The published release
tarballs make this straightforward and avoid putting Rust on the critical path
of every build. FetchContent is a poor fit here: the source build needs a Rust
toolchain and `git-lfs`, and the project has already been burned by
third-party CMake fighting its flag handling.

Deliverables: a working `IMPORTED` target, a documented dylib/DLL install rule,
and an answer to the `PlatformAudio` vs `AudioSource` question below. Exit
criterion: audio flows, or we learn it does not and stop.

### Phase 2 — `IVoiceTransport` seam and mesh/SFU coexistence (5-8 days)

Extract the interface, rename today's `VoiceEngine` to `MeshVoiceTransport`
behind it, add the `transport` field to `VoiceMemberContent`, and enforce
all-mesh-or-all-SFU per channel server-side. **No LiveKit code yet.** Mesh keeps
working throughout; this phase is a pure refactor with the existing tests as
the safety net. Doing it before the LiveKit implementation is what keeps voice
functioning during the transition.

### Phase 3 — `LiveKitVoiceTransport`, audio only (5-8 days)

Mic publish + remote subscribe, mute/deafen, level metering,
participant events wired to the existing signals. Ship behind config: a
deployment without `[voice.livekit]` sees no change. This is the phase that
proves the >4-participant claim — test it with 8-10 clients.

### Phase 4 — video, screen share, camera (5-10 days)

Re-point `ScreenShareController` and `CameraController` at LiveKit
`VideoSource`s, and `VideoStreamRegistry` at `VideoStream`s. Wider range
because the lossless-tier question (§4) may force a design decision here.

### Phase 5 — participant-tracking cleanup (3-5 days)

LiveKit webhooks or API polling; reaper becomes mesh-only; slow the member
poll for SFU channels.

### Phase 6 — deprecation (2-4 days, plus a release cycle of waiting)

Delete the mesh path and drop libdatachannel/opus/openh264/libaom — **only
if** Android voice has been resolved, since Android has no other option today.
Retire coturn.

**Total: roughly 23-40 days**, with phases 1-3 (13-21 days) being the ones that
decide whether this works. Phase 1 is cheap and answers the riskiest question;
do it before committing to the rest.

---

## 10. Open questions for the owner

1. **Android.** Accept mesh-only Android voice indefinitely, or budget a JNI
   bridge to the Kotlin SDK? This gates phase 6 entirely.
2. **`PlatformAudio` or `AudioSource`?** `PlatformAudio` gives echo
   cancellation, noise suppression and AGC for free — which the current
   pipeline has *none* of outside Android's `MODE_IN_COMMUNICATION` — but it
   takes ownership of device IO, deleting most of `AudioWorker` including
   device-selection-by-description and level metering, and it is unclear
   whether per-participant volume and the existing mic-level meter survive.
   `AudioSource` keeps `AudioWorker` and all that UI, but forfeits AEC/NS/AGC
   unless we implement them. **Recommendation: prototype `PlatformAudio` in
   phase 1 and check whether its device enumeration and level data can back
   the existing settings UI.** Echo cancellation is a bigger user-visible win
   than anything in the current audio path.
3. **The AV1 lossless screen-share tier.** Differentiator worth preserving (and
   therefore worth keeping a mesh path for), or acceptable loss?
4. **Voice permissions.** The permission bitmask in
   `protocol/include/bsfchat/Permissions.h` has **no voice bits** — no
   CONNECT, SPEAK, VIDEO, MUTE_MEMBERS or PRIORITY_SPEAKER. The token endpoint
   therefore derives publish rights from `kViewChannel` (mirroring current mesh
   behaviour: anyone who can see a voice channel can talk in it) and `roomAdmin`
   from `kManageChannels`. Adding real voice bits (bits 13 and 14 are free) is
   the right fix but touches `kAllFlags`, the role editor QML, and the role
   bootstrap — all currently owned by another agent. **Deferred deliberately.**
   When it lands, `handle_livekit_token` is the single place to change.
5. **Simulcast / dynacast policy.** Not investigated. Relevant for CPU on a
   10-person call with cameras on.
6. **E2EE.** The SDK lists end-to-end encryption support
   (`include/livekit/e2ee.h`). The mesh path is DTLS hop-by-hop, and the two
   media types differ: **audio** is Opus over an SCTP data channel with NO
   SRTP, while **video** is RTP and IS SRTP-protected, keyed by the same DTLS
   handshake (`cmake/Dependencies.cmake:38-40` vendors libsrtp for exactly
   this; `PeerConnectionManager.cpp:367,559` treat "transport with no SRTP" as
   the failure to avoid). Do not state "the mesh is DTLS-SRTP" (wrong for
   audio) or "there is no SRTP" (wrong for video) — both errors have been
   made in this repo. An SFU
   is a *reduction* in confidentiality unless E2EE is enabled — the server can
   decrypt otherwise. For a product whose pitch is self-hosting and no
   middlemen, this deserves a deliberate decision rather than a default.
   **UNVERIFIED**: key-distribution model and its interaction with our token
   issuance were not examined.

---

## 11. What phase 0 actually implemented

| File | Change |
| --- | --- |
| `protocol/include/bsfchat/JwtUtils.h` | `LiveKitGrants` struct, `livekit_token_sign(...)`, `kLiveKitMinTtl`/`kLiveKitMaxTtl` |
| `protocol/src/JwtUtils.cpp` | HS256 signer with the nested `video` grant claim. Separate from `jwt_sign` because that is RS256-only and `JwtClaims` cannot express a nested object claim |
| `server/src/core/Config.h` | `LiveKitConfig` + `VoiceConfig::livekit`, `configured()` |
| `server/src/core/Config.cpp` | `[voice.livekit]` sub-table parsing; `validate()` warnings for partial config, out-of-range TTL, and `ws://` |
| `server/src/api/VoiceHandler.h/.cpp` | `handle_livekit_token`, `livekit_room_name` |
| `server/src/core/Server.cpp` | One route registration |
| `server/config/bsfchat-server.example.toml` | Documented, commented-out `[voice.livekit]` block |
| `protocol/tests/test_jwt.cpp` | 12 tests: wire format, HS256 header, omitempty traps, TTL clamping, input rejection, secret non-disclosure |
| `server/tests/test_voice.cpp` | 21 endpoint tests + 5 config-parsing tests |

Security properties under test, each verified by mutation (break it, watch a
test fail, revert):

- No token without `kViewChannel` on that channel — via both a user override
  and an `@everyone` override, with a negative control proving an *unrelated*
  permission denial does not block voice.
- No token for a non-member, an unauthenticated caller, a non-voice channel, or
  a voice-disabled channel.
- No token when `[voice.livekit]` is absent or partial (404, so clients read it
  as "mesh only").
- `roomAdmin` tracks `kManageChannels` rather than being handed to everyone.
- SFU room names are per-channel, stable, server-scoped, and do not embed the
  raw Matrix room id.
- Denied grants are emitted explicitly as `false`, never omitted — LiveKit's
  `omitempty` pointers make an absent key mean *true*.
- `api_secret` appears in no response body and no token claim.
- A client-supplied `device_id` cannot forge another user's identity.
- Token issuance counts as a liveness heartbeat, with a control test proving
  the same stale heartbeat *is* reaped without it.

## Decision: mic metering under PlatformAudio (2026-07-30)

`PlatformAudio`/`PlatformAudioSource` expose **no level API**. `audio_level`
exists only in `AudioSourceStats` via `Room::getStats()` — an async FFI
round-trip, unusable for a 20-50ms meter. `onActiveSpeakersChanged` carries
only `std::vector<Participant*>`, i.e. binary speaking/not-speaking with no
magnitude.

**Decision: keep a Qt `QAudioSource` open purely for local mic metering,
alongside PlatformAudio's capture.** This preserves the continuous mic meter
and the existing audio settings UI, which `micLevelChanged(float)` /
`peerLevelChanged(userId, float)` are bound to in QML.

Implement in phase 3, when the LiveKit transport is actually wired.

Open risk to validate then: two audio input devices open simultaneously.
Plausible on macOS; **needs explicit validation on Windows**, where exclusive
-mode capture drivers are more common. If it proves unworkable there, the
fallback is binary speaking indicators from `onActiveSpeakersChanged` — a
visible downgrade, so exhaust the Qt option first.

Remote participant levels have no equivalent workaround: a Qt source can only
meter the local mic. Speaking rings for remote peers will be binary under
LiveKit regardless.
