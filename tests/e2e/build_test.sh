#!/bin/bash
set -e
cd /Users/josh/dev/gamechat/client
SP=/private/tmp/claude-501/-Users-josh-dev-gamechat/a93cf36b-3c49-4af9-bbf5-265c130484f9/scratchpad
mkdir -p "$SP/jbtest"
CXX=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++
SDK=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk

/opt/homebrew/share/qt/libexec/moc -I src -I build/_deps/opus-src/include \
  tests/test_jitter_buffer.cpp -o "$SP/jbtest/test_jitter_buffer.moc"

COMMON=(-std=gnu++20 -O1 -arch arm64 -isysroot "$SDK"
  -DQT_CORE_LIB -DQT_TESTLIB_LIB
  -I src -I build/_deps/opus-src/include -I "$SP/jbtest"
  -iframework /opt/homebrew/lib
  -isystem /opt/homebrew/lib/QtCore.framework/Headers
  -isystem /opt/homebrew/lib/QtTest.framework/Headers
  -isystem /opt/homebrew/share/qt/mkspecs/macx-clang
  -Wall -Wextra -Wshadow -Wsign-compare -Wshorten-64-to-32)

"$CXX" "${COMMON[@]}" -c src/voice/JitterBuffer.cpp -o "$SP/jbtest/JitterBuffer.o"
"$CXX" "${COMMON[@]}" -c tests/test_jitter_buffer.cpp -o "$SP/jbtest/test.o"
"$CXX" -arch arm64 -isysroot "$SDK" \
  "$SP/jbtest/test.o" "$SP/jbtest/JitterBuffer.o" \
  build/_deps/opus-build/libopus.a \
  -F /opt/homebrew/lib -framework QtCore -framework QtTest \
  -o "$SP/jbtest/test_jitter_buffer"
echo "BUILD OK"
