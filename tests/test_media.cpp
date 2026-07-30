#include <gtest/gtest.h>

#include "api/MediaHandler.h"
#include "core/Config.h"
#include "storage/LocalStorage.h"
#include "storage/MediaStorage.h"
#include "storage/S3Client.h"
#include "storage/S3Storage.h"
#include "store/SqliteStore.h"

#include <httplib.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#else
#include <unistd.h>
#endif

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

using namespace bsfchat;

// --- Local Storage Tests ---

class LocalStorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / "bsfchat_test_media";
        std::filesystem::create_directories(test_dir);
        storage = std::make_unique<LocalStorage>(test_dir.string());
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir);
    }

    std::filesystem::path test_dir;
    std::unique_ptr<LocalStorage> storage;
};

TEST_F(LocalStorageTest, UploadAndDownload) {
    std::string data = "Hello, world!";
    std::string content_type = "text/plain";
    std::string filename = "test.txt";

    auto path = storage->upload("media001", data, content_type, filename);
    EXPECT_FALSE(path.empty());

    auto result = storage->download("media001");
    ASSERT_TRUE(result.has_value());
    auto& [dl_data, dl_ct] = *result;
    EXPECT_EQ(dl_data, data);
    EXPECT_EQ(dl_ct, content_type);
}

TEST_F(LocalStorageTest, UploadBinaryData) {
    std::string data;
    data.resize(256);
    for (int i = 0; i < 256; ++i) {
        data[i] = static_cast<char>(i);
    }

    storage->upload("binary001", data, "application/octet-stream", "data.bin");

    auto result = storage->download("binary001");
    ASSERT_TRUE(result.has_value());
    auto& [dl_data, dl_ct] = *result;
    EXPECT_EQ(dl_data.size(), 256u);
    EXPECT_EQ(dl_data, data);
}

TEST_F(LocalStorageTest, DownloadNonexistent) {
    auto result = storage->download("doesnotexist");
    EXPECT_FALSE(result.has_value());
}

TEST_F(LocalStorageTest, Delete) {
    storage->upload("todelete", "data", "text/plain", "f.txt");
    EXPECT_TRUE(storage->download("todelete").has_value());

    EXPECT_TRUE(storage->remove("todelete"));
    EXPECT_FALSE(storage->download("todelete").has_value());
}

TEST_F(LocalStorageTest, DeleteNonexistent) {
    EXPECT_FALSE(storage->remove("ghost"));
}

// --- SQLite Media Metadata Tests ---

class MediaStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
    }

    std::unique_ptr<SqliteStore> store;
};

TEST_F(MediaStoreTest, InsertAndGetMedia) {
    store->insert_media("m1", "@alice:test", "image/png", "photo.png", 12345, "/data/m1");

    auto meta = store->get_media("m1");
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->media_id, "m1");
    EXPECT_EQ(meta->uploader, "@alice:test");
    EXPECT_EQ(meta->content_type, "image/png");
    EXPECT_EQ(meta->filename, "photo.png");
    EXPECT_EQ(meta->file_size, 12345);
    EXPECT_EQ(meta->file_path, "/data/m1");
}

TEST_F(MediaStoreTest, GetNonexistentMedia) {
    auto meta = store->get_media("nonexistent");
    EXPECT_FALSE(meta.has_value());
}

TEST_F(MediaStoreTest, DeleteMedia) {
    store->insert_media("m2", "@bob:test", "text/plain", "note.txt", 100, "/data/m2");
    EXPECT_TRUE(store->get_media("m2").has_value());

    EXPECT_TRUE(store->delete_media("m2"));
    EXPECT_FALSE(store->get_media("m2").has_value());
}

TEST_F(MediaStoreTest, DeleteNonexistentMedia) {
    EXPECT_FALSE(store->delete_media("ghost"));
}

TEST_F(MediaStoreTest, InsertMediaWithEmptyFilename) {
    store->insert_media("m3", "@alice:test", "application/octet-stream", "", 500, "/data/m3");
    auto meta = store->get_media("m3");
    ASSERT_TRUE(meta.has_value());
    EXPECT_EQ(meta->filename, "");
}

// --- S3 Signature Tests ---
// Unit test AWS Signature V4 components using known test vectors

TEST(S3SignatureTest, SHA256EmptyString) {
    // AWS test vector: SHA-256 of empty string
    auto hash = S3Client::sha256_hex("");
    EXPECT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(S3SignatureTest, SHA256KnownValue) {
    // SHA-256 of "Hello"
    auto hash = S3Client::sha256_hex("Hello");
    EXPECT_EQ(hash, "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969");
}

TEST(S3SignatureTest, HMACSHA256KnownValue) {
    // HMAC-SHA256 with a known key and data
    std::string key = "key";
    std::string data = "The quick brown fox jumps over the lazy dog";
    auto result = S3Client::hmac_sha256_hex(key, data);
    EXPECT_EQ(result, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

TEST(S3SignatureTest, URIEncode) {
    EXPECT_EQ(S3Client::uri_encode("hello/world", true), "hello%2Fworld");
    EXPECT_EQ(S3Client::uri_encode("hello/world", false), "hello/world");
    EXPECT_EQ(S3Client::uri_encode("foo bar", true), "foo%20bar");
    EXPECT_EQ(S3Client::uri_encode("test_file-1.txt", true), "test_file-1.txt");
    EXPECT_EQ(S3Client::uri_encode("special=chars&here", true), "special%3Dchars%26here");
}

// ─────────────────────────────────────────────────────────────────────────────
// Range / streaming download
//
// handle_download used to call storage->download(), materialising the whole
// object, and let httplib slice a range out of the in-memory copy: a 1-byte
// `Range:` request on a 50 MB video allocated 50 MB, multiplied by every
// concurrent seek. These tests cover both halves of the fix — the HTTP range
// semantics, and (the part that actually matters) that only the requested
// window is ever read.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// Deterministic pseudo-random byte for position `i`. Lets a test describe a
// 50 MB object without any test-side allocation of 50 MB.
inline char synth_byte(size_t i) {
    return static_cast<char>((i * 2654435761u + 7u) & 0xffu);
}

std::string synth_bytes(size_t offset, size_t length) {
    std::string s;
    s.resize(length);
    for (size_t i = 0; i < length; ++i) s[i] = synth_byte(offset + i);
    return s;
}

// A MediaStorage that answers from a generator rather than a buffer and counts
// exactly how many bytes it was asked to produce. The byte counter is the whole
// point: a test that only checks the response body would pass unchanged against
// the old read-everything-then-slice implementation.
class CountingStorage : public MediaStorage {
public:
    explicit CountingStorage(size_t size, std::string content_type = "video/mp4")
        : size_(size), content_type_(std::move(content_type)) {}

    std::string upload(const std::string&, const std::string&, const std::string&,
                       const std::string&) override {
        return "counting://object";
    }

    std::optional<std::tuple<std::string, std::string>> download(const std::string&) override {
        // The defect being fixed. If handle_download ever calls this again the
        // whole-object read is back, so record it and hand back the full body.
        ++whole_object_reads;
        bytes_read += size_;
        return std::make_tuple(synth_bytes(0, size_), content_type_);
    }

    std::optional<MediaStat> stat(const std::string&) override {
        ++stat_calls;
        MediaStat s;
        s.size = size_;
        s.content_type = content_type_;
        return s;
    }

    bool download_range(const std::string&, size_t offset, size_t length,
                        std::string& out) override {
        ++range_reads;
        largest_read = std::max(largest_read, length);
        read_windows.emplace_back(offset, length);
        if (offset >= size_) {
            out.clear();
            return true;
        }
        size_t n = std::min(length, size_ - offset);
        bytes_read += n;
        out = synth_bytes(offset, n);
        return true;
    }

    bool remove(const std::string&) override { return true; }

    size_t whole_object_reads = 0;
    size_t range_reads = 0;
    size_t stat_calls = 0;
    size_t bytes_read = 0;
    size_t largest_read = 0;
    std::vector<std::pair<size_t, size_t>> read_windows;

private:
    size_t size_;
    std::string content_type_;
};

// Reproduces httplib's write_content() loop (httplib.h,
// write_content_with_progress): call the provider, advance by however much it
// wrote, repeat until the window is covered. Driving it by hand is what lets a
// unit test observe storage reads without a socket. Hashes rather than
// accumulates the output so a 50 MB drain does not itself allocate 50 MB.
struct Drain {
    size_t bytes = 0;
    size_t largest_write = 0;
    size_t provider_calls = 0;
    uint64_t hash = 1469598103934665603ull;
    bool ok = true;
    std::string prefix; // first bytes, for spot checks
};

Drain drain_provider(const httplib::Response& res, size_t offset, size_t length,
                     size_t prefix_len = 0) {
    Drain d;
    size_t cur = offset;
    const size_t end = offset + length;

    httplib::DataSink sink;
    sink.write = [&](const char* data, size_t l) {
        d.bytes += l;
        d.largest_write = std::max(d.largest_write, l);
        for (size_t i = 0; i < l; ++i) {
            d.hash = (d.hash ^ static_cast<unsigned char>(data[i])) * 1099511628211ull;
        }
        if (d.prefix.size() < prefix_len) {
            d.prefix.append(data, std::min(l, prefix_len - d.prefix.size()));
        }
        cur += l;
        return true;
    };
    sink.is_writable = [] { return true; };

    while (cur < end) {
        ++d.provider_calls;
        // A provider that returns true without writing anything would spin
        // forever inside httplib. Bound the loop so that bug shows up as a
        // failed assertion instead of a hung test.
        if (d.provider_calls > 4096 + length / 1024) {
            d.ok = false;
            break;
        }
        if (!res.content_provider_(cur, end - cur, sink)) {
            d.ok = false;
            break;
        }
    }
    return d;
}

uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) h = (h ^ c) * 1099511628211ull;
    return h;
}

// FNV-1a over generated bytes, so a 50 MB expectation costs no 50 MB buffer in
// the test process either.
uint64_t fnv1a_synth(size_t offset, size_t length) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < length; ++i) {
        h = (h ^ static_cast<unsigned char>(synth_byte(offset + i))) * 1099511628211ull;
    }
    return h;
}

// Current resident set size in bytes, or 0 where unavailable. Deliberately
// *current* rather than ru_maxrss: the high-water mark is polluted by whatever
// ran earlier in the same gtest binary, which would make a delta against it
// meaningless.
size_t current_rss_bytes() {
#if defined(__APPLE__)
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS) {
        return 0;
    }
    return static_cast<size_t>(info.resident_size);
#elif defined(__linux__)
    std::ifstream statm("/proc/self/statm");
    size_t total_pages = 0, resident_pages = 0;
    if (!(statm >> total_pages >> resident_pages)) return 0;
    return resident_pages * static_cast<size_t>(sysconf(_SC_PAGESIZE));
#else
    return 0;
#endif
}

// Shapes a request the way httplib hands one to handle_download: the route
// captures land in req.matches, and any Range header has already been parsed
// into req.ranges before dispatch.
//
// Fills an existing Request rather than returning one: req.matches is a
// std::smatch holding iterators into req.path, so a Request carrying matches
// must not be copied or moved.
void init_media_request(httplib::Request& req, const std::string& media_id,
                        const std::string& token, const std::string& range_header = "") {
    req.path = "/_matrix/media/v3/download/test/" + media_id;
    static const std::regex pattern(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))");
    std::regex_match(req.path, req.matches, pattern);
    if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
    if (!range_header.empty()) {
        req.set_header("Range", range_header);
        EXPECT_TRUE(httplib::detail::parse_range_header(range_header, req.ranges))
            << "test wants a range header httplib accepts: " << range_header;
    }
}

struct HandlerFixture {
    Config config;
    std::unique_ptr<SqliteStore> store;
    std::string token = "media-token";

    HandlerFixture() {
        config = Config::defaults();
        config.server_name = "test";
        config.require_media_auth = true;
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
        store->create_user("@alice:test", "x");
        store->store_access_token(token, "@alice:test", "dev");
    }

    void register_media(const std::string& id, int64_t size,
                        const std::string& content_type = "video/mp4") {
        store->insert_media(id, "@alice:test", content_type, "clip.mp4", size,
                            "/data/" + id);
    }
};

} // namespace

// --- storage layer: LocalStorage stat + download_range ---

TEST_F(LocalStorageTest, StatReportsSizeAndContentTypeWithoutBody) {
    storage->upload("statme", "0123456789", "image/png", "p.png");

    auto info = storage->stat("statme");
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->size, 10u);
    EXPECT_EQ(info->content_type, "image/png");
}

TEST_F(LocalStorageTest, StatMissingObject) {
    EXPECT_FALSE(storage->stat("nope").has_value());
}

TEST_F(LocalStorageTest, StatEmptyObjectIsFoundWithZeroSize) {
    storage->upload("empty", "", "text/plain", "e.txt");
    auto info = storage->stat("empty");
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->size, 0u);
}

TEST_F(LocalStorageTest, DownloadRangeWindows) {
    const std::string data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    storage->upload("alpha", data, "text/plain", "a.txt");

    std::string out;

    // first byte
    ASSERT_TRUE(storage->download_range("alpha", 0, 1, out));
    EXPECT_EQ(out, "A");

    // last byte
    ASSERT_TRUE(storage->download_range("alpha", data.size() - 1, 1, out));
    EXPECT_EQ(out, "Z");

    // middle window
    ASSERT_TRUE(storage->download_range("alpha", 10, 5, out));
    EXPECT_EQ(out, "KLMNO");

    // whole object
    ASSERT_TRUE(storage->download_range("alpha", 0, data.size(), out));
    EXPECT_EQ(out, data);

    // window running past EOF is a short read, not an error
    ASSERT_TRUE(storage->download_range("alpha", 20, 100, out));
    EXPECT_EQ(out, "UVWXYZ");

    // offset at EOF: zero bytes, still a success
    ASSERT_TRUE(storage->download_range("alpha", data.size(), 10, out));
    EXPECT_TRUE(out.empty());

    // zero-length request
    out = "sentinel";
    ASSERT_TRUE(storage->download_range("alpha", 3, 0, out));
    EXPECT_TRUE(out.empty());
}

TEST_F(LocalStorageTest, DownloadRangeMissingObjectFails) {
    std::string out = "sentinel";
    EXPECT_FALSE(storage->download_range("ghost", 0, 4, out));
    EXPECT_TRUE(out.empty());
}

TEST_F(LocalStorageTest, DownloadRangeReusesCallerBuffer) {
    storage->upload("reuse", std::string(4096, 'x'), "text/plain", "r.txt");

    std::string out;
    ASSERT_TRUE(storage->download_range("reuse", 0, 4096, out));
    const auto cap = out.capacity();
    // Successive same-sized reads must not force a reallocation; the download
    // loop reuses one chunk buffer for the length of a transfer.
    for (int i = 0; i < 8; ++i) {
        ASSERT_TRUE(storage->download_range("reuse", 0, 4096, out));
        EXPECT_EQ(out.size(), 4096u);
    }
    EXPECT_EQ(out.capacity(), cap);
}

// THE memory property, measured at the filesystem backend: a small range read
// against a large object must not grow the process. The paired whole-object read
// at the end is a sensitivity check — without it, this test would also pass on a
// platform where the RSS probe always returns the same number, and would then be
// asserting nothing at all.
TEST_F(LocalStorageTest, SmallRangeOnLargeFileDoesNotMaterialiseTheFile) {
    if (current_rss_bytes() == 0) {
        GTEST_SKIP() << "no resident-set-size probe on this platform";
    }

    constexpr size_t kFileSize = 64u * 1024 * 1024;
    constexpr size_t kChunk = 1024 * 1024;

    {
        // Written a megabyte at a time so building the fixture does not itself
        // raise the high-water mark we are about to measure.
        std::ofstream ofs(test_dir / "big", std::ios::binary);
        ASSERT_TRUE(ofs.good());
        std::string block(kChunk, 'q');
        for (size_t written = 0; written < kFileSize; written += kChunk) {
            ofs.write(block.data(), static_cast<std::streamsize>(block.size()));
        }
    }
    {
        std::ofstream meta(test_dir / "big.meta");
        meta << "video/mp4\nbig.mp4\n";
    }

    ASSERT_EQ(storage->stat("big")->size, kFileSize);

    const auto baseline = static_cast<int64_t>(current_rss_bytes());
    std::string out;
    for (int i = 0; i < 64; ++i) {
        // 64 one-byte reads scattered through the file: the seek-around-a-video
        // access pattern that used to cost 64 x 64 MB.
        ASSERT_TRUE(storage->download_range("big", (kFileSize / 64) * i, 1, out));
        ASSERT_EQ(out.size(), 1u);
    }
    const auto range_growth = static_cast<int64_t>(current_rss_bytes()) - baseline;

    EXPECT_LT(range_growth, static_cast<int64_t>(8u * 1024 * 1024))
        << "64 one-byte range reads on a 64 MB file grew RSS by " << range_growth
        << " bytes; the read window is not bounded";

    // Sensitivity check, measured while the whole-object copy is still alive.
    {
        auto whole = storage->download("big");
        ASSERT_TRUE(whole.has_value());
        const auto whole_growth = static_cast<int64_t>(current_rss_bytes()) - baseline;
        ASSERT_EQ(std::get<0>(*whole).size(), kFileSize);
        ASSERT_GT(whole_growth, static_cast<int64_t>(32u * 1024 * 1024))
            << "the RSS probe did not notice a 64 MB whole-file read (delta "
            << whole_growth << "), so the range assertion above proves nothing";
    }
}

// --- handler layer: only the requested window reaches storage ---

TEST(MediaRangeHandler, OneByteRangeOnFiftyMegabyteObjectReadsOneByte) {
    HandlerFixture f;
    constexpr size_t kSize = 50u * 1024 * 1024;
    auto storage = std::make_shared<CountingStorage>(kSize);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("vid", static_cast<int64_t>(kSize));

    httplib::Request req;
    init_media_request(req, "vid", f.token, "bytes=25000000-25000000");
    httplib::Response res;
    handler.handle_download(req, res);

    // Handler declares the full object length; httplib derives Content-Range
    // and asks the provider only for the range it needs.
    ASSERT_TRUE(res.content_provider_ != nullptr);
    EXPECT_EQ(res.content_length_, kSize);
    EXPECT_EQ(res.get_header_value("Accept-Ranges"), "bytes");
    EXPECT_EQ(storage->whole_object_reads, 0u)
        << "handler fell back to a whole-object read";
    EXPECT_EQ(storage->bytes_read, 0u) << "no bytes should be read before streaming";

    auto d = drain_provider(res, 25000000, 1, 1);
    ASSERT_TRUE(d.ok);
    EXPECT_EQ(d.bytes, 1u);
    EXPECT_EQ(d.prefix, std::string(1, synth_byte(25000000)));

    // The property under test.
    EXPECT_EQ(storage->bytes_read, 1u)
        << "a 1-byte range read " << storage->bytes_read << " bytes from storage";
    EXPECT_EQ(storage->whole_object_reads, 0u);
    EXPECT_LE(storage->largest_read, 64u * 1024);
}

TEST(MediaRangeHandler, WholeFiftyMegabyteObjectStreamsInBoundedChunks) {
    HandlerFixture f;
    constexpr size_t kSize = 50u * 1024 * 1024;
    auto storage = std::make_shared<CountingStorage>(kSize);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("vid", static_cast<int64_t>(kSize));

    // `Range: bytes=0-49999999` — the client asked for everything, which must
    // still not be materialised in one buffer.
    httplib::Request req;
    init_media_request(req, "vid", f.token, "bytes=0-" + std::to_string(kSize - 1));
    httplib::Response res;
    handler.handle_download(req, res);
    ASSERT_TRUE(res.content_provider_ != nullptr);

    auto d = drain_provider(res, 0, kSize);
    ASSERT_TRUE(d.ok);
    EXPECT_EQ(d.bytes, kSize);
    EXPECT_EQ(storage->bytes_read, kSize);
    EXPECT_EQ(storage->whole_object_reads, 0u);

    // Bounded chunks: no single storage read, and no single socket write, may
    // approach the object size.
    EXPECT_LE(storage->largest_read, 64u * 1024)
        << "largest single storage read was " << storage->largest_read << " bytes";
    EXPECT_LE(d.largest_write, 64u * 1024);
    EXPECT_GT(d.provider_calls, 700u)
        << "50 MB delivered in " << d.provider_calls
        << " calls implies chunks of ~" << (kSize / std::max<size_t>(d.provider_calls, 1))
        << " bytes";

    // ...and the bytes are still right.
    EXPECT_EQ(d.hash, fnv1a_synth(0, kSize));
}

TEST(MediaRangeHandler, ProviderIsContiguousAndOrderedAcrossChunks) {
    HandlerFixture f;
    constexpr size_t kSize = 300u * 1024;
    auto storage = std::make_shared<CountingStorage>(kSize);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("vid", static_cast<int64_t>(kSize));

    httplib::Request req;
    init_media_request(req, "vid", f.token, "bytes=1000-200999");
    httplib::Response res;
    handler.handle_download(req, res);
    ASSERT_TRUE(res.content_provider_ != nullptr);

    auto d = drain_provider(res, 1000, 200000);
    ASSERT_TRUE(d.ok);
    EXPECT_EQ(d.bytes, 200000u);
    EXPECT_EQ(d.hash, fnv1a(synth_bytes(1000, 200000)));

    size_t expect_offset = 1000;
    size_t total = 0;
    for (auto& [offset, length] : storage->read_windows) {
        EXPECT_EQ(offset, expect_offset) << "storage reads must be contiguous";
        expect_offset += length;
        total += length;
    }
    EXPECT_EQ(total, 200000u) << "read exactly the requested window, no more";
}

TEST(MediaRangeHandler, NoRangeHeaderStillStreamsRatherThanMaterialising) {
    HandlerFixture f;
    constexpr size_t kSize = 4u * 1024 * 1024;
    auto storage = std::make_shared<CountingStorage>(kSize);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("vid", static_cast<int64_t>(kSize));

    httplib::Request req;
    init_media_request(req, "vid", f.token);
    httplib::Response res;
    handler.handle_download(req, res);

    ASSERT_TRUE(res.content_provider_ != nullptr);
    auto d = drain_provider(res, 0, kSize);
    ASSERT_TRUE(d.ok);
    EXPECT_EQ(d.bytes, kSize);
    EXPECT_EQ(storage->whole_object_reads, 0u);
    EXPECT_LE(storage->largest_read, 64u * 1024);
}

// Pins an upstream contract the handler leans on, rather than handler logic:
// httplib's Response::set_content_provider() installs no provider at all when
// the declared length is 0 (`if (in_length > 0)`). That is what makes a
// zero-length object safe to push through the streaming path — the provider's
// no-progress guard can never see offset == total == 0. If an httplib upgrade
// starts installing zero-length providers, this fails and points at the reason.
TEST(MediaRangeHandler, ZeroLengthObjectDoesNotInstallAContentProvider) {
    HandlerFixture f;
    auto storage = std::make_shared<CountingStorage>(0, "text/plain");
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("empty", 0, "text/plain");

    httplib::Request req;
    init_media_request(req, "empty", f.token);
    httplib::Response res;
    handler.handle_download(req, res);

    EXPECT_EQ(res.content_provider_, nullptr);
    EXPECT_EQ(res.content_length_, 0u);
    EXPECT_EQ(res.get_header_value("Content-Type"), "text/plain");
    EXPECT_EQ(storage->range_reads, 0u);
}

TEST(MediaRangeHandler, UnsatisfiableRangeGetsContentRangeStar) {
    HandlerFixture f;
    auto storage = std::make_shared<CountingStorage>(100);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("small", 100);

    httplib::Request req;
    init_media_request(req, "small", f.token, "bytes=500-600");
    httplib::Response res;
    handler.handle_download(req, res);

    EXPECT_EQ(res.status, 416);
    EXPECT_EQ(res.get_header_value("Content-Range"), "bytes */100");
    EXPECT_EQ(res.content_provider_, nullptr);
    EXPECT_EQ(storage->bytes_read, 0u) << "a 416 must not read the object";
}

TEST(MediaRangeHandler, TooManyRangesRejected) {
    HandlerFixture f;
    auto storage = std::make_shared<CountingStorage>(4096);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("multi", 4096);

    // Within the cap: served.
    {
        httplib::Request req;
        init_media_request(req, "multi", f.token, "bytes=0-0,10-10,20-20,30-30");
        httplib::Response res;
        handler.handle_download(req, res);
        EXPECT_NE(res.status, 416);
        EXPECT_TRUE(res.content_provider_ != nullptr);
    }
    // One range past the cap: rejected, and nothing read.
    {
        httplib::Request req;
        init_media_request(req, "multi", f.token, "bytes=0-0,10-10,20-20,30-30,40-40");
        httplib::Response res;
        handler.handle_download(req, res);
        EXPECT_EQ(res.status, 416);
        EXPECT_EQ(res.get_header_value("Content-Range"), "bytes */4096");
        EXPECT_EQ(storage->bytes_read, 0u);
    }
}

TEST(MediaRangeHandler, RangeRequestStillRequiresAuth) {
    HandlerFixture f;
    auto storage = std::make_shared<CountingStorage>(4096);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("guarded", 4096);

    // No token at all.
    {
        httplib::Request req;
        init_media_request(req, "guarded", "", "bytes=0-0");
        httplib::Response res;
        handler.handle_download(req, res);
        EXPECT_EQ(res.status, 401);
        EXPECT_EQ(res.content_provider_, nullptr);
        EXPECT_EQ(storage->stat_calls, 0u);
    }
    // Garbage token.
    {
        httplib::Request req;
        init_media_request(req, "guarded", "not-a-real-token", "bytes=0-0");
        httplib::Response res;
        handler.handle_download(req, res);
        EXPECT_EQ(res.status, 401);
    }
    // ?access_token= instead of a header — what QML Image.source has to use.
    {
        httplib::Request req;
        init_media_request(req, "guarded", "", "bytes=0-0");
        req.params.emplace("access_token", f.token);
        httplib::Response res;
        handler.handle_download(req, res);
        EXPECT_NE(res.status, 401);
        EXPECT_TRUE(res.content_provider_ != nullptr);
    }
}

TEST(MediaRangeHandler, MissingFromStorageIs404NotAStreamOfNothing) {
    HandlerFixture f;
    // stat() answers nullopt for a media row with no object behind it.
    class MissingStorage : public CountingStorage {
    public:
        MissingStorage() : CountingStorage(0) {}
        std::optional<MediaStat> stat(const std::string&) override { return std::nullopt; }
    };
    auto storage = std::make_shared<MissingStorage>();
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("gone", 1234);

    httplib::Request req;
    init_media_request(req, "gone", f.token, "bytes=0-0");
    httplib::Response res;
    handler.handle_download(req, res);
    EXPECT_EQ(res.status, 404);
    EXPECT_EQ(res.content_provider_, nullptr);
}

// --- HTTP layer: real requests through cpp-httplib's own range machinery ---
//
// The unit tests above bypass httplib: they call the provider directly with
// offsets a test computed. httplib does its own Range parsing, normalisation,
// 416 handling and multipart framing before and after the handler runs, and
// that is where the subtleties are, so these go over a socket.

namespace {

class MediaHttpTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = std::filesystem::temp_directory_path() / "bsfchat_media_http_test";
        std::filesystem::remove_all(dir_);
        std::filesystem::create_directories(dir_);

        storage_ = std::make_shared<LocalStorage>(dir_.string());
        config_ = Config::defaults();
        config_.server_name = "test";
        config_.require_media_auth = true;
        store_ = std::make_unique<SqliteStore>(":memory:");
        store_->initialize();
        store_->create_user("@alice:test", "x");
        store_->store_access_token(token_, "@alice:test", "dev");

        handler_ = std::make_shared<MediaHandler>(*store_, config_, storage_);

        // Same two route patterns Server::setup_routes registers.
        svr_.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+)/([^/]+))",
                 [h = handler_](const httplib::Request& rq, httplib::Response& rs) {
                     h->handle_download(rq, rs);
                 });
        svr_.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))",
                 [h = handler_](const httplib::Request& rq, httplib::Response& rs) {
                     h->handle_download(rq, rs);
                 });

        port_ = svr_.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { svr_.listen_after_bind(); });
        svr_.wait_until_ready();
    }

    void TearDown() override {
        svr_.stop();
        if (thread_.joinable()) thread_.join();
        std::filesystem::remove_all(dir_);
    }

    void put(const std::string& id, const std::string& data,
             const std::string& content_type = "video/mp4") {
        storage_->upload(id, data, content_type, "clip.mp4");
        store_->insert_media(id, "@alice:test", content_type, "clip.mp4",
                             static_cast<int64_t>(data.size()), "/x/" + id);
    }

    httplib::Result get(const std::string& id, const std::string& range = "",
                        bool with_token = true) {
        httplib::Client cli("127.0.0.1", port_);
        cli.set_read_timeout(10);
        httplib::Headers h;
        if (with_token) h.emplace("Authorization", "Bearer " + token_);
        if (!range.empty()) h.emplace("Range", range);
        return cli.Get("/_matrix/media/v3/download/test/" + id, h);
    }

    std::filesystem::path dir_;
    std::shared_ptr<LocalStorage> storage_;
    std::unique_ptr<SqliteStore> store_;
    std::shared_ptr<MediaHandler> handler_;
    Config config_;
    httplib::Server svr_;
    std::thread thread_;
    int port_ = 0;
    std::string token_ = "media-token";
};

} // namespace

TEST_F(MediaHttpTest, NoRangeServesWholeObjectWithAcceptRanges) {
    const std::string body = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    put("obj", body);

    auto res = get("obj");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, body);
    EXPECT_EQ(res->get_header_value("Accept-Ranges"), "bytes");
    EXPECT_EQ(res->get_header_value("Content-Type"), "video/mp4");
    EXPECT_EQ(res->get_header_value("Content-Length"), std::to_string(body.size()));
    EXPECT_FALSE(res->has_header("Content-Range"));
}

TEST_F(MediaHttpTest, FirstByte) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=0-0");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "A");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 0-0/26");
    EXPECT_EQ(res->get_header_value("Content-Length"), "1");
}

TEST_F(MediaHttpTest, LastByte) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=25-25");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "Z");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 25-25/26");
}

TEST_F(MediaHttpTest, MiddleWindow) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=10-14");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "KLMNO");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 10-14/26");
}

TEST_F(MediaHttpTest, OpenEndedRange) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=20-");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "UVWXYZ");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 20-25/26");
}

TEST_F(MediaHttpTest, OpenEndedRangeFromZeroIsTheWholeObjectAs206) {
    const std::string body = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    put("obj", body);
    auto res = get("obj", "bytes=0-");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, body);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 0-25/26");
}

TEST_F(MediaHttpTest, SuffixRange) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=-4");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "WXYZ");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 22-25/26");
}

TEST_F(MediaHttpTest, LastPosPastEndClampsToTheEnd) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // RFC 9110 14.1.2: a last-pos at or past the length means "the remainder".
    auto res = get("obj", "bytes=24-9999");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "YZ");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 24-25/26");
}

TEST_F(MediaHttpTest, ZeroLengthSuffixRangeIsUnsatisfiable) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // `bytes=-0` asks for the last zero bytes. There is no satisfiable
    // zero-length range, so 416 with the real length.
    auto res = get("obj", "bytes=-0");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */26");
}

TEST_F(MediaHttpTest, RangeStartingPastEndIsUnsatisfiable) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=26-30");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */26");
}

TEST_F(MediaHttpTest, OpenEndedRangeStartingPastEndIsUnsatisfiable) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=99-");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */26");
}

TEST_F(MediaHttpTest, SuffixLongerThanObjectIsUnsatisfiable) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // Judgement call, documented: cpp-httplib treats an over-long suffix as
    // unsatisfiable rather than clamping to the whole object, and it re-derives
    // the range after the handler returns — so agreeing with it is the only way
    // to keep one consistent answer. We add the Content-Range it omits.
    auto res = get("obj", "bytes=-9999");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */26");
}

TEST_F(MediaHttpTest, MalformedRangeHeadersDoNotThrowOutOfTheHandler) {
    const std::string body = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    put("obj", body);

    for (const char* bad : {"bytes=abc-def", "bytes=", "bytes=1-2-3", "bytes 0-1",
                            "items=0-1", "bytes=-", "bytes=99999999999999999999-",
                            "bytes=5-1", "bytes=x", ""}) {
        auto res = get("obj", bad);
        if (std::string(bad).empty()) continue; // no header at all
        ASSERT_TRUE(res) << "no response for Range: " << bad;
        EXPECT_TRUE(res->status == 416 || res->status == 200 || res->status == 206)
            << "Range: " << bad << " produced " << res->status;
    }

    // The server survived all of it and still serves normally.
    auto res = get("obj", "bytes=0-3");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "ABCD");
}

TEST_F(MediaHttpTest, MultiRangeReturnsMultipartByteranges) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=0-1,10-11");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_NE(res->get_header_value("Content-Type").find("multipart/byteranges"),
              std::string::npos);
    EXPECT_NE(res->body.find("Content-Range: bytes 0-1/26"), std::string::npos);
    EXPECT_NE(res->body.find("Content-Range: bytes 10-11/26"), std::string::npos);
    EXPECT_NE(res->body.find("AB"), std::string::npos);
    EXPECT_NE(res->body.find("KL"), std::string::npos);
}

TEST_F(MediaHttpTest, TooManyRangesIsRejectedNotAmplified) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=0-0,2-2,4-4,6-6,8-8");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */26");
}

TEST_F(MediaHttpTest, EmptyObjectServesZeroBytes) {
    put("empty", "", "text/plain");
    auto res = get("empty");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "");
    EXPECT_EQ(res->get_header_value("Content-Length"), "0");
}

TEST_F(MediaHttpTest, AnyRangeOnAnEmptyObjectIsUnsatisfiable) {
    put("empty", "", "text/plain");
    auto res = get("empty", "bytes=0-0");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 416);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes */0");
}

TEST_F(MediaHttpTest, UnauthenticatedRangeRequestIs401) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    auto res = get("obj", "bytes=0-0", /*with_token=*/false);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
}

TEST_F(MediaHttpTest, QueryParamTokenAuthorisesARangeRequest) {
    put("obj", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    httplib::Client cli("127.0.0.1", port_);
    auto res = cli.Get("/_matrix/media/v3/download/test/obj?access_token=" + token_,
                       {{"Range", "bytes=2-4"}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->body, "CDE");
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 2-4/26");
}

TEST_F(MediaHttpTest, LargeObjectRangesAreCorrectOverTheWire) {
    // 8 MiB is enough that a whole-object read per request would be obvious,
    // and small enough to keep the test fast.
    constexpr size_t kSize = 8u * 1024 * 1024;
    std::string body = synth_bytes(0, kSize);
    put("big", body);

    // Small window deep inside the object.
    {
        auto res = get("big", "bytes=7000000-7000099");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 206);
        ASSERT_EQ(res->body.size(), 100u);
        EXPECT_EQ(res->body, body.substr(7000000, 100));
        EXPECT_EQ(res->get_header_value("Content-Range"),
                  "bytes 7000000-7000099/" + std::to_string(kSize));
    }
    // Final byte.
    {
        auto res = get("big", "bytes=" + std::to_string(kSize - 1) + "-");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 206);
        ASSERT_EQ(res->body.size(), 1u);
        EXPECT_EQ(res->body[0], body[kSize - 1]);
    }
    // Whole object, streamed across many chunks: still byte-exact.
    {
        auto res = get("big");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        ASSERT_EQ(res->body.size(), kSize);
        EXPECT_EQ(fnv1a(res->body), fnv1a(body));
    }
    // A range spanning several 64 KiB chunk boundaries.
    {
        auto res = get("big", "bytes=65530-196619");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 206);
        ASSERT_EQ(res->body.size(), 131090u);
        EXPECT_EQ(res->body, body.substr(65530, 131090));
    }
}

// --- S3 backend: ranged GET rather than fetch-then-slice ---
//
// The deploy config references S3, so the streaming path has to hold there too:
// a small range must become a small transfer, not a whole-object GET the client
// slices. Driven against a stand-in S3 endpoint, which is enough to assert the
// request that goes out and how each status is interpreted.

namespace {

class FakeS3Test : public ::testing::Test {
protected:
    void SetUp() override {
        object_ = synth_bytes(0, 1000);

        // httplib::Server has no Head(); HEAD dispatches to the GET handlers
        // (httplib.h: `req.method == "GET" || req.method == "HEAD"`), which is
        // also how the real S3Client::head_object gets answered.
        svr_.Get("/bucket/(.*)", [this](const httplib::Request& rq, httplib::Response& rs) {
            const bool is_head = rq.method == "HEAD";
            if (!is_head) {
                last_range_ = rq.get_header_value("Range");
                got_range_header_ = rq.has_header("Range");
                ++requests_;
            }

            if (is_head) {
                if (mode_ == Mode::NotFound) {
                    rs.status = 404;
                    return;
                }
                rs.status = 200;
                rs.set_content(object_, "video/mp4"); // body suppressed for HEAD
                return;
            }

            if (mode_ == Mode::NotFound) {
                rs.status = 404;
                rs.set_content("<Error/>", "application/xml");
                return;
            }
            if (mode_ == Mode::Unsatisfiable) {
                rs.status = 416;
                rs.set_content("<Error/>", "application/xml");
                return;
            }
            if (mode_ == Mode::IgnoreRange || !got_range_header_) {
                // Pinning status 200 is what makes this the "endpoint ignored
                // Range" case: httplib only slices a body when the status is
                // 206, so an explicit 200 sends the whole object back.
                rs.status = 200;
                rs.set_content(object_, "video/mp4");
                return;
            }

            // Honour the range the way a real origin does — by handing over the
            // whole representation and letting the serving layer apply the
            // range. Slicing here by hand AND setting 206 makes httplib apply
            // the client's range a second time, to the already-sliced body:
            // `bytes=100-149` against a 50-byte body is unsatisfiable, so the
            // fake origin answered 416 and every ranged-GET test failed against
            // a bug in the test double rather than in S3Client.
            //
            // Leaving status unset lets httplib pick 206, derive Content-Range
            // from the full length, and slice — and answer 416 by itself when
            // the window really is past the end.
            rs.set_content(object_, "video/mp4");
        });

        port_ = svr_.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { svr_.listen_after_bind(); });
        svr_.wait_until_ready();

        cfg_.endpoint = "http://127.0.0.1:" + std::to_string(port_);
        cfg_.access_key = "key";
        cfg_.secret_key = "secret";
        cfg_.bucket = "bucket";
        cfg_.use_path_style = true;
    }

    void TearDown() override {
        svr_.stop();
        if (thread_.joinable()) thread_.join();
    }

    enum class Mode { HonourRange, IgnoreRange, Unsatisfiable, NotFound };

    Mode mode_ = Mode::HonourRange;
    std::string object_;
    std::string last_range_;
    bool got_range_header_ = false;
    size_t requests_ = 0;

    S3Config cfg_;
    httplib::Server svr_;
    std::thread thread_;
    int port_ = 0;
};

} // namespace

TEST_F(FakeS3Test, RangedGetSendsAnInclusiveRangeHeaderAndTransfersOnlyThatWindow) {
    S3Client client(cfg_);

    auto obj = client.get_object_range("media", 100, 50);
    ASSERT_TRUE(obj.has_value());
    // Inclusive on both ends: 100..149, not 100..150.
    EXPECT_EQ(last_range_, "bytes=100-149");
    EXPECT_EQ(obj->data, object_.substr(100, 50));
    // The transfer itself was 50 bytes, not 1000: that is the memory property
    // at the object-store boundary.
    EXPECT_EQ(obj->data.size(), 50u);
}

TEST_F(FakeS3Test, SingleByteRangeTransfersOneByte) {
    S3Client client(cfg_);
    auto obj = client.get_object_range("media", 999, 1);
    ASSERT_TRUE(obj.has_value());
    EXPECT_EQ(last_range_, "bytes=999-999");
    ASSERT_EQ(obj->data.size(), 1u);
    EXPECT_EQ(obj->data[0], object_[999]);
}

TEST_F(FakeS3Test, PlainGetSendsNoRangeHeader) {
    S3Client client(cfg_);
    auto obj = client.get_object("media");
    ASSERT_TRUE(obj.has_value());
    EXPECT_FALSE(got_range_header_);
    EXPECT_EQ(obj->data.size(), object_.size());
}

TEST_F(FakeS3Test, EndpointIgnoringRangeIsSlicedRatherThanReturnedWhole) {
    mode_ = Mode::IgnoreRange;
    S3Client client(cfg_);

    auto obj = client.get_object_range("media", 10, 5);
    ASSERT_TRUE(obj.has_value());
    // Correctness is preserved even against a non-conforming endpoint; the lost
    // memory win is logged as a warning rather than silently swallowed.
    EXPECT_EQ(obj->data, object_.substr(10, 5));
}

TEST_F(FakeS3Test, UnsatisfiableRangeIsAShortReadNotAnError) {
    mode_ = Mode::Unsatisfiable;
    S3Client client(cfg_);

    auto obj = client.get_object_range("media", 5000, 10);
    ASSERT_TRUE(obj.has_value()) << "416 must not look like a missing object";
    EXPECT_TRUE(obj->data.empty());
}

TEST_F(FakeS3Test, MissingObjectIsNullopt) {
    mode_ = Mode::NotFound;
    S3Client client(cfg_);
    EXPECT_FALSE(client.get_object_range("media", 0, 10).has_value());
}

TEST_F(FakeS3Test, ZeroLengthRangeIssuesNoRequestAtAll) {
    S3Client client(cfg_);
    auto obj = client.get_object_range("media", 0, 0);
    ASSERT_TRUE(obj.has_value());
    EXPECT_TRUE(obj->data.empty());
    EXPECT_EQ(requests_, 0u) << "a zero-length window should not hit the network";
}

TEST_F(FakeS3Test, S3StorageStatUsesHeadObject) {
    S3Storage storage(cfg_);
    auto info = storage.stat("media");
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->size, object_.size());
    EXPECT_EQ(info->content_type, "video/mp4");
}

TEST_F(FakeS3Test, S3StorageStatMissingObject) {
    mode_ = Mode::NotFound;
    S3Storage storage(cfg_);
    EXPECT_FALSE(storage.stat("media").has_value());
}

TEST_F(FakeS3Test, S3StorageDownloadRangeMatchesTheInterfaceContract) {
    S3Storage storage(cfg_);
    std::string out;

    ASSERT_TRUE(storage.download_range("media", 0, 1, out));
    EXPECT_EQ(out, object_.substr(0, 1));

    ASSERT_TRUE(storage.download_range("media", 500, 100, out));
    EXPECT_EQ(out, object_.substr(500, 100));

    ASSERT_TRUE(storage.download_range("media", object_.size() - 1, 1, out));
    EXPECT_EQ(out, object_.substr(object_.size() - 1, 1));

    // Zero-length read: success, empty, no request.
    out = "sentinel";
    ASSERT_TRUE(storage.download_range("media", 10, 0, out));
    EXPECT_TRUE(out.empty());

    // Past the end: short (empty) read, not a failure.
    ASSERT_TRUE(storage.download_range("media", 9999, 10, out));
    EXPECT_TRUE(out.empty());
}

TEST_F(FakeS3Test, S3StorageDownloadRangeFailsForAMissingObject) {
    mode_ = Mode::NotFound;
    S3Storage storage(cfg_);
    std::string out = "sentinel";
    EXPECT_FALSE(storage.download_range("media", 0, 10, out));
    EXPECT_TRUE(out.empty());
}

// The handler streams identically over S3: bounded windows, no whole-object GET.
TEST_F(FakeS3Test, HandlerStreamsFromS3InBoundedChunks) {
    HandlerFixture f;
    auto storage = std::make_shared<S3Storage>(cfg_);
    MediaHandler handler(*f.store, f.config, storage);
    f.register_media("media", static_cast<int64_t>(object_.size()));

    httplib::Request req;
    init_media_request(req, "media", f.token, "bytes=200-299");
    httplib::Response res;
    handler.handle_download(req, res);

    ASSERT_TRUE(res.content_provider_ != nullptr);
    EXPECT_EQ(res.content_length_, object_.size());

    auto d = drain_provider(res, 200, 100);
    ASSERT_TRUE(d.ok);
    EXPECT_EQ(d.bytes, 100u);
    EXPECT_EQ(d.hash, fnv1a(object_.substr(200, 100)));
    // Exactly one ranged GET for the window, and it was a ranged GET.
    EXPECT_EQ(last_range_, "bytes=200-299");
}

// ── HEAD on the download endpoint ─────────────────────────────────────────
//
// Nothing registers a HEAD route: Server::setup_routes calls svr_.Get() only.
// httplib dispatches HEAD to the Get handler table, so HEAD "should" work — but
// nobody had ever verified it, and "should" is not a test. Two things matter and
// neither is visible in a normal GET test:
//   1. the metadata a client uses to decide whether to range-request at all
//      (Content-Length, Accept-Ranges, Content-Type) must be right;
//   2. HEAD must not READ the object. A HEAD that walks the content provider to
//      completion would be a full-size storage read serving a zero-byte response
//      — invisible to every existing assertion, and a free amplification lever
//      for anyone who can reach the endpoint.
class MediaHeadTest : public ::testing::Test {
protected:
    static constexpr size_t kSize = 8 * 1024 * 1024;

    void SetUp() override {
        storage_ = std::make_shared<CountingStorage>(kSize);
        config_ = Config::defaults();
        config_.server_name = "test";
        config_.require_media_auth = true;
        store_ = std::make_unique<SqliteStore>(":memory:");
        store_->initialize();
        store_->create_user("@alice:test", "x");
        store_->store_access_token(token_, "@alice:test", "dev");
        store_->insert_media("obj", "@alice:test", "video/mp4", "clip.mp4",
                             static_cast<int64_t>(kSize), "counting://object");

        handler_ = std::make_shared<MediaHandler>(*store_, config_, storage_);
        svr_.Get(R"(/_matrix/media/v3/download/([^/]+)/([^/]+))",
                 [h = handler_](const httplib::Request& rq, httplib::Response& rs) {
                     h->handle_download(rq, rs);
                 });
        port_ = svr_.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { svr_.listen_after_bind(); });
        svr_.wait_until_ready();
    }

    void TearDown() override {
        svr_.stop();
        if (thread_.joinable()) thread_.join();
    }

    httplib::Headers auth(const std::string& range = "") const {
        httplib::Headers h{{"Authorization", "Bearer " + token_}};
        if (!range.empty()) h.emplace("Range", range);
        return h;
    }

    httplib::Client client() const {
        httplib::Client cli("127.0.0.1", port_);
        cli.set_read_timeout(20);
        return cli;
    }

    std::shared_ptr<CountingStorage> storage_;
    std::unique_ptr<SqliteStore> store_;
    std::shared_ptr<MediaHandler> handler_;
    Config config_;
    httplib::Server svr_;
    std::thread thread_;
    int port_ = 0;
    std::string token_ = "media-token";
};

TEST_F(MediaHeadTest, HeadIsRoutedToTheGetHandlerAndReturnsTheMetadata) {
    auto res = client().Head("/_matrix/media/v3/download/test/obj", auth());
    ASSERT_TRUE(res) << "HEAD did not reach a handler at all";
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("Content-Length"), std::to_string(kSize));
    // The client-visible contract. Note this assertion does NOT pin
    // MediaHandler's own set_header call: httplib adds `Accept-Ranges: bytes` to
    // a HEAD response when the handler did not (see `req.method == "HEAD" &&
    // !res.has_header("Accept-Ranges")` in httplib.h), so it would still hold
    // with our line deleted. The GET path, which httplib does not backstop, is
    // what pins it — see MediaHttpTest.NoRangeServesWholeObjectWithAcceptRanges.
    // Confirmed by mutation: deleting the handler's header fails the GET test and
    // not this one.
    EXPECT_EQ(res->get_header_value("Accept-Ranges"), "bytes")
        << "a client cannot know it may range-request without this";
    EXPECT_EQ(res->get_header_value("Content-Type"), "video/mp4");
    EXPECT_TRUE(res->body.empty()) << "HEAD returned a body of " << res->body.size() << " bytes";

    // The metadata came from stat(), which is the cheap path.
    EXPECT_GE(storage_->stat_calls, 1);
}

TEST_F(MediaHeadTest, HeadDoesNotReadTheObject) {
    auto res = client().Head("/_matrix/media/v3/download/test/obj", auth());
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);

    // The property. A HEAD that drained the content provider would read all
    // 8 MB to produce nothing, and every existing test would still pass.
    EXPECT_EQ(storage_->whole_object_reads, 0)
        << "HEAD reached MediaStorage::download() — the whole-object read is back";
    EXPECT_EQ(storage_->bytes_read, 0u)
        << "HEAD read " << storage_->bytes_read << " bytes to serve a zero-byte response";

    // Control: the very same object over GET DOES read, so the zero above is
    // HEAD's doing and not a broken fixture.
    auto get = client().Get("/_matrix/media/v3/download/test/obj", auth());
    ASSERT_TRUE(get);
    ASSERT_EQ(get->status, 200);
    EXPECT_EQ(storage_->bytes_read, kSize);
}

TEST_F(MediaHeadTest, HeadHonoursARangeWithoutReadingIt) {
    auto res = client().Head("/_matrix/media/v3/download/test/obj", auth("bytes=0-99"));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 206);
    EXPECT_EQ(res->get_header_value("Content-Range"), "bytes 0-99/" + std::to_string(kSize));
    EXPECT_TRUE(res->body.empty());
    EXPECT_EQ(storage_->bytes_read, 0u) << "a ranged HEAD still read the range";
}

TEST_F(MediaHeadTest, HeadIsRefusedAndCappedExactlyLikeGet) {
    // Unauthenticated: HEAD must not become a metadata oracle that GET is not.
    auto anon = client().Head("/_matrix/media/v3/download/test/obj");
    ASSERT_TRUE(anon);
    EXPECT_EQ(anon->status, 401);

    // Unknown object.
    auto missing = client().Head("/_matrix/media/v3/download/test/nope", auth());
    ASSERT_TRUE(missing);
    EXPECT_EQ(missing->status, 404);

    // The multi-range cap applies to HEAD too — otherwise HEAD would be the
    // cheaper way to make the server do the fan-out work.
    auto capped = client().Head("/_matrix/media/v3/download/test/obj",
                                auth("bytes=0-0,2-2,4-4,6-6,8-8"));
    ASSERT_TRUE(capped);
    EXPECT_EQ(capped->status, 416);
    EXPECT_EQ(capped->get_header_value("Content-Range"), "bytes */" + std::to_string(kSize));
    EXPECT_EQ(storage_->bytes_read, 0u);
}

// ── Upload rejections ─────────────────────────────────────────────────────
//
// The empty-upload refusal previously answered `M_NOT_JSON` on an endpoint that
// takes a raw binary body and never parses JSON at all — a code that pointed at a
// problem which could not exist. The status was always right; only the code was
// misleading, and nothing anywhere compared against it.
TEST_F(MediaHeadTest, AnEmptyUploadIsRefusedAsAnInvalidParameterNotAsBadJson) {
    httplib::Request req;
    req.path = "/_matrix/media/v3/upload";
    req.body = "";
    req.set_header("Authorization", "Bearer " + token_);
    req.set_header("Content-Type", "image/png");
    httplib::Response res;
    handler_->handle_upload(req, res);

    ASSERT_EQ(res.status, 400) << res.body;
    auto body = nlohmann::json::parse(res.body);
    EXPECT_EQ(body.value("errcode", ""), "M_INVALID_PARAM");
    EXPECT_NE(body.value("errcode", ""), "M_NOT_JSON")
        << "this endpoint takes a binary body and never parses JSON";
    // Assert on the reason, not merely the status: a 400 from some other guard
    // (auth, content type, size) would be the right code for the wrong cause.
    EXPECT_NE(body.value("error", "").find("file data"), std::string::npos) << res.body;

    // And nothing was stored — a refused upload must not leave a media row behind.
    EXPECT_EQ(storage_->stat_calls, 0);
}
