#include <gtest/gtest.h>

#include "storage/LocalStorage.h"
#include "storage/S3Client.h"
#include "store/SqliteStore.h"

#include <filesystem>
#include <fstream>

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
