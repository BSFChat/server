#include <gtest/gtest.h>
#include "auth/LocalAuth.h"
#include "store/SqliteStore.h"

#include <bsfchat/Identifiers.h>

using namespace bsfchat;

TEST(LocalAuth, HashAndVerify) {
    auto hash = hash_password("mysecret", 10);
    EXPECT_TRUE(hash.starts_with("$pbkdf2$"));
    EXPECT_TRUE(verify_password("mysecret", hash));
    EXPECT_FALSE(verify_password("wrongpassword", hash));
}

TEST(LocalAuth, DifferentHashesForSamePassword) {
    auto h1 = hash_password("test", 10);
    auto h2 = hash_password("test", 10);
    EXPECT_NE(h1, h2); // different salts
    EXPECT_TRUE(verify_password("test", h1));
    EXPECT_TRUE(verify_password("test", h2));
}

class StoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<SqliteStore>(":memory:");
        store->initialize();
    }

    std::unique_ptr<SqliteStore> store;
};

TEST_F(StoreTest, CreateUser) {
    EXPECT_TRUE(store->create_user("@alice:test", hash_password("pass", 10)));
    EXPECT_TRUE(store->user_exists("@alice:test"));
    EXPECT_FALSE(store->user_exists("@bob:test"));
}

TEST_F(StoreTest, DuplicateUser) {
    EXPECT_TRUE(store->create_user("@alice:test", hash_password("pass", 10)));
    EXPECT_FALSE(store->create_user("@alice:test", hash_password("pass2", 10)));
}

TEST_F(StoreTest, AccessTokens) {
    store->create_user("@alice:test", hash_password("pass", 10));
    store->store_access_token("tok123", "@alice:test", "DEVICE1");

    auto user = store->get_user_by_token("tok123");
    ASSERT_TRUE(user.has_value());
    EXPECT_EQ(*user, "@alice:test");

    EXPECT_FALSE(store->get_user_by_token("invalid").has_value());

    store->delete_access_token("tok123");
    EXPECT_FALSE(store->get_user_by_token("tok123").has_value());
}

TEST_F(StoreTest, PasswordVerification) {
    auto pw_hash = hash_password("secret123", 10);
    store->create_user("@alice:test", pw_hash);

    auto stored = store->get_password_hash("@alice:test");
    ASSERT_TRUE(stored.has_value());
    EXPECT_TRUE(verify_password("secret123", *stored));
    EXPECT_FALSE(verify_password("wrongpass", *stored));
}
