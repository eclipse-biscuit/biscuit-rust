use inline_c::assert_c;

#[test]
fn build() {
    (assert_c! {
            #include <stdio.h>
            #include <string.h>
            #include <inttypes.h>
            #include "biscuit_auth.h"

            int main() {
                char *seed = "abcdefghabcdefghabcdefghabcdefgh";

                KeyPair * root_kp = key_pair_new((const uint8_t *) seed, strlen(seed), 0);
                printf("key_pair creation error? %s\n", error_message());
                PublicKey* root = key_pair_public(root_kp);

                BiscuitBuilder* b = biscuit_builder();
                printf("builder creation error? %s\n", error_message());
                biscuit_builder_add_fact(b, "right(\"file1\", \"read\")");

                printf("builder add authority error? %s\n", error_message());

                Biscuit * biscuit = biscuit_builder_build(b, root_kp, (const uint8_t * ) seed, strlen(seed));
                printf("biscuit creation error? %s\n", error_message());

                BlockBuilder* bb = create_block();
                block_builder_add_check(bb, "check if operation(\"read\")");
                block_builder_add_fact(bb, "hello(\"world\")");
                printf("builder add check error? %s\n", error_message());

                char *seed2 = "ijklmnopijklmnopijklmnopijklmnop";

                KeyPair * kp2 = key_pair_new((const uint8_t *) seed2, strlen(seed2), 0);

                Biscuit* b2 = biscuit_append_block(biscuit, bb, kp2);
                printf("biscuit append error? %s\n", error_message());

                AuthorizerBuilder * ab = authorizer_builder();
                printf("authorizer builder creation error? %s\n", error_message());

                authorizer_builder_add_check(ab, "check if right(\"efgh\")");
                printf("authorizer builder add check error? %s\n", error_message());

                authorizer_builder_add_policy(ab, "allow if true");
                printf("authorizer builder add policy error? %s\n", error_message());

                Authorizer * authorizer = authorizer_builder_build(ab, b2);
                printf("authorizer creation error? %s\n", error_message());

                if(!authorizer_authorize(authorizer)) {
                    printf("authorizer error(code = %d): %s\n", error_kind(), error_message());

                    if(error_kind() == LogicUnauthorized) {
                        uint64_t error_count = error_check_count();
                        printf("failed checks (%" PRIu64 "):\n", error_count);

                        for(uint64_t i = 0; i < error_count; i++) {
                            if(error_check_is_authorizer(i)) {
                                uint64_t check_id = error_check_id(i);
                                const char* rule = error_check_rule(i);

                                printf("  Authorizer check %" PRIu64 ": %s\n", check_id, rule);
                            } else {
                                uint64_t check_id = error_check_id(i);
                                uint64_t block_id = error_check_block_id(i);
                                const char* rule = error_check_rule(i);
                                printf("  Block %" PRIu64 ", check %" PRIu64 ": %s\n", block_id, check_id, rule);
                            }

                        }
                    }
                } else {
                    printf("authorizer succeeded\n");
                }
                char* world_print = authorizer_print(authorizer);
                printf("authorizer world:\n%s\n", world_print);
                string_free(world_print);

                uint64_t sz = biscuit_serialized_size(b2);
                printf("serialized size: %" PRIu64 "\n", sz);
                uint8_t * buffer = malloc(sz);
                uint64_t written = biscuit_serialize(b2, buffer);
                printf("wrote %" PRIu64 " bytes\n", written);

                const char *biscuit_source = biscuit_print_block_source(b2, 0);
                printf("biscuit block 0 source: %s\n", biscuit_source);

                uintptr_t count = biscuit_block_count(b2);
                printf("biscuit block count: %" PRIuPTR "\n", count);

                char *block_context_0 = biscuit_block_context(b2, 0);
                printf("biscuit block 0 context: %s\n", block_context_0);

                free(buffer);
                authorizer_free(authorizer);
                block_builder_free(bb);
                biscuit_free(b2);
                key_pair_free(kp2);
                biscuit_free(biscuit);
                public_key_free(root);
                key_pair_free(root_kp);

                return 0;
            }
        })
        .success()
        .stdout(
            r#"key_pair creation error? (null)
builder creation error? (null)
builder add authority error? (null)
biscuit creation error? (null)
builder add check error? (null)
biscuit append error? (null)
authorizer builder creation error? (null)
authorizer builder add check error? (null)
authorizer builder add policy error? (null)
authorizer creation error? (null)
authorizer error(code = 21): authorization failed: an allow policy matched (policy index: 0), and the following checks failed: Check n°0 in authorizer: check if right("efgh"), Check n°0 in block n°1: check if operation("read")
failed checks (2):
  Authorizer check 0: check if right("efgh")
  Block 1, check 0: check if operation("read")
authorizer world:
// Facts:
// origin: 0
right("file1", "read");
// origin: 1
hello("world");

// Checks:
// origin: 1
check if operation("read");
// origin: authorizer
check if right("efgh");

// Policies:
allow if true;

serialized size: 322
wrote 322 bytes
biscuit block 0 source: right("file1", "read");

biscuit block count: 2
biscuit block 0 context: (null)
"#,
        );
}

#[test]
fn serialize_keys() {
    (assert_c! {
        #include <stdio.h>
        #include <string.h>
        #include "biscuit_auth.h"

        int main() {
            char *seed = "abcdefghabcdefghabcdefghabcdefgh";
            uint8_t * priv_buf = malloc(32);
            uint8_t * pub_buf = malloc(32);


            KeyPair * kp = key_pair_new((const uint8_t *) seed, strlen(seed), 0);
            printf("key_pair creation error? %s\n", error_message());
            PublicKey* pubkey = key_pair_public(kp);

            key_pair_serialize(kp, priv_buf);
            public_key_serialize(pubkey, pub_buf);

            public_key_free(pubkey);
            key_pair_free(kp);
        }
    })
    .success()
    .stdout("key_pair creation error? (null)\n");
}
