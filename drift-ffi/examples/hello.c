/*
 * Minimal DRIFT FFI sanity test in C.
 *
 * Binds two transports on loopback (Alice + Bob), Alice sends a
 * greeting, Bob receives it, Bob echoes it back, Alice reads the
 * echo. Prints a pass/fail summary at the end.
 *
 * Build: see the Makefile in this directory.
 *   make hello
 *   ./hello
 */

#include "../drift.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char *err_name(enum DriftResult r) {
    switch (r) {
        case DRIFT_OK:                       return "OK";
        case DRIFT_ERR_INVALID_ADDR:         return "INVALID_ADDR";
        case DRIFT_ERR_UNKNOWN_PEER:         return "UNKNOWN_PEER";
        case DRIFT_ERR_AUTH_FAILED:          return "AUTH_FAILED";
        case DRIFT_ERR_PACKET_TOO_SHORT:     return "PACKET_TOO_SHORT";
        case DRIFT_ERR_SESSION_EXHAUSTED:    return "SESSION_EXHAUSTED";
        case DRIFT_ERR_HANDSHAKE_EXHAUSTED:  return "HANDSHAKE_EXHAUSTED";
        case DRIFT_ERR_QUEUE_FULL:           return "QUEUE_FULL";
        case DRIFT_ERR_TIMEOUT:              return "TIMEOUT";
        case DRIFT_ERR_IO:                   return "IO";
        case DRIFT_ERR_INVALID_ARGUMENT:     return "INVALID_ARGUMENT";
        case DRIFT_ERR_INTERNAL:             return "INTERNAL";
    }
    return "UNKNOWN";
}

#define CHECK(expr) do { \
    enum DriftResult _r = (expr); \
    if (_r != DRIFT_OK) { \
        fprintf(stderr, "FAIL at %s:%d: %s returned %s\n", \
                __FILE__, __LINE__, #expr, err_name(_r)); \
        return 1; \
    } \
} while (0)

int main(void) {
    /* --- Generate keypairs up front so we can pre-register
     *     each side on the other before handshaking. --- */
    struct DriftIdentity *alice_id = drift_identity_generate();
    struct DriftIdentity *bob_id   = drift_identity_generate();
    if (!alice_id || !bob_id) {
        fprintf(stderr, "identity generate failed\n");
        return 1;
    }

    uint8_t alice_pub[32], bob_pub[32];
    CHECK(drift_identity_public_key(alice_id, alice_pub));
    CHECK(drift_identity_public_key(bob_id,   bob_pub));

    /* --- Bind Bob. Passing the identity handle transfers
     *     ownership to the transport; do not free it. --- */
    struct DriftTransport *bob = NULL;
    CHECK(drift_transport_bind("127.0.0.1:0", bob_id, &bob));

    /* Learn Bob's actual bound port via the new local_addr
     * accessor — kernel-assigned because we bound to :0. */
    char bob_addr[64] = {0};
    CHECK(drift_transport_local_addr(bob, bob_addr, sizeof(bob_addr)));
    printf("Bob bound on %s\n", bob_addr);

    /* Pre-register Alice on Bob as a Responder peer. Bob will
     * learn Alice's real source address from the first HELLO;
     * 0.0.0.0:0 is just a placeholder. */
    uint8_t alice_pid[8];
    CHECK(drift_transport_add_peer(bob, alice_pub, "0.0.0.0:0",
                                   0 /* responder */, alice_pid));

    /* --- Bind Alice, register Bob as her Initiator peer. --- */
    struct DriftTransport *alice = NULL;
    CHECK(drift_transport_bind("127.0.0.1:0", alice_id, &alice));

    uint8_t bob_pid[8];
    CHECK(drift_transport_add_peer(alice, bob_pub, bob_addr,
                                   1 /* initiator */, bob_pid));

    /* --- Alice → Bob: "hello from C" --- */
    const char *msg = "hello from C";
    CHECK(drift_transport_send_data(alice, bob_pid,
                                    (const uint8_t *)msg, strlen(msg),
                                    0 /* deadline */, 0 /* coalesce */));

    struct DriftMessage *got = NULL;
    CHECK(drift_transport_recv(bob, 5000, &got));
    size_t n = drift_message_payload_len(got);
    const uint8_t *payload = drift_message_payload(got);
    printf("Bob received %zu bytes: \"%.*s\"\n", n, (int)n, payload);

    uint8_t from[8];
    CHECK(drift_message_peer_id(got, from));

    /* --- Bob echoes back to Alice. --- */
    CHECK(drift_transport_send_data(bob, from, payload, n, 0, 0));
    drift_message_free(got);
    got = NULL;

    CHECK(drift_transport_recv(alice, 5000, &got));
    size_t n2 = drift_message_payload_len(got);
    const uint8_t *echo = drift_message_payload(got);
    printf("Alice received echo (%zu bytes): \"%.*s\"\n",
           n2, (int)n2, echo);

    int ok = (n2 == strlen(msg)) && memcmp(echo, msg, n2) == 0;

    uint64_t alice_hs = drift_transport_handshakes_completed(alice);
    uint64_t bob_hs   = drift_transport_handshakes_completed(bob);
    printf("handshakes_completed: alice=%llu bob=%llu\n",
           (unsigned long long)alice_hs, (unsigned long long)bob_hs);

    drift_message_free(got);
    drift_transport_free(alice);
    drift_transport_free(bob);

    if (ok) {
        printf("PASS\n");
        return 0;
    } else {
        printf("FAIL: echo mismatch\n");
        return 1;
    }
}
