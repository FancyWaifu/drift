/*
 * drift-ffi — C ABI for the DRIFT identity-first transport.
 * Auto-generated from drift-ffi/src/lib.rs by cbindgen; do not
 * edit by hand.
 *
 * Opaque handle lifecycle: every `drift_X_new` (or bind/generate)
 * function is paired with `drift_X_free`. Handles are not
 * thread-safe unless explicitly noted; wrap in your own lock
 * if sharing across threads.
 */


#ifndef DRIFT_FFI_H
#define DRIFT_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Every fallible entry point returns one of these.
 */
enum DriftResult {
    DRIFT_OK = 0,
    DRIFT_ERR_INVALID_ADDR = 1,
    DRIFT_ERR_UNKNOWN_PEER = 2,
    DRIFT_ERR_AUTH_FAILED = 3,
    DRIFT_ERR_PACKET_TOO_SHORT = 4,
    DRIFT_ERR_SESSION_EXHAUSTED = 5,
    DRIFT_ERR_HANDSHAKE_EXHAUSTED = 6,
    DRIFT_ERR_QUEUE_FULL = 7,
    DRIFT_ERR_TIMEOUT = 8,
    DRIFT_ERR_IO = 9,
    DRIFT_ERR_INVALID_ARGUMENT = 10,
    DRIFT_ERR_INTERNAL = 99,
};

/**
 * Opaque handle to a DRIFT identity (X25519 keypair).
 */
struct DriftIdentity;

/**
 * Opaque handle to a received message.
 */
struct DriftMessage;

/**
 * Opaque handle to a DRIFT transport (a bound UDP socket +
 * peer table + handshake state machine).
 */
struct DriftTransport;

/**
 * Generate a fresh random identity.
 */
struct DriftIdentity *drift_identity_generate(void);

/**
 * Build an identity deterministically from a 32-byte seed.
 * Returns NULL if `secret` is NULL.
 */
struct DriftIdentity *drift_identity_from_secret(const uint8_t *secret);

/**
 * Copy the 32-byte public key into `out`. Returns non-zero on
 * NULL argument.
 */
enum DriftResult drift_identity_public_key(const struct DriftIdentity *id, uint8_t *out);

/**
 * Copy the 8-byte peer_id (BLAKE2b-truncated pubkey) into
 * `out`. Returns non-zero on NULL argument.
 */
enum DriftResult drift_identity_peer_id(const struct DriftIdentity *id, uint8_t *out);

/**
 * Free an identity. Safe to call with NULL.
 */
void drift_identity_free(struct DriftIdentity *id);

/**
 * Bind a UDP socket and return a transport handle.
 * `addr` is a C string like "0.0.0.0:9000" or "127.0.0.1:0".
 * The identity is consumed (freed on failure too — callers
 * should not free it themselves after this call).
 */
enum DriftResult drift_transport_bind(const char *addr,
                                      struct DriftIdentity *identity,
                                      struct DriftTransport **out);

/**
 * Register a peer by its 32-byte public key and remote address.
 * `initiator` is 1 for the client side (the side that sends
 * HELLO first), 0 for the responder side. On success, `out_pid`
 * receives the 8-byte peer_id used for subsequent operations.
 */
enum DriftResult drift_transport_add_peer(struct DriftTransport *transport,
                                          const uint8_t *peer_pub,
                                          const char *addr,
                                          int initiator,
                                          uint8_t *out_pid);

/**
 * Send an encrypted DATA packet to `peer_id`.
 * `deadline_ms` = 0 disables deadline semantics (short-header
 * fast path eligible). `coalesce_group` = 0 disables coalescing.
 */
enum DriftResult drift_transport_send_data(struct DriftTransport *transport,
                                           const uint8_t *peer_id,
                                           const uint8_t *payload,
                                           uintptr_t payload_len,
                                           uint16_t deadline_ms,
                                           uint32_t coalesce_group);

/**
 * Receive one decrypted DATA packet. Blocks up to `timeout_ms`
 * for a packet; pass 0 to wait forever. On success, `out_msg`
 * receives a handle to be freed with `drift_message_free`.
 * On timeout returns `DRIFT_ERR_TIMEOUT` and writes NULL to
 * `*out_msg`.
 */
enum DriftResult drift_transport_recv(struct DriftTransport *transport,
                                      uint64_t timeout_ms,
                                      struct DriftMessage **out_msg);

/**
 * Current transport metrics. Lightweight snapshot — atomic
 * loads only, no locks.
 */
uint64_t drift_transport_handshakes_completed(const struct DriftTransport *transport);

/**
 * Write the transport's local socket address into `out_buf`
 * as a null-terminated C string (e.g. "127.0.0.1:54321").
 * `buf_len` is the size of `out_buf` including the nul byte
 * (64 bytes is always enough — IPv6 maxes out around 54).
 * On error, `*out_buf` is set to the empty string.
 */
enum DriftResult drift_transport_local_addr(const struct DriftTransport *transport,
                                            char *out_buf,
                                            uintptr_t buf_len);

/**
 * Free a transport. Safe to call with NULL. Aborts all
 * background tasks on drop.
 */
void drift_transport_free(struct DriftTransport *transport);

/**
 * Number of bytes in the payload.
 */
uintptr_t drift_message_payload_len(const struct DriftMessage *msg);

/**
 * Pointer to the payload bytes. Valid until `drift_message_free`
 * is called on this handle.
 */
const uint8_t *drift_message_payload(const struct DriftMessage *msg);

/**
 * Copy the sender peer_id (8 bytes) into `out`.
 */
enum DriftResult drift_message_peer_id(const struct DriftMessage *msg, uint8_t *out);

/**
 * Free a received message. Safe to call with NULL.
 */
void drift_message_free(struct DriftMessage *msg);

#endif  /* DRIFT_FFI_H */
