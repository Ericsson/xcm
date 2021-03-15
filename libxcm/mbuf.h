/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef MBUF
#define MBUF

/* A 'mbuf' serves as a message buffer for a yet-to-be-completed, and
   this module also deals with message wire encoding */

#include "util.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MBUF_MSG_MAX (65535)
#define MBUF_HDR_LEN (sizeof(uint32_t))
#define MBUF_WIRE_MAX (MBUF_MSG_MAX+MBUF_HDR_LEN)

struct mbuf
{
    char *wire_data;
    uint32_t wire_capacity;
    uint32_t wire_len;
};

#define MBUF_UNUSED __attribute__ ((unused))

static void mbuf_init(struct mbuf *b) MBUF_UNUSED;

static void mbuf_deinit(struct mbuf *b) MBUF_UNUSED;

static void mbuf_wire_ensure_capacity(struct mbuf *b, uint32_t capacity)
    MBUF_UNUSED;

static void mbuf_wire_ensure_spare_capacity(struct mbuf *b,
					    uint32_t spare_capacity)
    MBUF_UNUSED;

static void mbuf_wire_appended(struct mbuf *b, int bytes_appended)
    MBUF_UNUSED;

static void *mbuf_wire_start(struct mbuf *b) MBUF_UNUSED;

static void *mbuf_wire_end(struct mbuf *b) MBUF_UNUSED;

static int mbuf_wire_len(struct mbuf *b) MBUF_UNUSED;

static int mbuf_wire_capacity_left(struct mbuf *b) MBUF_UNUSED;

static bool mbuf_is_empty(struct mbuf *b) MBUF_UNUSED;

static bool mbuf_is_partial(struct mbuf *b) MBUF_UNUSED;

static void mbuf_set(struct mbuf *b, const void *msg, uint32_t msg_len)
    MBUF_UNUSED;

static int mbuf_hdr_left(struct mbuf *b) MBUF_UNUSED;

static bool mbuf_has_complete_hdr(struct mbuf *b) MBUF_UNUSED;

static bool mbuf_is_hdr_valid(struct mbuf *b) MBUF_UNUSED;

static uint32_t mbuf_complete_payload_len(struct mbuf *b) MBUF_UNUSED;

static uint32_t mbuf_payload_buffered(struct mbuf *b) MBUF_UNUSED;

static int mbuf_payload_left(struct mbuf *b) MBUF_UNUSED;

static bool mbuf_is_complete(struct mbuf *b) MBUF_UNUSED;

static void *mbuf_payload_start(struct mbuf *b) MBUF_UNUSED;

static void mbuf_init(struct mbuf *b)
{
    b->wire_len = 0;
    b->wire_capacity = 0;
    b->wire_data = NULL;
}

static void mbuf_deinit(struct mbuf *b)
{
    if (b)
	free(b->wire_data);
}

static void mbuf_reset(struct mbuf *b)
{
    b->wire_len = 0;
}

static void mbuf_wire_ensure_capacity(struct mbuf *b, uint32_t capacity)
{
    if (b->wire_capacity < capacity) {
	b->wire_data = ut_realloc(b->wire_data, capacity);
	b->wire_capacity = capacity;
	assert(capacity <= MBUF_WIRE_MAX);
    }
}


static void mbuf_wire_ensure_spare_capacity(struct mbuf *b, uint32_t spare_capacity)
{
    mbuf_wire_ensure_capacity(b, b->wire_len + spare_capacity);
}


static void mbuf_wire_appended(struct mbuf *b, int bytes_appended)
{
    b->wire_len += bytes_appended;
    assert(b->wire_len <= b->wire_capacity);
}

static void *mbuf_wire_start(struct mbuf *b)
{
    return b->wire_data;
}

static void *mbuf_wire_end(struct mbuf *b)
{
    return b->wire_data + b->wire_len;
}

static int mbuf_wire_len(struct mbuf *b)
{
    return b->wire_len;
}

static int mbuf_wire_capacity_left(struct mbuf *b)
{
    return MBUF_WIRE_MAX - b->wire_len;
}

static bool mbuf_is_empty(struct mbuf *b)
{
    return mbuf_wire_len(b) == 0;
}

static bool mbuf_is_partial(struct mbuf *b)
{
    return !mbuf_is_empty(b) && !mbuf_is_complete(b);
}

static void mbuf_set(struct mbuf *b, const void *msg, uint32_t msg_len)
{
    uint32_t wire_len = MBUF_HDR_LEN+msg_len;
    mbuf_wire_ensure_capacity(b, wire_len);
    uint32_t n_msg_len = htonl(msg_len);

    memcpy(b->wire_data, &n_msg_len, MBUF_HDR_LEN);
    memcpy(b->wire_data + MBUF_HDR_LEN, msg, msg_len);

    b->wire_len = wire_len;
}

static int mbuf_hdr_left(struct mbuf *b)
{
    return b->wire_len < MBUF_HDR_LEN ? MBUF_HDR_LEN - b->wire_len : 0;
}

static bool mbuf_has_complete_hdr(struct mbuf *b)
{
    return mbuf_hdr_left(b) == 0;
}

static bool mbuf_is_hdr_valid(struct mbuf *b)
{
    return  mbuf_has_complete_hdr(b) &&
	mbuf_complete_payload_len(b) <= MBUF_MSG_MAX;
}

static uint32_t mbuf_complete_payload_len(struct mbuf *b)
{
    assert(mbuf_has_complete_hdr(b));
    uint32_t n_msg_len;
    memcpy(&n_msg_len, b->wire_data, sizeof(n_msg_len));
    return ntohl(n_msg_len);
}

static uint32_t mbuf_payload_buffered(struct mbuf *b)
{
    if (mbuf_has_complete_hdr(b))
	return b->wire_len - MBUF_HDR_LEN;
    else
	return 0;
}

static int mbuf_payload_left(struct mbuf *b)
{
    return mbuf_complete_payload_len(b) - mbuf_payload_buffered(b);
}

static bool mbuf_is_complete(struct mbuf *b)
{
    return mbuf_has_complete_hdr(b) &&
	mbuf_complete_payload_len(b) == mbuf_payload_buffered(b);
}

static void *mbuf_payload_start(struct mbuf *b)
{
    return b->wire_data + MBUF_HDR_LEN;
}

#endif
