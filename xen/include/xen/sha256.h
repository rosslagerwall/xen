/* sha2.h

   The sha2 family of hash functions.

   Copyright (C) 2001, 2012 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/
 
#ifndef SHA_256_H
#define SHA_256_H

#include <xen/types.h>

/* SHA256 */

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

/* Digest is kept internally as 8 32-bit words. */
#define _SHA256_DIGEST_LENGTH 8

struct sha256_ctx
{
    uint32_t state[_SHA256_DIGEST_LENGTH];    /* State variables */
    uint64_t count;                           /* 64-bit block count */
    uint8_t block[SHA256_BLOCK_SIZE];         /* SHA256 data buffer */
    unsigned int index;                       /* index into buffer */
};

void sha256_init(struct sha256_ctx *ctx);

void sha256_update(struct sha256_ctx *ctx,
                   size_t length,
                   const uint8_t *data);

void
sha256_digest(struct sha256_ctx *ctx,
              size_t length,
              uint8_t *digest);

#endif /* SHA_256_H */
