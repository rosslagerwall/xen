/* mpi.h  -  Multi Precision Integers
 *        Copyright (C) 1994, 1996, 1998, 1999,
 *                    2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * Note: This code is heavily based on the GNU MP Library.
 *         Actually it's the same code with only minor changes in the
 *         way the data is stored; this is to support the abstraction
 *         of an optional secure memory allocation which may be used
 *         to avoid revealing of sensitive data due to paging etc.
 *         The GNU MP Library itself is published under the LGPL;
 *         however I decided to publish this code under the plain GPL.
 */

#ifndef MPI_H
#define MPI_H

#include <xen/types.h>

#define BYTES_PER_MPI_LIMB      (BITS_PER_LONG / 8)
#define BITS_PER_MPI_LIMB       BITS_PER_LONG

typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;

struct mpi {
    int alloced;        /* array size (# of allocated limbs) */
    int nlimbs;         /* number of valid limbs */
    int nbits;          /* the real number of valid bits (info only) */
    int sign;           /* indicates a negative number */
    unsigned flags;     /* bit 0: array must be allocated in secure memory space */
    /* bit 1: not used */
    /* bit 2: the limb is a pointer to some m_alloced data */
    mpi_limb_t *d;      /* array with the limbs */
};

typedef struct mpi *MPI;

MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
MPI mpi_read_raw_data(const void *xbuffer, size_t nbytes);
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod);
int mpi_cmp_ui(MPI u, unsigned long v);
int mpi_cmp(MPI u, MPI v);
unsigned mpi_get_nbits(MPI a);
int mpi_test_bit(MPI a, unsigned int n);

#endif /* MPI_H */
