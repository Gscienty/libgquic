/* include/util/malloc.h 内存申请封装（用于调试）
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_UTIL_MALLOC_H
#define _LIBGQUIC_UTIL_MALLOC_H

#include "exception.h"
#include <stddef.h>

gquic_exception_t gquic_malloc(void **const result, size_t size);
gquic_exception_t gquic_free(void *const ptr);

#define GQUIC_MALLOC_STRUCT(result, type) (gquic_malloc((void **) (result), sizeof(type)))

#endif
