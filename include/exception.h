#ifndef _LIBGQUIC_EXCEPTION_H
#define _LIBGQUIC_EXCEPTION_H

#define GQUIC_EXCEPTION_INSUFFICIENT_CAPACITY   -10000001
#define GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED    -10000002
#define GQUIC_EXCEPTION_ALLOCATION_FAILED       -10000003
#define GQUIC_EXCEPTION_INITIAL_FAILED          -10000004
#define GQUIC_SUCCESS 0

#define GQUIC_ASSERT(exception, expression) ((exception = (expression)) != GQUIC_SUCCESS)

#endif
