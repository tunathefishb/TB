#ifndef TB_MATH_H
#define TB_MATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB_NAN      (__builtin_nan(""))
#define TB_INFINITY (__builtin_inf())
#define TB_PI       3.14159265358979323846264338327950288
#define TB_E        2.71828182845904523536028747135266250

typedef union {
    double   d;
    uint64_t u;
} TbDblBits;

static inline bool tb_isnan(double x) {
    TbDblBits b = { .d = x };
    return ((b.u & 0x7FF0000000000000ULL) == 0x7FF0000000000000ULL) &&
           ((b.u & 0x000FFFFFFFFFFFFFULL) != 0ULL);
}

static inline bool tb_isinf(double x) {
    TbDblBits b = { .d = x };
    return (b.u & 0x7FFFFFFFFFFFFFFFULL) == 0x7FF0000000000000ULL;
}

static inline bool tb_isfinite(double x) {
    TbDblBits b = { .d = x };
    return (b.u & 0x7FF0000000000000ULL) != 0x7FF0000000000000ULL;
}

static inline bool tb_signbit(double x) {
    TbDblBits b = { .d = x };
    return (b.u >> 63) != 0ULL;
}

static inline double tb_fabs(double x) {
    TbDblBits b = { .d = x };
    b.u &= 0x7FFFFFFFFFFFFFFFULL;
    return b.d;
}

double tb_trunc(double x);
double tb_floor(double x);
double tb_ceil(double x);
double tb_round(double x);
double tb_ldexp(double x, int n);
double tb_fmod(double x, double y);
double tb_sqrt(double x);
double tb_exp(double x);
double tb_log(double x);
double tb_log10(double x);
double tb_pow(double x, double y);
double tb_sin(double x);
double tb_cos(double x);
double tb_tan(double x);
double tb_atan2(double y, double x);

/* Gregorian UTC calendar helpers (zero libc time.h dependency) */
int64_t tb_unix_from_civil(int year, int month, int day, int hour, int min, int sec);
void    tb_civil_from_unix(int64_t unix_sec, int *year, int *month, int *day,
                           int *hour, int *min, int *sec);
void    tb_utc_to_iso8601(double epoch_ms, char *out, size_t cap);

#endif /* TB_MATH_H */
