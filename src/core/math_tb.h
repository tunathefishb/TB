#ifndef TB_MATH_H
#define TB_MATH_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TB_NAN      ((double)NAN)
#define TB_INFINITY ((double)INFINITY)
#define TB_PI       3.14159265358979323846264338327950288
#define TB_E        2.71828182845904523536028747135266250

#define tb_isnan(x)    isnan(x)
#define tb_isinf(x)    isinf(x)
#define tb_isfinite(x) isfinite(x)
#define tb_signbit(x)  (signbit(x) != 0)
#define tb_fabs(x)     fabs(x)
#define tb_trunc(x)    trunc(x)
#define tb_floor(x)    floor(x)
#define tb_ceil(x)     ceil(x)
#define tb_ldexp(x, n) ldexp((x), (n))
#define tb_fmod(x, y)  fmod((x), (y))
#define tb_sqrt(x)     sqrt(x)
#define tb_exp(x)      exp(x)
#define tb_log(x)      log(x)
#define tb_log10(x)    log10(x)
#define tb_sin(x)      sin(x)
#define tb_cos(x)      cos(x)
#define tb_tan(x)      tan(x)
#define tb_atan2(y, x) atan2((y), (x))

/* ECMAScript Math.round: rounds -0.5 to -0.0 (unlike C99 round(-0.5) == -1.0) */
static inline double tb_round(double x) {
    if (!isfinite(x) || x == 0.0) return x;
    if (fabs(x) >= 4503599627370496.0) return x;
    if (x > 0.0) return floor(x + 0.5);
    if (x >= -0.5) return -0.0;
    return floor(x + 0.5);
}

/* ECMAScript Math.pow: pow(±1, ±Infinity) must return NaN (unlike C99 pow == 1.0) */
static inline double tb_pow(double x, double y) {
    if (y == 0.0) return 1.0;
    if (isnan(x) || isnan(y)) return TB_NAN;
    if (fabs(x) == 1.0 && isinf(y)) return TB_NAN;
    return pow(x, y);
}

/* Gregorian UTC calendar helpers backed by libc timegm / gmtime_r */
static inline int64_t tb_unix_from_civil(int year, int month, int day,
                                         int hour, int min, int sec) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year  = year - 1900;
    tm.tm_mon   = month - 1;
    tm.tm_mday  = day;
    tm.tm_hour  = hour;
    tm.tm_min   = min;
    tm.tm_sec   = sec;
    tm.tm_isdst = 0;
    return (int64_t)timegm(&tm);
}

static inline void tb_civil_from_unix(int64_t unix_sec, int *year, int *month, int *day,
                                      int *hour, int *min, int *sec) {
    time_t t = (time_t)unix_sec;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    gmtime_r(&t, &tm);
    *year  = tm.tm_year + 1900;
    *month = tm.tm_mon + 1;
    *day   = tm.tm_mday;
    *hour  = tm.tm_hour;
    *min   = tm.tm_min;
    *sec   = tm.tm_sec;
}

static inline void tb_utc_to_iso8601(double epoch_ms, char *out, size_t cap) {
    if (!out || cap == 0) return;
    if (!isfinite(epoch_ms)) {
        snprintf(out, cap, "Invalid Date");
        return;
    }
    int64_t ms_total  = (int64_t)floor(epoch_ms);
    int64_t sec_total = ms_total / 1000LL;
    int ms = (int)(ms_total % 1000LL);
    if (ms < 0) {
        ms += 1000;
        sec_total -= 1;
    }
    int y, mo, d, h, mi, s;
    tb_civil_from_unix(sec_total, &y, &mo, &d, &h, &mi, &s);
    snprintf(out, cap, "%04d-%02u-%02uT%02u:%02u:%02u.%03uZ",
             y, (unsigned)mo % 100U, (unsigned)d % 100U,
             (unsigned)h % 100U, (unsigned)mi % 100U,
             (unsigned)s % 100U, (unsigned)ms % 1000U);
}

#endif /* TB_MATH_H */
