#include "math_tb.h"
#include "common.h"

double tb_trunc(double x) {
    TbDblBits b = { .d = x };
    int e = (int)((b.u >> 52) & 0x7FFULL) - 1023;
    if (e >= 52) return x; /* Already integer, Inf, or NaN */
    if (e < 0) {
        b.u &= 0x8000000000000000ULL; /* Preserve signed zero */
        return b.d;
    }
    uint64_t frac_mask = (1ULL << (52 - e)) - 1ULL;
    b.u &= ~frac_mask;
    return b.d;
}

double tb_floor(double x) {
    if (!tb_isfinite(x) || x == 0.0) return x;
    double t = tb_trunc(x);
    return (x < t) ? (t - 1.0) : t;
}

double tb_ceil(double x) {
    if (!tb_isfinite(x) || x == 0.0) return x;
    double t = tb_trunc(x);
    if (x > t) {
        double r = t + 1.0;
        if (r == 0.0 && tb_signbit(x)) return -0.0;
        return r;
    }
    return t;
}

double tb_round(double x) {
    if (!tb_isfinite(x) || x == 0.0) return x;
    /* Doubles with |x| >= 2^52 have no fractional bits */
    if (tb_fabs(x) >= 4503599627370496.0) return x;
    if (x > 0.0) return tb_floor(x + 0.5);
    if (x >= -0.5) return -0.0;
    return tb_floor(x + 0.5);
}

static double scale_pow2_step(double x, int step) {
    /* step must satisfy -1022 <= step <= 1023 */
    TbDblBits s;
    s.u = (uint64_t)(step + 1023) << 52;
    return x * s.d;
}

double tb_ldexp(double x, int n) {
    if (!tb_isfinite(x) || x == 0.0 || n == 0) return x;
    if (n > 2099) return x * 1e308 * 1e308;
    if (n < -2099) return x * 1e-308 * 1e-308;
    while (n > 1023) {
        x = scale_pow2_step(x, 1023);
        n -= 1023;
    }
    while (n < -1022) {
        x = scale_pow2_step(x, -1022);
        n += 1022;
    }
    return scale_pow2_step(x, n);
}

double tb_fmod(double x, double y) {
    TbDblBits ux = { .d = x };
    TbDblBits uy = { .d = y };
    int ex = (int)((ux.u >> 52) & 0x7FFULL);
    int ey = (int)((uy.u >> 52) & 0x7FFULL);
    uint64_t sx = ux.u & 0x8000000000000000ULL;

    if ((uy.u << 1) == 0ULL || tb_isnan(y) || ex == 0x7FF) {
        return TB_NAN;
    }
    if ((ux.u << 1) <= (uy.u << 1)) {
        if ((ux.u << 1) == (uy.u << 1)) {
            TbDblBits z = { .u = sx };
            return z.d;
        }
        return x;
    }

    /* Normalize x and y into 53-bit integer mantissas [2^52, 2^53) */
    uint64_t mx, my;
    if (ex == 0) {
        uint64_t i = ux.u << 12;
        while ((i >> 63) == 0) { ex--; i <<= 1; }
        mx = i >> 11;
    } else {
        mx = (ux.u & 0x000FFFFFFFFFFFFFULL) | (1ULL << 52);
    }

    if (ey == 0) {
        uint64_t i = uy.u << 12;
        while ((i >> 63) == 0) { ey--; i <<= 1; }
        my = i >> 11;
    } else {
        my = (uy.u & 0x000FFFFFFFFFFFFFULL) | (1ULL << 52);
    }

    /* Exact binary long-division remainder */
    for (; ex > ey; ex--) {
        if (mx >= my) {
            mx -= my;
            if (mx == 0ULL) {
                TbDblBits z = { .u = sx };
                return z.d;
            }
        }
        mx <<= 1;
    }
    if (mx >= my) {
        mx -= my;
        if (mx == 0ULL) {
            TbDblBits z = { .u = sx };
            return z.d;
        }
    }

    /* Renormalize remainder */
    while ((mx >> 52) == 0ULL) {
        mx <<= 1;
        ex--;
    }

    if (ex > 0) {
        ux.u = sx | ((uint64_t)ex << 52) | (mx & 0x000FFFFFFFFFFFFFULL);
    } else {
        /* Subnormal remainder */
        int shift = 1 - ex;
        if (shift >= 64) {
            ux.u = sx;
        } else {
            mx >>= shift;
            ux.u = sx | mx;
        }
    }
    return ux.d;
}

double tb_sqrt(double x) {
    if (tb_isnan(x)) return TB_NAN;
    if (x == 0.0) return x;
    if (x < 0.0) return TB_NAN;
    if (tb_isinf(x)) return TB_INFINITY;
#if defined(__x86_64__) || defined(__SSE2__)
    double res;
    __asm__("sqrtsd %1, %0" : "=x"(res) : "x"(x));
    return res;
#else
    TbDblBits b = { .d = x };
    int e = (int)((b.u >> 52) & 0x7FFULL) - 1023;
    if (e == -1023) {
        b.d *= 18014398509481984.0; /* 2^54 */
        e = (int)((b.u >> 52) & 0x7FFULL) - 1023 - 54;
    }
    b.u = (b.u & 0x000FFFFFFFFFFFFFULL) | (1023ULL << 52);
    double m = b.d;
    if (e & 1) {
        m *= 2.0;
        e--;
    }
    double y = (m > 2.0) ? 1.7 : 1.2;
    for (int i = 0; i < 6; i++) {
        y = 0.5 * (y + m / y);
    }
    return tb_ldexp(y, e / 2);
#endif
}

double tb_exp(double x) {
    if (tb_isnan(x)) return TB_NAN;
    if (x == 0.0) return 1.0;
    if (x > 709.78271289338397) return TB_INFINITY;
    if (x < -745.13321910194110) return 0.0;

    static const double INV_LN2 = 1.44269504088896338700e+00;
    static const double LN2_HI  = 6.93147180369123816490e-01;
    static const double LN2_LO  = 1.90821492927058770002e-10;
    static const double P1 =  1.66666666666666019037e-01;
    static const double P2 = -2.77777777770155933842e-03;
    static const double P3 =  6.61375632143793436117e-05;
    static const double P4 = -1.65339022054652515390e-06;
    static const double P5 =  4.13813679705723846039e-08;

    int k = 0;
    double hi = 0.0, lo = 0.0, r = x;
    if (tb_fabs(x) > 0.34657359027997264) {
        k  = (int)(x * INV_LN2 + (x >= 0.0 ? 0.5 : -0.5));
        hi = x - (double)k * LN2_HI;
        lo = (double)k * LN2_LO;
        r  = hi - lo;
    } else if (tb_fabs(x) < 3.725290298461914e-09) {
        return 1.0 + x;
    } else {
        hi = x;
        lo = 0.0;
    }

    double t = r * r;
    double c = r - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    double y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);
    return (k == 0) ? y : tb_ldexp(y, k);
}

double tb_log(double x) {
    if (tb_isnan(x) || x < 0.0) return TB_NAN;
    if (x == 0.0) return -TB_INFINITY;
    if (tb_isinf(x)) return TB_INFINITY;
    if (x == 1.0) return 0.0;

    static const double LN2_HI = 6.93147180369123816490e-01;
    static const double LN2_LO = 1.90821492927058770002e-10;
    static const double LG1 = 6.666666666666735130e-01;
    static const double LG2 = 3.999999999940941908e-01;
    static const double LG3 = 2.857142874366239149e-01;
    static const double LG4 = 2.222219843214978396e-01;
    static const double LG5 = 1.818357216161805012e-01;
    static const double LG6 = 1.531383769920937332e-01;
    static const double LG7 = 1.479819860511658591e-01;

    TbDblBits b = { .d = x };
    int k = 0;
    if ((b.u >> 52) == 0ULL) {
        b.d *= 18014398509481984.0; /* 2^54 */
        k = -54;
    }
    k += (int)((b.u >> 52) & 0x7FFULL) - 1023;
    uint64_t mant = b.u & 0x000FFFFFFFFFFFFFULL;
    /* Center f around 1.0: if f >= sqrt(2), divide by 2 and increment k */
    if (mant >= 0x0006A09E667F3BCDULL) {
        b.u = mant | (1022ULL << 52);
        k += 1;
    } else {
        b.u = mant | (1023ULL << 52);
    }

    double f   = b.d - 1.0;
    double s   = f / (2.0 + f);
    double z   = s * s;
    double w   = z * z;
    double t1  = w * (LG2 + w * (LG4 + w * LG6));
    double t2  = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    double R   = t2 + t1;
    double hfsq = 0.5 * f * f;
    double dk  = (double)k;
    return dk * LN2_HI - ((hfsq - (s * (hfsq + R) + dk * LN2_LO)) - f);
}

double tb_log10(double x) {
    if (tb_isnan(x) || x < 0.0) return TB_NAN;
    if (x == 0.0) return -TB_INFINITY;
    if (tb_isinf(x)) return TB_INFINITY;
    /* Exact integer powers of 10 in [10^0, 10^22] */
    double p = 1.0;
    for (int i = 0; i <= 22; i++) {
        if (x == p) return (double)i;
        p *= 10.0;
    }
    static const double IVLN10_HI = 4.34294481878168880939e-01;
    static const double IVLN10_LO = 2.50829467116452752298e-11;
    double l = tb_log(x);
    TbDblBits lh = { .d = l };
    lh.u &= 0xFFFFFFFF00000000ULL;
    double l_hi = lh.d;
    double l_lo = l - l_hi;
    return l_hi * IVLN10_HI + (l_lo * IVLN10_HI + l * IVLN10_LO);
}

double tb_pow(double x, double y) {
    if (y == 0.0) return 1.0;
    if (tb_isnan(x) || tb_isnan(y)) return TB_NAN;
    if (tb_fabs(x) == 1.0 && tb_isinf(y)) return TB_NAN;
    if (x == 1.0) return 1.0;
    if (y == 1.0) return x;

    bool y_is_int = tb_isfinite(y) && (tb_floor(y) == y);
    bool y_is_odd = y_is_int && (tb_fabs(tb_fmod(y, 2.0)) == 1.0);

    if (tb_isinf(y)) {
        double ax = tb_fabs(x);
        if (y > 0.0) return (ax > 1.0) ? TB_INFINITY : 0.0;
        return (ax > 1.0) ? 0.0 : TB_INFINITY;
    }
    if (tb_isinf(x)) {
        if (x < 0.0) {
            if (y > 0.0) return y_is_odd ? -TB_INFINITY : TB_INFINITY;
            return y_is_odd ? -0.0 : 0.0;
        }
        return (y > 0.0) ? TB_INFINITY : 0.0;
    }
    if (x == 0.0) {
        if (y < 0.0) return (tb_signbit(x) && y_is_odd) ? -TB_INFINITY : TB_INFINITY;
        return (tb_signbit(x) && y_is_odd) ? -0.0 : 0.0;
    }

    /* Fast exact binary exponentiation for small integer exponents */
    if (y_is_int && tb_fabs(y) <= 64.0) {
        int n = (int)y;
        bool neg_exp = n < 0;
        unsigned int un = (unsigned int)(neg_exp ? -n : n);
        double res  = 1.0;
        double base = x;
        while (un > 0U) {
            if (un & 1U) res *= base;
            un >>= 1;
            if (un > 0U) base *= base;
        }
        return neg_exp ? (1.0 / res) : res;
    }

    if (x < 0.0) {
        if (!y_is_int) return TB_NAN;
        double mag = tb_exp(y * tb_log(-x));
        return y_is_odd ? -mag : mag;
    }
    return tb_exp(y * tb_log(x));
}

static double kernel_sin(double x, double y) {
    static const double S1 = -1.66666666666666324348e-01;
    static const double S2 =  8.33333333332248946124e-03;
    static const double S3 = -1.98412698298579493134e-04;
    static const double S4 =  2.75573137070700676789e-06;
    static const double S5 = -2.50507602534068634195e-08;
    static const double S6 =  1.58969099521155010221e-10;
    double z = x * x;
    double v = z * x;
    double r = S2 + z * (S3 + z * (S4 + z * (S5 + z * S6)));
    return x - ((z * (0.5 * y - v * r) - y) - v * S1);
}

static double kernel_cos(double x, double y) {
    static const double C1 =  4.16666666666666019037e-02;
    static const double C2 = -1.38888888888741095749e-03;
    static const double C3 =  2.48015872894767294178e-05;
    static const double C4 = -2.75573143513906633035e-07;
    static const double C5 =  2.08757232129817482790e-09;
    static const double C6 = -1.13596475577881948265e-11;
    double z  = x * x;
    double r  = z * (C1 + z * (C2 + z * (C3 + z * (C4 + z * (C5 + z * C6)))));
    double hz = 0.5 * z;
    double w  = 1.0 - hz;
    return w + (((1.0 - w) - hz) + (z * r - x * y));
}

static int rem_pio2(double x, double *r_hi, double *r_lo) {
    static const double INV_PIO2 = 6.36619772367581382433e-01;
    static const double PIO2_1   = 1.57079632673412561417e+00;
    static const double PIO2_1T  = 6.12323399573676588613e-11;
    static const double PIO2_2   = 6.12323399573676480357e-11;
    static const double PIO2_2T  = 1.08267081172926885478e-21;

    if (tb_fabs(x) > 1.0e8) {
        x = tb_fmod(x, 6.283185307179586476925286766559);
    }
    double fn = tb_round(x * INV_PIO2);
    int64_t n = (int64_t)fn;
    double r  = x - fn * PIO2_1;
    double w  = fn * PIO2_1T;
    double y  = r - w;
    if (tb_fabs(y) < 1e-9) {
        r = x - fn * PIO2_1;
        w = fn * PIO2_2;
        y = r - w;
        *r_hi = y;
        *r_lo = (r - y) - w - fn * PIO2_2T;
    } else {
        *r_hi = y;
        *r_lo = (r - y) - w;
    }
    return (int)(n & 3);
}

double tb_sin(double x) {
    if (!tb_isfinite(x)) return TB_NAN;
    if (tb_fabs(x) <= 0.7853981633974483) {
        if (tb_fabs(x) < 2.0e-9) return x;
        return kernel_sin(x, 0.0);
    }
    double hi, lo;
    int q = rem_pio2(x, &hi, &lo);
    switch (q & 3) {
        case 0: return  kernel_sin(hi, lo);
        case 1: return  kernel_cos(hi, lo);
        case 2: return -kernel_sin(hi, lo);
        default: return -kernel_cos(hi, lo);
    }
}

double tb_cos(double x) {
    if (!tb_isfinite(x)) return TB_NAN;
    if (tb_fabs(x) <= 0.7853981633974483) {
        if (tb_fabs(x) < 2.0e-9) return 1.0;
        return kernel_cos(x, 0.0);
    }
    double hi, lo;
    int q = rem_pio2(x, &hi, &lo);
    switch (q & 3) {
        case 0: return  kernel_cos(hi, lo);
        case 1: return -kernel_sin(hi, lo);
        case 2: return -kernel_cos(hi, lo);
        default: return  kernel_sin(hi, lo);
    }
}

double tb_tan(double x) {
    if (!tb_isfinite(x)) return TB_NAN;
    if (x == 0.0) return x;
    return tb_sin(x) / tb_cos(x);
}

static double atan_pos(double x) {
    static const double ATANHI[4] = {
        4.63647609000806093515e-01, /* atan(0.5) */
        7.85398163397448278999e-01, /* atan(1.0) */
        9.82793723247329054082e-01, /* atan(1.5) */
        1.57079632679489655800e+00  /* atan(inf) */
    };
    static const double ATANLO[4] = {
        2.26987774529616870924e-17,
        3.06161699786838301793e-17,
        1.39033110312309984516e-17,
        6.12323399573676603587e-17
    };
    static const double A0  =  3.33333333333329318027e-01;
    static const double A1  = -1.99999999998764832476e-01;
    static const double A2  =  1.42857142725034663711e-01;
    static const double A3  = -1.11111104054623557880e-01;
    static const double A4  =  9.09088713343650656196e-02;
    static const double A5  = -7.69187620504482999495e-02;
    static const double A6  =  6.66107313738753120669e-02;
    static const double A7  = -5.83357013379057348645e-02;
    static const double A8  =  4.97687799461593236017e-02;
    static const double A9  = -3.65315727442169155270e-02;
    static const double A10 =  1.62858201153657823623e-02;

    if (x >= 9.007199254740992e15) return ATANHI[3] + ATANLO[3];
    int id = -1;
    if (x >= 0.4375) { /* 7/16 */
        if (x < 1.1875) { /* 19/16 */
            if (x < 0.6875) { /* 11/16 */
                id = 0;
                x = (2.0 * x - 1.0) / (2.0 + x);
            } else {
                id = 1;
                x = (x - 1.0) / (x + 1.0);
            }
        } else {
            if (x < 2.4375) { /* 39/16 */
                id = 2;
                x = (x - 1.5) / (1.0 + 1.5 * x);
            } else {
                id = 3;
                x = -1.0 / x;
            }
        }
    }
    double z  = x * x;
    double w  = z * z;
    double s1 = z * (A0 + w * (A2 + w * (A4 + w * (A6 + w * (A8 + w * A10)))));
    double s2 = w * (A1 + w * (A3 + w * (A5 + w * (A7 + w * A9))));
    if (id < 0) return x - x * (s1 + s2);
    return ATANHI[id] - ((x * (s1 + s2) - ATANLO[id]) - x);
}

double tb_atan2(double y, double x) {
    if (tb_isnan(x) || tb_isnan(y)) return TB_NAN;
    bool sy = tb_signbit(y);
    bool sx = tb_signbit(x);

    if (y == 0.0) {
        if (sx) return sy ? -TB_PI : TB_PI;
        return sy ? -0.0 : 0.0;
    }
    if (x == 0.0) {
        return sy ? (-0.5 * TB_PI) : (0.5 * TB_PI);
    }
    if (tb_isinf(x)) {
        if (tb_isinf(y)) {
            double a = sx ? (0.75 * TB_PI) : (0.25 * TB_PI);
            return sy ? -a : a;
        }
        double a = sx ? TB_PI : 0.0;
        return sy ? -a : a;
    }
    if (tb_isinf(y)) {
        return sy ? (-0.5 * TB_PI) : (0.5 * TB_PI);
    }

    double z = atan_pos(tb_fabs(y / x));
    if (sx) z = TB_PI - z;
    return sy ? -z : z;
}

/* Howard Hinnant's exact Gregorian calendar conversions */
int64_t tb_unix_from_civil(int year, int month, int day, int hour, int min, int sec) {
    int64_t y = year - (month <= 2 ? 1 : 0);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);
    uint32_t m = (uint32_t)(month > 2 ? month - 3 : month + 9);
    uint32_t doy = (153U * m + 2U) / 5U + (uint32_t)day - 1U;
    uint32_t doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    int64_t days = era * 146097LL + (int64_t)doe - 719468LL;
    return days * 86400LL + (int64_t)hour * 3600LL + (int64_t)min * 60LL + (int64_t)sec;
}

void tb_civil_from_unix(int64_t unix_sec, int *year, int *month, int *day,
                        int *hour, int *min, int *sec) {
    int64_t days = unix_sec / 86400LL;
    int64_t rem  = unix_sec % 86400LL;
    if (rem < 0) {
        rem += 86400LL;
        days -= 1;
    }
    *hour = (int)(rem / 3600LL);
    rem %= 3600LL;
    *min  = (int)(rem / 60LL);
    *sec  = (int)(rem % 60LL);

    int64_t z = days + 719468LL;
    int64_t era = (z >= 0 ? z : z - 146096LL) / 146097LL;
    uint32_t doe = (uint32_t)(z - era * 146097LL);
    uint32_t yoe = (doe - doe / 1460U + doe / 36524U - doe / 146096U) / 365U;
    int64_t y = (int64_t)yoe + era * 400LL;
    uint32_t doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
    uint32_t mp  = (5U * doy + 2U) / 153U;
    uint32_t d   = doy - (153U * mp + 2U) / 5U + 1U;
    uint32_t m   = mp < 10U ? mp + 3U : mp - 9U;
    y += (m <= 2U) ? 1 : 0;

    *year  = (int)y;
    *month = (int)m;
    *day   = (int)d;
}

void tb_utc_to_iso8601(double epoch_ms, char *out, size_t cap) {
    if (!out || cap == 0) return;
    if (!tb_isfinite(epoch_ms)) {
        snprintf(out, cap, "Invalid Date");
        return;
    }
    int64_t ms_total = (int64_t)tb_floor(epoch_ms);
    int64_t sec_total = ms_total / 1000LL;
    int ms = (int)(ms_total % 1000LL);
    if (ms < 0) {
        ms += 1000;
        sec_total -= 1;
    }
    int y, mo, d, h, mi, s;
    tb_civil_from_unix(sec_total, &y, &mo, &d, &h, &mi, &s);
    snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, mo, d, h, mi, s, ms);
}
