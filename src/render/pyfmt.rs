//! Python formatting rules that snow's output depends on: `str(Decimal)`, `repr(float)` and
//! `isoformat()` / `str()` of dates and times (ADR 0001, Decision 6).

use jiff::civil::{Date, DateTime, Time};

/// A decimal number as Python's `Decimal` stores it: sign, coefficient digits and exponent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDecimal {
    negative: bool,
    /// Coefficient without leading zeros ("0" for zero).
    digits: String,
    exponent: i64,
}

/// Parses `[+-]digits[.digits][(e|E)[+-]digits]` (at least one digit in the mantissa).
pub(crate) fn parse_decimal(text: &str) -> Option<ParsedDecimal> {
    let (negative, rest) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (mantissa, exponent) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], rest[i + 1..].parse::<i64>().ok()?),
        None => (rest, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.len() + fraction.len() == 0 || !all_digits(whole) || !all_digits(fraction) {
        return None;
    }
    let joined = format!("{whole}{fraction}");
    let trimmed = joined.trim_start_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    Some(ParsedDecimal {
        negative,
        digits: digits.to_string(),
        exponent: exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?,
    })
}

impl ParsedDecimal {
    /// Rounds to `precision` significant digits, half to even: what Python's `Decimal` context
    /// does with `getcontext().prec = precision` (`--decimal-precision`).
    fn round_to(mut self, precision: usize) -> Self {
        let len = self.digits.len();
        if precision == 0 || len <= precision {
            return self;
        }
        let rest = self.digits.split_off(precision);
        self.exponent += rest.len() as i64;
        let (first, tail) = rest.split_at(1);
        let tail_nonzero = tail.bytes().any(|b| b != b'0');
        let last_odd = self
            .digits
            .bytes()
            .last()
            .is_some_and(|b| (b - b'0') % 2 == 1);
        let up = first > "5" || (first == "5" && (tail_nonzero || last_odd));
        if up {
            let mut digits: Vec<u8> = self.digits.into_bytes();
            let mut i = digits.len();
            loop {
                if i == 0 {
                    // 999 -> 1000: keep `precision` digits and move the dropped zero to the exponent.
                    digits.insert(0, b'1');
                    digits.pop();
                    self.exponent += 1;
                    break;
                }
                i -= 1;
                if digits[i] == b'9' {
                    digits[i] = b'0';
                } else {
                    digits[i] += 1;
                    break;
                }
            }
            self.digits = String::from_utf8_lossy(&digits).into_owned();
        }
        self
    }

    /// Python's `Decimal.normalize()`: trailing zeros move into the exponent; zero is `0`.
    fn normalize(mut self) -> Self {
        if self.digits == "0" {
            self.exponent = 0;
            return self;
        }
        let trimmed = self.digits.trim_end_matches('0');
        self.exponent += (self.digits.len() - trimmed.len()) as i64;
        self.digits.truncate(trimmed.len());
        self
    }

    /// Python's `Decimal.__str__` (the "to-scientific-string" rule).
    fn to_sci_string(&self) -> String {
        let len = self.digits.len() as i64;
        let left_digits = self.exponent + len;
        let dot_place = if self.exponent <= 0 && left_digits > -6 {
            left_digits
        } else {
            1
        };
        let (int_part, frac_part) = if dot_place <= 0 {
            (
                "0".to_string(),
                format!(".{}{}", "0".repeat((-dot_place) as usize), self.digits),
            )
        } else if dot_place >= len {
            (
                format!("{}{}", self.digits, "0".repeat((dot_place - len) as usize)),
                String::new(),
            )
        } else {
            let (a, b) = self.digits.split_at(dot_place as usize);
            (a.to_string(), format!(".{b}"))
        };
        let exp = if left_digits == dot_place {
            String::new()
        } else {
            format!("E{:+}", left_digits - dot_place)
        };
        let sign = if self.negative { "-" } else { "" };
        format!("{sign}{int_part}{frac_part}{exp}")
    }
}

/// `str(Decimal(text))`, or `str(Decimal(text).normalize())` with `normalize` (DECFLOAT, which
/// the connector returns as a normalized `Decimal`). Unparseable text is returned unchanged.
pub(crate) fn decimal_str(text: &str, normalize: bool) -> String {
    match parse_decimal(text) {
        Some(d) if normalize => d.normalize().to_sci_string(),
        Some(d) => d.to_sci_string(),
        None => text.to_string(),
    }
}

/// `text` rounded to `precision` significant digits as Python's `Decimal` context does
/// (`--decimal-precision`), as a number [`decimal_str`] renders. Unparseable text is returned
/// unchanged.
pub(crate) fn round_decimal(text: &str, precision: usize) -> String {
    match parse_decimal(text) {
        Some(d) => {
            let d = d.round_to(precision);
            format!(
                "{}{}E{}",
                if d.negative { "-" } else { "" },
                d.digits,
                d.exponent
            )
        }
        None => text.to_string(),
    }
}

/// `json.dumps` of a float: `NaN`, `Infinity`, `-Infinity`, otherwise `float_repr`.
pub(crate) fn json_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else {
        float_repr(value)
    }
}

/// Python's `repr(float)` / `str(float)`: shortest round-trip digits, `1e+16`, `1e-05`, `3.0`,
/// `inf`, `-inf`, `nan`.
pub(crate) fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.into();
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "-1.2345e-7", "1e16", "0e0".
    let sci = format!("{value:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let len = digits.len() as i32;
    let decpt = exp + 1;
    let body = if decpt <= -4 || decpt > 16 {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let exp_sign = if exp < 0 { '-' } else { '+' };
        format!("{first}{rest}e{exp_sign}{:02}", exp.abs())
    } else if decpt <= 0 {
        format!("0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= len {
        format!("{digits}{}.0", "0".repeat((decpt - len) as usize))
    } else {
        let (a, b) = digits.split_at(decpt as usize);
        format!("{a}.{b}")
    };
    format!("{sign}{body}")
}

/// `date.isoformat()`: `YYYY-MM-DD`.
pub(crate) fn date_iso(d: Date) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day())
}

/// `time.isoformat()`: `HH:MM:SS`, plus `.ffffff` when the microseconds are not zero
/// (nanoseconds are truncated, as the connector does).
pub(crate) fn time_iso(t: Time) -> String {
    let micros = t.subsec_nanosecond() / 1000;
    let base = format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second());
    if micros == 0 {
        base
    } else {
        format!("{base}.{micros:06}")
    }
}

/// `datetime.isoformat(sep)`: `T` for JSON and CSV, ` ` for `str()`.
pub(crate) fn datetime_iso(dt: DateTime, sep: char) -> String {
    format!("{}{sep}{}", date_iso(dt.date()), time_iso(dt.time()))
}

/// The `+HH:MM` suffix of an aware datetime (`:SS` added when the offset has seconds).
pub(crate) fn offset_iso(offset_seconds: i32) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let total = offset_seconds.unsigned_abs();
    let (h, m, s) = (total / 3600, total % 3600 / 60, total % 60);
    if s == 0 {
        format!("{sign}{h:02}:{m:02}")
    } else {
        format!("{sign}{h:02}:{m:02}:{s:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::{date, time};

    #[test]
    fn decimal_str_follows_python() {
        for (input, expected) in [
            ("1.50", "1.50"),
            ("-1.50", "-1.50"),
            ("0.00000010", "1.0E-7"),
            ("0.000001", "0.000001"),
            ("0.00", "0.00"),
            ("123.456", "123.456"),
            ("1e30", "1E+30"),
            ("1E-10", "1E-10"),
            ("0", "0"),
            ("-0", "-0"),
            ("+7", "7"),
            ("00012", "12"),
            ("1.5e3", "1.5E+3"),
            (".5", "0.5"),
        ] {
            assert_eq!(decimal_str(input, false), expected, "{input}");
        }
    }

    #[test]
    fn rounding_follows_the_decimal_context() {
        // Expected values were produced by snow 3.34.0 (Python `Decimal`, half to even).
        for (input, prec, expected) in [
            ("1.2345", 3, "1.23"),
            ("1.2345", 2, "1.2"),
            ("123456.789", 3, "1.23E+5"),
            ("0.333333", 3, "0.333"),
            ("-1.2355", 3, "-1.24"),
            ("2.5", 1, "2"),
            ("3.5", 1, "4"),
            ("2.51", 1, "3"),
            ("99.99", 3, "100"),
            ("99.99", 2, "1.0E+2"),
            ("0.0000", 3, "0.0000"),
            ("1.50", 3, "1.50"),
            ("1.2000", 3, "1.20"),
            ("123456789.123456789", 3, "1.23E+8"),
            ("0.00012345", 3, "0.000123"),
            ("5", 1, "5"),
        ] {
            assert_eq!(
                decimal_str(&round_decimal(input, prec), false),
                expected,
                "{input} @ {prec}"
            );
        }
        assert_eq!(round_decimal("abc", 3), "abc");
        assert_eq!(round_decimal("1.5", 0), "15E-1");
    }

    #[test]
    fn decfloat_is_normalized() {
        for (input, expected) in [
            ("1.5", "1.5"),
            ("0.0000000001", "1E-10"),
            ("12345678901234567890.123", "12345678901234567890.123"),
            ("1000000000000000000000000000000", "1E+30"),
            ("0", "0"),
            ("0.000", "0"),
            ("-0.000001", "-0.000001"),
            ("42", "42"),
            ("420", "4.2E+2"),
            ("1.50", "1.5"),
            ("-0.000000000000000000012345", "-1.2345E-20"),
            ("0.0000001", "1E-7"),
        ] {
            assert_eq!(decimal_str(input, true), expected, "{input}");
        }
    }

    #[test]
    fn unparseable_decimals_are_kept() {
        for input in ["", "-", "abc", "1.2.3", "1e", "1ex", "."] {
            assert_eq!(decimal_str(input, false), input);
            assert!(parse_decimal(input).is_none(), "{input}");
        }
    }

    #[test]
    fn float_repr_follows_python() {
        for (input, expected) in [
            (1.5, "1.5"),
            (1e16, "1e+16"),
            ("1.0000000000000001e-05".parse().unwrap(), "1e-05"),
            (0.1, "0.1"),
            (123456789.125, "123456789.125"),
            (1e22, "1e+22"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (-2.5, "-2.5"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (3.0, "3.0"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (1.25e-7, "1.25e-07"),
            (12.0, "12.0"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(float_repr(input), expected, "{input}");
        }
    }

    #[test]
    fn dates_and_times_follow_isoformat() {
        assert_eq!(date_iso(date(1, 1, 1)), "0001-01-01");
        assert_eq!(time_iso(time(10, 11, 12, 0)), "10:11:12");
        assert_eq!(time_iso(time(10, 11, 12, 999)), "10:11:12");
        assert_eq!(time_iso(time(10, 11, 12, 123_456_789)), "10:11:12.123456");
        let dt = date(2024, 1, 2).at(3, 4, 5, 500_000_000);
        assert_eq!(datetime_iso(dt, 'T'), "2024-01-02T03:04:05.500000");
        assert_eq!(datetime_iso(dt, ' '), "2024-01-02 03:04:05.500000");
        assert_eq!(offset_iso(7200), "+02:00");
        assert_eq!(offset_iso(-19800), "-05:30");
        assert_eq!(offset_iso(0), "+00:00");
        assert_eq!(offset_iso(-3661), "-01:01:01");
    }
}
