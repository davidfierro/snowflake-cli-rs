//! SQL API v2 string values → [`Value`] (ADR 0001, Decision 6).

use super::result::{SfType, Value};
use crate::error::{Error, ErrorKind, Result};
use crate::render::pyfmt::round_decimal;
use jiff::civil::{Date, DateTime, Time};
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};

/// Converts one cell. `ltz_zone` is the session time zone, required for TIMESTAMP_LTZ.
/// `decimal_precision` (`--decimal-precision`) rounds decimals to that many significant digits.
pub(crate) fn convert(
    sf_type: &SfType,
    raw: Option<String>,
    ltz_zone: Option<&TimeZone>,
    decimal_precision: Option<usize>,
) -> Result<Value> {
    let Some(raw) = raw else {
        return Ok(Value::Null);
    };
    let value = match sf_type {
        SfType::Fixed { scale: 0, .. } => raw.parse().ok().map(Value::Int),
        SfType::Fixed { .. } | SfType::Decfloat => is_decimal(&raw).then(|| {
            Value::Decimal(match decimal_precision {
                Some(prec) if rounded_by_connector(sf_type, &raw) => round_decimal(&raw, prec),
                _ => raw,
            })
        }),
        SfType::Real => raw.parse().ok().map(Value::Float),
        SfType::Text | SfType::Other(_) => Some(Value::Text(raw)),
        SfType::Binary => crate::codec::decode_hex(&raw).map(Value::Binary),
        SfType::Boolean => match raw.as_str() {
            "true" | "TRUE" | "1" => Some(Value::Bool(true)),
            "false" | "FALSE" | "0" => Some(Value::Bool(false)),
            _ => None,
        },
        SfType::Date => raw
            .parse::<i64>()
            .ok()
            .and_then(date_from_days)
            .map(Value::Date),
        SfType::Time { .. } => epoch_duration(&raw).and_then(time_of_day).map(Value::Time),
        SfType::TimestampNtz { .. } => epoch_duration(&raw)
            .and_then(utc_datetime)
            .map(Value::TimestampNtz),
        SfType::TimestampTz { .. } => timestamp_tz(&raw),
        SfType::TimestampLtz { .. } => {
            let zone = ltz_zone.ok_or_else(|| {
                Error::new(
                    ErrorKind::Communication,
                    "The session time zone is unknown.",
                )
            })?;
            epoch_duration(&raw).and_then(|d| zoned(d, zone))
        }
        SfType::Variant | SfType::Object | SfType::Array => Some(Value::Json(raw)),
    };
    value.ok_or_else(|| {
        // Never include the value itself: it is query data.
        Error::new(
            ErrorKind::Communication,
            format!(
                "Malformed {} value in the SQL API response.",
                type_label(sf_type)
            ),
        )
    })
}

fn type_label(sf_type: &SfType) -> &str {
    match sf_type {
        SfType::Fixed { .. } => "NUMBER",
        SfType::Real => "FLOAT",
        SfType::Decfloat => "DECFLOAT",
        SfType::Text => "TEXT",
        SfType::Binary => "BINARY",
        SfType::Boolean => "BOOLEAN",
        SfType::Date => "DATE",
        SfType::Time { .. } => "TIME",
        SfType::TimestampNtz { .. } => "TIMESTAMP_NTZ",
        SfType::TimestampLtz { .. } => "TIMESTAMP_LTZ",
        SfType::TimestampTz { .. } => "TIMESTAMP_TZ",
        SfType::Variant => "VARIANT",
        SfType::Object => "OBJECT",
        SfType::Array => "ARRAY",
        SfType::Other(name) => name,
    }
}

/// Whether the official snow rounds this value to the decimal context's precision. Its connector
/// builds a `Decimal` by arithmetic (`Decimal(int).scaleb(-scale)`, rounded by the context) for
/// DECFLOAT and for NUMBERs whose unscaled value fits in 64 bits, and from the exact digits
/// (never rounded) for the wider ones.
fn rounded_by_connector(sf_type: &SfType, raw: &str) -> bool {
    match sf_type {
        SfType::Decfloat => true,
        _ => {
            let unscaled: String = raw.chars().filter(|c| *c != '.').collect();
            !raw.contains(['e', 'E']) && unscaled.parse::<i64>().is_ok()
        }
    }
}

/// `[-]digits[.digits][e[+-]digits]`, the forms the SQL API returns for NUMBER and DECFLOAT.
fn is_decimal(raw: &str) -> bool {
    crate::render::pyfmt::parse_decimal(raw).is_some()
}

fn date_from_days(days: i64) -> Option<Date> {
    let seconds = days.checked_mul(86_400)?;
    Some(
        Timestamp::from_second(seconds)
            .ok()?
            .to_zoned(TimeZone::UTC)
            .date(),
    )
}

/// Parses `[-]seconds[.fraction]` (fraction up to 9 digits) into a duration from the epoch.
fn epoch_duration(raw: &str) -> Option<SignedDuration> {
    let (negative, unsigned) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let seconds: i64 = whole.parse().ok()?;
    let nanos: i32 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").parse().ok()?
    };
    let duration = SignedDuration::new(seconds, nanos);
    Some(if negative { -duration } else { duration })
}

fn time_of_day(since_midnight: SignedDuration) -> Option<Time> {
    if since_midnight.is_negative() || since_midnight >= SignedDuration::from_hours(24) {
        return None;
    }
    Time::midnight().checked_add(since_midnight).ok()
}

fn utc_datetime(since_epoch: SignedDuration) -> Option<DateTime> {
    Some(
        Timestamp::from_duration(since_epoch)
            .ok()?
            .to_zoned(TimeZone::UTC)
            .datetime(),
    )
}

/// TIMESTAMP_TZ: `"<epoch> <offset minutes + 1440>"`.
fn timestamp_tz(raw: &str) -> Option<Value> {
    let (epoch, offset) = raw.split_once(' ')?;
    let offset_minutes = offset.parse::<i32>().ok()?.checked_sub(1440)?;
    let offset = jiff::tz::Offset::from_seconds(offset_minutes.checked_mul(60)?).ok()?;
    zoned(epoch_duration(epoch)?, &TimeZone::fixed(offset))
}

fn zoned(since_epoch: SignedDuration, zone: &TimeZone) -> Option<Value> {
    let timestamp = Timestamp::from_duration(since_epoch).ok()?;
    let zoned = timestamp.to_zoned(zone.clone());
    Some(Value::TimestampTz {
        local: zoned.datetime(),
        offset_seconds: zoned.offset().seconds(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::{date, time};

    fn conv(sf_type: SfType, raw: &str) -> Value {
        convert(&sf_type, Some(raw.to_string()), None, None).unwrap()
    }

    fn fails(sf_type: SfType, raw: &str) {
        let err = convert(&sf_type, Some(raw.to_string()), None, None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Communication);
        assert!(!err.message().contains(raw), "message leaks the value");
    }

    const FIXED0: SfType = SfType::Fixed {
        precision: 38,
        scale: 0,
    };
    const FIXED2: SfType = SfType::Fixed {
        precision: 10,
        scale: 2,
    };

    #[test]
    fn null_is_null_for_every_type() {
        for t in [
            FIXED0,
            SfType::Real,
            SfType::Text,
            SfType::TimestampLtz { scale: 9 },
        ] {
            assert_eq!(convert(&t, None, None, None).unwrap(), Value::Null);
        }
    }

    #[test]
    fn decimal_precision_rounds_what_the_connector_rounds() {
        let at =
            |t: &SfType, raw: &str, p| convert(t, Some(raw.to_string()), None, Some(p)).unwrap();
        let wide = SfType::Fixed {
            precision: 38,
            scale: 3,
        };
        // Unscaled value fits in 64 bits: rounded, half to even.
        assert_eq!(at(&FIXED2, "1.25", 2), Value::Decimal("12E-1".into()));
        assert_eq!(at(&FIXED2, "1.35", 2), Value::Decimal("14E-1".into()));
        assert_eq!(at(&wide, "1.234", 3), Value::Decimal("123E-2".into()));
        // Does not fit: exact digits, as the connector builds it.
        assert_eq!(
            at(&wide, "12345678901234567890.123", 3),
            Value::Decimal("12345678901234567890.123".into())
        );
        assert_eq!(
            at(&SfType::Decfloat, "12345.6789", 1),
            Value::Decimal("1E4".into())
        );
        // Scale 0 and floats are not decimals.
        assert_eq!(at(&FIXED0, "12345", 2), Value::Int(12345));
        assert_eq!(at(&SfType::Real, "1.2345", 2), Value::Float(1.2345));
    }

    #[test]
    fn numbers() {
        assert_eq!(
            conv(FIXED0, "-99999999999999999999999999999999999999"),
            Value::Int(-99_999_999_999_999_999_999_999_999_999_999_999_999)
        );
        assert_eq!(conv(FIXED2, "1.50"), Value::Decimal("1.50".into()));
        assert_eq!(
            conv(SfType::Decfloat, "1e30"),
            Value::Decimal("1e30".into())
        );
        assert_eq!(conv(SfType::Real, "1.5"), Value::Float(1.5));
        assert_eq!(conv(SfType::Real, "-inf"), Value::Float(f64::NEG_INFINITY));
        assert!(matches!(conv(SfType::Real, "NaN"), Value::Float(f) if f.is_nan()));
        fails(FIXED0, "1.5");
        fails(FIXED2, "abc");
        fails(SfType::Real, "x");
    }

    #[test]
    fn text_binary_boolean_json_other() {
        assert_eq!(conv(SfType::Text, "a"), Value::Text("a".into()));
        assert_eq!(
            conv(SfType::Other("vector".into()), "[1,2]"),
            Value::Text("[1,2]".into())
        );
        assert_eq!(
            conv(SfType::Binary, "AB01ff"),
            Value::Binary(vec![0xab, 0x01, 0xff])
        );
        assert_eq!(conv(SfType::Binary, ""), Value::Binary(vec![]));
        fails(SfType::Binary, "ABC");
        fails(SfType::Binary, "ZZ");
        fails(SfType::Binary, "é1");
        assert_eq!(conv(SfType::Boolean, "true"), Value::Bool(true));
        assert_eq!(conv(SfType::Boolean, "false"), Value::Bool(false));
        fails(SfType::Boolean, "yes");
        for t in [SfType::Variant, SfType::Object, SfType::Array] {
            assert_eq!(
                conv(t, "{\n  \"a\": 1\n}"),
                Value::Json("{\n  \"a\": 1\n}".into())
            );
        }
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(conv(SfType::Date, "19724"), Value::Date(date(2024, 1, 2)));
        assert_eq!(conv(SfType::Date, "-719162"), Value::Date(date(1, 1, 1)));
        fails(SfType::Date, "x");
        fails(SfType::Date, "99999999999999");
        let t = SfType::Time { scale: 9 };
        assert_eq!(
            conv(t.clone(), "36672.123456789"),
            Value::Time(time(10, 11, 12, 123_456_789))
        );
        assert_eq!(
            conv(t.clone(), "86399.5"),
            Value::Time(time(23, 59, 59, 500_000_000))
        );
        assert_eq!(conv(t.clone(), "0"), Value::Time(time(0, 0, 0, 0)));
        fails(t.clone(), "86400");
        fails(t.clone(), "-1");
        fails(t.clone(), "1.1234567890");
        fails(t.clone(), "1.x");
        fails(t, ".5");
    }

    #[test]
    fn timestamps() {
        let ntz = SfType::TimestampNtz { scale: 9 };
        assert_eq!(
            conv(ntz.clone(), "1704164645.123456789"),
            Value::TimestampNtz(date(2024, 1, 2).at(3, 4, 5, 123_456_789))
        );
        assert_eq!(
            conv(ntz.clone(), "-315619199.750000000"),
            Value::TimestampNtz(date(1960, 1, 1).at(0, 0, 0, 250_000_000))
        );
        fails(ntz, "99999999999999999");

        let tz = SfType::TimestampTz { scale: 9 };
        assert_eq!(
            conv(tz.clone(), "1704157445.000000000 1560"),
            Value::TimestampTz {
                local: date(2024, 1, 2).at(3, 4, 5, 0),
                offset_seconds: 7200
            }
        );
        assert_eq!(
            conv(tz.clone(), "1704184445.500 1110"),
            Value::TimestampTz {
                local: date(2024, 1, 2).at(3, 4, 5, 500_000_000),
                offset_seconds: -19800
            }
        );
        fails(tz.clone(), "1704157445");
        fails(tz.clone(), "1704157445 x");
        fails(tz, "1704157445 99999");

        let ltz = SfType::TimestampLtz { scale: 9 };
        let zone = TimeZone::get("America/Los_Angeles").unwrap();
        assert_eq!(
            convert(&ltz, Some("1704164645.000000000".into()), Some(&zone), None).unwrap(),
            Value::TimestampTz {
                local: date(2024, 1, 1).at(19, 4, 5, 0),
                offset_seconds: -28800
            }
        );
        let err = convert(&ltz, Some("1".into()), None, None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Communication);
    }

    #[test]
    fn labels_name_the_type() {
        for (t, label) in [
            (FIXED0, "NUMBER"),
            (SfType::Real, "FLOAT"),
            (SfType::Decfloat, "DECFLOAT"),
            (SfType::Text, "TEXT"),
            (SfType::Binary, "BINARY"),
            (SfType::Boolean, "BOOLEAN"),
            (SfType::Date, "DATE"),
            (SfType::Time { scale: 0 }, "TIME"),
            (SfType::TimestampNtz { scale: 0 }, "TIMESTAMP_NTZ"),
            (SfType::TimestampLtz { scale: 0 }, "TIMESTAMP_LTZ"),
            (SfType::TimestampTz { scale: 0 }, "TIMESTAMP_TZ"),
            (SfType::Variant, "VARIANT"),
            (SfType::Object, "OBJECT"),
            (SfType::Array, "ARRAY"),
            (SfType::Other("geo".into()), "geo"),
        ] {
            assert_eq!(type_label(&t), label);
        }
    }
}
