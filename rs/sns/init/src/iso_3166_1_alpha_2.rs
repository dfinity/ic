//! ISO 3166-1 alpha-2 country codes.
//!
//! This is the list of the 249 officially assigned two-letter country codes of
//! ISO 3166-1, sorted in ascending lexicographic order. It was generated from
//! the `isocountry` crate (version 0.3.2), which used to be a dependency of
//! this crate.

/// All ISO 3166-1 alpha-2 country codes, sorted in ascending lexicographic
/// order (which allows `is_iso_3166_1_alpha_2` to use binary search).
#[rustfmt::skip]
pub const ISO_3166_1_ALPHA_2: [&str; 249] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT",
    "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
    "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
    "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
    "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK",
    "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
    "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR",
    "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
    "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
    "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
    "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
    "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF",
    "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW",
    "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

/// Returns true iff `code` is an (upper case) ISO 3166-1 alpha-2 country code.
pub fn is_iso_3166_1_alpha_2(code: &str) -> bool {
    ISO_3166_1_ALPHA_2.binary_search(&code).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_sorted_and_unique() {
        assert_eq!(ISO_3166_1_ALPHA_2.len(), 249);
        for window in ISO_3166_1_ALPHA_2.windows(2) {
            assert!(window[0] < window[1], "{window:?} is out of order");
        }
    }

    #[test]
    fn list_entries_are_two_upper_case_ascii_letters() {
        for code in ISO_3166_1_ALPHA_2 {
            assert_eq!(code.len(), 2, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_uppercase()), "{code}");
        }
    }

    #[test]
    fn is_iso_3166_1_alpha_2_works() {
        for code in ISO_3166_1_ALPHA_2 {
            assert!(is_iso_3166_1_alpha_2(code), "{code}");
        }
        for (code, expected) in [
            ("AD", true),
            ("CH", true),
            ("US", true),
            ("ZW", true),
            ("", false),
            ("A", false),
            ("ch", false),
            ("XX", false),
            ("ZZ", false),
            ("USA", false),
            ("AA", false),
        ] {
            assert_eq!(is_iso_3166_1_alpha_2(code), expected, "{code}");
        }
    }
}
