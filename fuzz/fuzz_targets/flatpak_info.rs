//! `/.flatpak-info` as read from a caller's root: never panics, and accepted
//! files always name a valid application and instance.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scopevault::identity::AppId;
use scopevault::identity::flatpak::parse_flatpak_info;

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = parse_flatpak_info(data.to_vec()) {
        assert!(AppId::parse(info.app_id.as_str()).is_ok());
        assert!(!info.instance_id.is_empty() && info.instance_id.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(info.raw, data);
    }
});
