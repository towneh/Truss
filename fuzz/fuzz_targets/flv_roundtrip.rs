#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    truss::invariants::flv_roundtrip(data);
});
