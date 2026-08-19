#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    truss::invariants::scan_survives_its_own_encoder(data);
});
