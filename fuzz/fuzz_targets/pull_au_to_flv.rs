#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    truss::invariants::pull_au_to_flv(data);
});
