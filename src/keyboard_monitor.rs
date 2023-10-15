use log::trace;
pub fn key_msg(s: String) {
    // chinese charactor
    // if !s.contains("invalid utf-8 sequence") {
        log::info!("{}", s);
    // }
}