//! Monitor external connections, output to [log/session.log]
// use log::trace;
#[allow(dead_code)]
pub fn trace_msg(s: String) {
    // chinese charactor
    if !s.contains("invalid utf-8 sequence") {
        log::debug!("{}", s);
    }
}
