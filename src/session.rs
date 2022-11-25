use log::trace;
pub fn trace_msg(s: String) {
    // chinese charactor
    if !s.contains("invalid utf-8 sequence") {
        trace!("{}", s);
    }
}
