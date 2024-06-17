use inputbot::KeybdKey;
/*
shortcut key
ctrl + 8 : show console
ctrl + 9 : hide console
*/
use regex::{Captures, Regex};
use std::ffi::OsString;
// use std::fmt::Error;
use std::fs::{self,
              // File
};
use std::io::{BufRead,
              // BufReader
};
use std::os::windows::ffi::OsStringExt;
use winapi::shared::windef::HWND;
use winapi::um::winuser::{GetForegroundWindow, GetWindowTextW, SendMessageW};

use crate::{
    // sleep,
    sleep_ms};

static mut AUTO_INPUT_STRING: String = String::new();
static mut AUTO_INPUT_LINE: Option<Captures> = None;
pub static mut AUTO_INPUT_ON_OFF: bool = false;
pub static mut AUTO_INPUT_ENGINEER_PERMISSION: String = String::new();
pub static mut AUTO_INPUT_ENGINEER_NAME: String = String::new();
pub static mut AUTO_INPUT_ENGINEER_PASSWORD: String = String::new();

pub fn key_msg(s: String) {
    // chinese character
    // if !s.contains("invalid utf-8 sequence") {
    log::info!("{}", s);
    // }
}
pub fn key_msg_debug(s: &str) {
    // chinese character
    // if !s.contains("invalid utf-8 sequence") {
    log::debug!("{}", s);
    // }
}

/// get foreground window title
pub fn get_foreground_window_title() -> Option<String> {
    // 获取当前焦点窗口的句柄
    let foreground_window: HWND = unsafe { GetForegroundWindow() };

    // 获取标题文本的长度
    let text_length: i32 = unsafe {
        SendMessageW(
            foreground_window,
            winapi::um::winuser::WM_GETTEXTLENGTH,
            0,
            0,
        ) as i32
    };

    // 创建用于存储标题文本的缓冲区
    let mut buffer: Vec<u16> = vec![0; (text_length + 1) as usize];

    // 获取标题文本
    let chars_copied: i32 =
        unsafe { GetWindowTextW(foreground_window, buffer.as_mut_ptr(), text_length + 1) };

    if chars_copied > 0 {
        // 将缓冲区中的标题文本转换为 Rust 字符串
        let title: OsString = OsString::from_wide(&buffer[..(chars_copied as usize)]);
        if let Some(title_str) = title.into_string().ok() {
            return Some(title_str.trim().to_lowercase());
        }
    }

    None
}
#[macro_export] macro_rules! release_keys {
    (1) => {
        KeybdKey::LControlKey.release();
    };
    (2) => {
        KeybdKey::LAltKey.release();
    };
    (3) => {
        KeybdKey::LShiftKey.release();
    };
    (4) => {
        KeybdKey::LControlKey.release();
        KeybdKey::LAltKey.release();
    };
    (5) => {
        KeybdKey::LControlKey.release();
        KeybdKey::LShiftKey.release();
    };
    (6) => {
        KeybdKey::LAltKey.release();
        KeybdKey::LShiftKey.release();
    };
    (7) => {
        KeybdKey::LControlKey.release();

        KeybdKey::LAltKey.release();
        KeybdKey::LShiftKey.release();
    };
    
    (_) => {};
}
/// 使用快捷鍵觸發
///
/// 讀取每一行文本,區分 abc[alt]abc 括號内外的内容,用來模擬按鍵
pub fn key_send(index_trigger: i32) {
    unsafe {
        if !AUTO_INPUT_ON_OFF {
            key_msg_debug("auto input off");
            return;
        }
    }
    release_keys!(7);

    let capslock_state = if KeybdKey::CapsLockKey.is_toggled() {
        KeybdKey::CapsLockKey.press();
        KeybdKey::CapsLockKey.release();
        true
    } else {
        false
    };

    unsafe {
        match fs::read_to_string("auto_input.ini") {
            Ok(reader) => {
                AUTO_INPUT_STRING = reader;
                // 正则表达式匹配模式
                let pattern = Regex::new(r#"^(\d+),(\d+),(.*?),(.*?),(.*?),(.*?)$"#).unwrap();
                let bracket_pattern = Regex::new(r#"(\[.*?])"#).unwrap();

                // 早夜班時間不同
                let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
                let current_shift =
                    if chrono::Timelike::hour(&now) >= 7 && chrono::Timelike::hour(&now) < 19 {
                        "d"
                    } else {
                        "n"
                    };
                // 逐行读取并处理
                for line in AUTO_INPUT_STRING.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    AUTO_INPUT_LINE = pattern.captures(&line.trim());
                    if let Some(captures) = &AUTO_INPUT_LINE {
                        // 解析匹配的数据
                        let index: i32 = captures[1].parse().unwrap();
                        let window_title_matching_pattern: u32 = captures[2].parse().unwrap();
                        let window_title: &str = &captures[3].trim().to_lowercase();
                        let delay: u64 = captures[4].parse().unwrap();
                        let strings: &str = &captures[5];
                        let shift: &str = &captures[6].trim().to_lowercase();
                        // 在这里进行处理逻辑
                        // 忽略注釋行
                        if !line.starts_with("//") {
                            // log::debug!("Index: {}", index);
                            if index_trigger != index {
                                continue;
                            }
                            if (window_title_matching_pattern != 0
                                && window_title_matching_pattern != 1)
                                || (shift != "n" && shift != "d")
                                || delay > 10000
                                || strings.is_empty()
                                || window_title.len() < 3
                            {
                                log::debug!("break: {}", index);

                                break;
                            }

                            // log::debug!("Window Title Matching Pattern: {}",window_title_matching_pattern);
                            // log::debug!("Window Title: {}", window_title);

                            // continue 可以匹配多個相同快捷鍵和不同的窗口
                            if window_title_matching_pattern != 0
                                && window_title != get_foreground_window_title().unwrap()
                            {
                                // log::debug!("matching: 1,fail");
                                // 1 完全匹配 失敗
                                continue;
                            } else if window_title_matching_pattern == 0
                                && !get_foreground_window_title()
                                    .unwrap()
                                    .contains(window_title)
                            {
                                // log::debug!("matching: 0,fail");
                                // 0 部分匹配 失敗
                                continue;
                            } else if current_shift != shift {
                                continue;
                            }

                            // 匹配按鍵
                            let mut prev_end = 0;
                            for capture in bracket_pattern.captures_iter(&strings) {
                                let start = capture.get(0).unwrap().start();
                                let end = capture.get(0).unwrap().end();

                                if prev_end < start {
                                    let outside_content = &strings[prev_end..start];
                                    // println!("{}", outside_content);
                                    inputbot::KeySequence(outside_content).send();
                                }

                                let bracket_content = &strings[start..end];
                                // println!("BRACKET: {}", bracket_content);
                                match bracket_content.to_lowercase().as_str() {
                                    "[alt]" => {
                                        KeybdKey::LAltKey.press();
                                        KeybdKey::LAltKey.release();
                                    }
                                    "[ctrl]" => {
                                        KeybdKey::LControlKey.press();
                                        KeybdKey::LControlKey.release();
                                    }
                                    "[shift]" => {
                                        KeybdKey::LShiftKey.press();
                                        KeybdKey::LShiftKey.release();
                                    }
                                    "[tab]" => {
                                        KeybdKey::TabKey.press();
                                        KeybdKey::TabKey.release();
                                    }
                                    "[backspace]" => {
                                        KeybdKey::BackspaceKey.press();
                                        KeybdKey::BackspaceKey.release();
                                    }
                                    "[enter]" => {
                                        KeybdKey::EnterKey.press();
                                        KeybdKey::EnterKey.release();
                                    }
                                    _ => (),
                                }
                                prev_end = end;
                                // println!("Delay: {}", delay);
                                sleep_ms(delay);
                            }

                            if prev_end < strings.len() {
                                let outside_content = &strings[prev_end..];
                                // println!("{}", outside_content);
                                inputbot::KeySequence(&outside_content).send();
                            }
                            // log::debug!("Strings: {}", strings);
                            // println!("---");

                            // break 原因是能執行到這裏一定是匹配到對應内容

                            key_msg(format!(
                                "key send: {} {} {} {}",
                                index, window_title_matching_pattern, window_title, strings
                            ));
                            break;
                        }
                    }
                }
                if capslock_state {
                    KeybdKey::CapsLockKey.press();
                    KeybdKey::CapsLockKey.release();
                }
            }
            Err(e) => {
                if capslock_state {
                    KeybdKey::CapsLockKey.press();
                    KeybdKey::CapsLockKey.release();
                }
                // 文件打开失败
                log::error!("Failed to open file (auto_input.ini): {:?}", e)
            }
        }
    }
}
