//! # created by Terry on 2022-11-25
//!
//! file-watcher is a tool to watch file changes
use encoding::{all::GBK, DecoderTrap, Encoding};
use evtx::EvtxParser;
use hotwatch::{Event, Hotwatch};
use inputbot::{handle_input_events, KeySequence, KeybdKey, MouseButton, MouseCursor};
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use platform_dirs::UserDirs;
use regex::Regex;
use std::{
    env,
    fmt::format,
    fs::{self},
    io::{Read, Write},
    net::TcpListener,
    ops::Add,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    str::from_utf8,
    sync::Arc,
    time::Duration,
};
extern crate self_update;
use chrono::{Datelike, FixedOffset, Local, Utc};

mod session;
use crate::{cobra::COBRA, session::trace_msg};

/// CreateProcess parameter
mod structs;
mod tests;
use crate::structs::ConfigEnv;

mod cobra;

// 15 Oct 2023
mod keyboard_monitor;
use keyboard_monitor::*;
use sysinfo::{Pid, ProcessExt, ProcessRefreshKind, System, SystemExt};
mod process_monitor;
use process_monitor::*;

// for keyboard monitor show console
use winapi::um::{consoleapi::AllocConsole, wincon::FreeConsole};

const CREATE_NO_WINDOW: u32 = 0x08000000;
/// executeable file -> [process_name]
///
/// new file -> [./update/filename.exe]
///
/// old file -> [./tmp/[filename.exe]
pub fn get_update_file_name() -> (String, PathBuf, PathBuf) {
    let process_name = env::current_exe().unwrap();
    let process_name = format!("{}", process_name.file_name().unwrap().to_str().unwrap());
    let current_dir = env::current_dir().unwrap();
    let path_update_file = "update";
    let path_tmp_file = "tmp";
    if !Path::new(path_update_file).exists() {
        std::fs::create_dir(path_update_file).unwrap();
    }
    if !Path::new(path_tmp_file).exists() {
        std::fs::create_dir(path_tmp_file).unwrap();
    }
    let path_update_file = current_dir.join(path_update_file).join(&process_name);
    let path_tmp_file = current_dir.join(path_tmp_file).join(&process_name);
    if cfg!(debug_assertions) {
        println!("process_name: {:?}", process_name);
        println!("current_dir: {:?}", current_dir);
        println!("path_update_file: {:?}", path_update_file);
        println!("path_tmp_file: {:?}", path_tmp_file);
    }
    (process_name, path_update_file, path_tmp_file)
}

/// configuration file: [config.ini] , Can be files or directories
pub fn watch_file(s: &str) -> Result<Hotwatch, String> {
    if !Path::new(s).exists() {
        return Err("Invalid Path".to_string());
    }

    let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
    hotwatch
        .watch(s, |event: Event| match event {
            Event::Create(path) => info!(
                "[Create] {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Write(path) => info!(
                "[Write]  {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Remove(path) => warn!(
                "[Remove] {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Rename(from, to) => info!(
                "[Rename] {:?} to {:?}",
                from.file_name().unwrap_or(from.as_os_str()),
                to.file_name().unwrap_or(to.as_os_str())
            ),
            Event::Chmod(path) => info!(
                "[Chmod] {:?} had its permissions changed!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Error(err, path) => {
                error!("[Error] Error {:?} occurred for file {:?}", err, path)
            }
            Event::Rescan => info!("Rescan"),
            Event::NoticeWrite(path) => info!(
                "[NoticeWrite] {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::NoticeRemove(path) => info!(
                "[NoticeRemove] {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
        })
        .expect("failed to watch file!");
    Ok(hotwatch)
}

/// Automatically close old programs, for update
pub fn repeatedly_execute(process_name: String) {
    let process_id_self = std::process::id();
    let re = Regex::new(r"[ ]{2,}\d{2,} ").unwrap();
    let mut cmd = Command::new("tasklist");
    cmd.arg("/fi").arg(format!("imagename eq {}", process_name));
    let output = cmd.output().expect("failed to execute process");
    // let output = String::from_utf8(output.stdout).unwrap();
    // 中文解碼
    let output = GBK.decode(&output.stdout, DecoderTrap::Strict).unwrap();
    // let mut count = 0;
    for line in output.lines() {
        if line.contains(process_name.as_str()) {
            if let Ok(v) = re
                .captures(line)
                .unwrap()
                .get(0)
                .unwrap()
                .as_str()
                .trim()
                .parse::<u32>()
            {
                if v != process_id_self {
                    if let Err(e) = Command::new("taskkill")
                        .arg("/pid")
                        .arg(&v.to_string()[..])
                        .arg("/f")
                        .spawn()
                    {
                        error!("kill process failed: {:?}", e)
                    }
                }
            }
            // count += 1;
        }
    }
    /* if count > 1 {
        info!("{} is running repeatedly, exit!", process_name);
        std::process::exit(0);
    } */
    return;
}

/// CLI  
pub fn powershell(pangram: &str) {
    // let pangram = r#"Get-SmbOpenFile|select ClientComputerName,Path"#;

    let process = match Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Err(e) => panic!("couldn't spawn PS: {e}"),
        Ok(process) => process,
    };

    if let Err(e) = process.stdin.unwrap().write_all(pangram.as_bytes()) {
        panic!("couldn't write to PS stdin: {e}")
    }

    let mut s = String::new();
    let mut buffer = Vec::new();
    // 中文解碼
    if let Err(e) = process.stdout.unwrap().read_to_end(&mut buffer) {
        error!("Powershell process error: {:?}", e);
        panic!("couldn't read PS stdout: {e}");
    } else {
        s = if let Ok(s) = from_utf8(&buffer) {
            s.to_string()
        } else {
            GBK.decode(&buffer, DecoderTrap::Strict).unwrap()
        };
        if s.is_empty() {
            return;
        }
        if s.lines().count() < 3 {
            panic!("PS output too short")
        } else {
            s.lines()
                .skip(6)
                .take_while(|line| !line.is_empty() && !line.starts_with("PS"))
                .for_each(|line| trace_msg(line.to_owned()));
        }
    }
}

/// auto restart, need to be run as admin
///
/// update file name same as executable file name
///
/// update file path: ./update/[file-watch.exe]
///
/// just put update file in the 'update' folder as excutable file
pub fn update(update_file: &PathBuf, tmp_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !update_file.exists() {
        return Ok(());
    }
    info!("Update file");
    self_update::Move::from_source(&update_file)
        .replace_using_temp(&tmp_file)
        .to_dest(&::std::env::current_exe()?)?;
    // here run app will kill the old app in repeatedly_execute()
    powershell(r#"start file-watch.exe"#);
    Ok(())
}

//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
#[allow(dead_code)]
/// Use [`powershell`] instead of cmd
fn process_cmd(re: Regex) {
    let cmd1 = Command::new("net")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("session")
        .output()
        .expect("process failed to execute");
    // match String::from_utf8(cmd1.stdout) {
    // 中文解碼

    match GBK.decode(&cmd1.stdout, DecoderTrap::Strict) {
        Ok(v) => {
            if v.len() > 10 && !v.contains("no entries") {
                trace_msg(format!(
                    "net session:\n{}",
                    re.replace_all(
                        &v[v.rfind("-\r\n").unwrap_or(0) + 5..v.rfind("\r\nThe").unwrap_or(0)],
                        "\t"
                    )
                ));
            }
        }
        Err(e) => {
            trace_msg(format!("net session: {}", e));
        }
    }
    let cmd2 = Command::new("openfiles")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .expect("process failed to execute");

    // chinese charactor
    // String::from_utf8_lossy(format!("{:?}",cmd2).as_bytes())

    //中文解碼
    match GBK.decode(&cmd2.stdout, DecoderTrap::Strict) {
        // match String::from_utf8(cmd2.stdout) {
        Ok(v) => {
            if v.len() > 10 && !v.contains("No shared") {
                trace_msg(format!(
                    "openfiles:\n{}",
                    re.replace_all(&v[v.rfind("=\r\n").unwrap_or(0) + 5..], "\t")
                ))
            }
        }
        Err(e) => {
            trace_msg(format!("openfiles: {}", e));
        }
    }
}

use std::net::UdpSocket;
/// get the local ip address, return an `Option<String>`. when it fail, return `None`.
pub fn local_ipaddress_get() -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return None,
    };

    match socket.local_addr() {
        Ok(addr) => return Some(addr.ip().to_string()),
        Err(_) => return None,
    };
}

/// receive message from ip:6666 and then process it
pub fn receive_message() {
    let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");
    let local_ip = if cfg.telnet.default {
        cfg.telnet.default_ip.clone() + ":" + cfg.telnet.port.as_str()
    } else {
        local_ipaddress_get().unwrap_or("127.0.0.1".to_string()) + ":" + cfg.telnet.port.as_str()
    };
    info!("Listening on {}", &local_ip);
    let listener = TcpListener::bind(local_ip).expect("Failed to bind to port");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                info!("New connection: {}", stream.peer_addr().unwrap());
                stream.set_write_timeout(Some(Duration::from_secs(cfg.telnet.timeout)));
                stream.set_read_timeout(Some(Duration::from_secs(cfg.telnet.timeout)));
                loop {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(bytes_read) => {
                            if bytes_read > 0 {
                                // recieved  message
                                stream.write_all(b"\r\nreceived msg\r\n");
                                println!(
                                    "Received a message: {}",
                                    String::from_utf8_lossy(&buffer[..bytes_read])
                                );
                                let res = process_message(&String::from_utf8_lossy(
                                    &buffer[..bytes_read],
                                ));
                                if !res.is_empty() {
                                    // println!("send message: {}", res);
                                    stream.write_all(res.as_bytes());
                                }
                                stream.write_all(b"processed msg\r\n");
                            } else if bytes_read == 0 {
                                // 斷開連接
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to receive data: {}", e);
                            // os error 10053
                            // if read time out , than break and wait new connection
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to establish connection: {}", e);
            }
        }
    }
}

/// message from receive_message by telnet
fn process_message(s: &str) -> String {
    let v: Vec<&str> = s.split_whitespace().collect();
    if v.len() >= 1 {
        match v[0] {
            /* "update" => {
                if v[1] == "file-watch.exe" {
                    powershell(r#"start file-watch.exe"#);
                }
            } */
            "crash" => {
                // get crash log
                get_system_log();
                println!("get_system_log()");
            }
            "cobra" => {
                // get cobra log
                /* 15, M1 STATUS (Up)  FEEDBACK: T-CASE T_EVAP: 25.0 UP_SENSOR: FALSE DOWN_SENSOR: FALSE HEAD_STATE: RUN HEATER POWER: 100.00 EEV Steps: 177 T_CASE: 23.87 Set Temp:
                25.00 RH: -26.1 T-Discharge: 157.6 T-Liquid: 82.5 T-Suction: -9.5 T-Ambient: 75.7 P-Discharge: 191.9 P-Suction: 15.1 Compression Ratio: 6.9 Compressor Amps: 5.9 Bypass Steps: 166 SubCooling: 4.2 Superheat: 11.5 ERRORS: WARN:High Ambient Temperature  (22 07 30 22 36) TSD Millivolts: 0.00 TSD Temperature: NaN M1 T-CASE OFFSET: 0.00 Power On Off: 1 TSD Feedback: 0 Dynamic_SV: 25.0 PV: 23.9 M1 POWERBOX: 1 M1 FTC200 PV: 0.0 M1 FTC200 PWM: 0.0
                 */
                COBRA::init();
                // COBRA::connect(1);
                println!("COBRA::init(1)");

                unsafe {
                    // COBRA::MESSAGE COLLECT TO STRING
                    return cobra::COBRA_MESSAGE.join("\n");
                }
            }
            "powershell" => {
                //  這裡用來執行powershell遠端命令, 接收的參數為腳本路徑
                if v[1] != "" {
                    // 拼接後面所有的字符串
                    let path = v.iter().skip(1).map(|&x| x).collect::<Vec<_>>().join(" ");
                    println!("cmd path: {}", path);
                    powershell(format!("& {}", path).as_str());
                }
            }
            _ => (),
        }
    }
    String::new()
}

/// result 3200D crash log to desktop
#[allow(deprecated)]
pub fn get_system_log() {
    let fp = PathBuf::from(r#"C:\Windows\System32\winevt\Logs\Application.evtx"#);
    let now = Utc::now().add(FixedOffset::east(8 * 3600));
    let mut computer_name = hostname::get().unwrap().to_str().unwrap().to_string();
    let today = now.format("%Y-%m-%d").to_string();
    // let desktop_dir =        (UserDirs::new().unwrap().desktop_dir.to_string_lossy() + "\\Log_").to_string();
    // let desktop_dir = format!("{}{}{}",UserDirs::new().unwrap().desktop_dir.to_string_lossy(),"\\Log_",computer_name);
    let desktop_dir = format!(
        "{}{}{}\\{}",
        UserDirs::new().unwrap().desktop_dir.to_string_lossy(),
        "\\Log_",
        computer_name,
        today
    );
    let desktop_dir = Path::new(&desktop_dir);
    if !desktop_dir.exists() {
        if let Err(e) = fs::create_dir(&desktop_dir.parent().unwrap()) {
            eprintln!("desktop_dir: {}", e);
            sleep(3);
        };
        if let Err(e) = fs::create_dir(&desktop_dir) {
            eprintln!("desktop_dir: {}", e);
            sleep(3);
        };
    }

    //system log readings
    {
        let mut parser = EvtxParser::from_path(fp).unwrap();
        let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");

        // let key_word = r"<Level>2";
        // let key_word = "Level\": 2,";
        // let key_word2 = "3200";
        let key_word = &cfg.sys_log.key1;
        let key_word2 = &cfg.sys_log.key2;
        let mut contents = String::new();
        // let count = parser.records().count();

        let start_time = now - chrono::Duration::days(30);
        for record in parser.records_json() {
            match record {
                Ok(r) => {
                    // 2023/02/21 filter  date

                    // 如果事件记录创建时间在最近一个月内，则处理它
                    if !(r.timestamp >= start_time && r.timestamp <= now) {
                        continue;
                    }

                    if r.data.contains(key_word2) && r.data.contains(key_word) {
                        // println!(
                        //     "Record {}，{}\n{}",
                        //     r.event_record_id,
                        //     r.timestamp.add(FixedOffset::east(8 * 3600)),
                        //     r.data
                        // );
                        contents += format!(
                            "Record {},{}\n{}\n{:#>60}\n{:@>60}\n{:#>60}\n",
                            r.event_record_id,
                            r.timestamp.add(FixedOffset::east(8 * 3600)),
                            r.data.replacen(r"\n", "\n", cfg.sys_log.text_wrapping), // limit 50
                            "#",
                            "@",
                            "#"
                        )
                        .as_str();
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        let path = format!(
            "{}\\{}",
            desktop_dir.display(),
            now.format("%d-%m-%Y").to_string() + &" SysAppLog.txt"
        );
        if let Err(e) = fs::write(path, contents) {
            eprintln!("System Log:{}", e);
            sleep(3);
        };
    }

    //copy crash lot
    // let mut date = now.format("%Y%m%d").to_string();
    // if cfg!(debug) {
    //     date = "20211126".to_string();
    // }
    // let file_name = format!("Crash_{}_.csv", date);
    // let target_dir = format!("{}\\{}", desktop_dir, file_name);
    {
        // 循環不能超過30天, 需要另做判斷 讓month - n%30
        for i in 0..7 {
            let day = now.day() as i32 - i;
            let date = format!(
                "{}{:02}{:02}",
                if day < 1 && now.month() == 1 {
                    now.year() - 1
                } else {
                    now.year()
                },
                if day < 1 {
                    if now.month() == 1 {
                        12
                    } else {
                        now.month() - 1
                    }
                } else {
                    now.month()
                },
                if day < 1 { 31 + (day) } else { day }
            );
            let file_name = format!("Crash_{}_.csv", date);
            let target_dir = format!("{}\\{}", desktop_dir.display(), file_name);
            let path = format!("D:\\3200\\Deubug_Wen\\{}", file_name);
            println!("###{}", target_dir);
            if let Err(e) = fs::copy(&path, &target_dir) {
                eprintln!("Crash Log:{}", e);
                sleep(1);
            }
            // println!("{}", date);
        }
    }

    //copy event log HSLTN038_2022_3
    let mut file_name =
        format!("{:?}_{:?}_{:?}.log", computer_name, now.year(), now.month()).replace("\"", "");
    if cfg!(debug) {
        //debug_assertions
        eprintln!("debug_assertions - Debug Mode");
        computer_name = "HSLTN027".to_string();
        file_name = format!("{:?}_{:?}_{:?}.log", computer_name, 2020, 10).replace("\"", "");
    }
    let path = format!("D:\\3200\\Log\\{}", file_name).replace("\"", "");
    let target_dir = format!("{}\\{}", desktop_dir.display(), file_name);
    println!("###{}", target_dir);
    if !Path::new(&path).exists() {
        eprintln!("Event log does not exist, exit after 4 seconds.");
        return;
    }

    if let Err(e) = fs::write(&target_dir, "") {
        eprintln!("Create event log:{}", e);
        sleep(3);
    };

    if let Err(e) = fs::copy(&path, &target_dir) {
        eprintln!("Copy event log:{}", e);
        sleep(3);
    }
    println!("Done.");
}

fn sleep(secs: u64) {
    std::thread::sleep(std::time::Duration::from_secs(secs));
}
fn sleep_ms(millis: u64) {
    std::thread::sleep(std::time::Duration::from_millis(millis));
}
/// 判斷一個給定的文件是否存在字符串 `telnet.timeout`,且該字符串要位於行首,
///
/// 如果不存在則在文件末尾添加新行, 添加內容為 `telnet.timeout=10 # seconds`   
///
/// 這是用來更新新的配置項, 以便於後續的讀取
///
/// `start_with` 用來判斷行首的內容, 例如: `telnet.timeout`
///
/// `hole_line` 用來添加的新行, 例如: `telnet.timeout=10 # seconds`
pub fn cfg_update(start_with: &str, hole_line: &str) {
    if start_with.is_empty() || hole_line.is_empty() {
        return;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(".env")
        .unwrap();
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
    let mut lines = contents.lines();
    let mut found = false;
    let mut line_number = 0;
    for line in lines {
        line_number += 1;
        if line.starts_with(start_with) {
            found = true;
            break;
        }
    }
    if !found {
        warn!("some configuration parameters does not exist not found, adding to .env");
        contents.push_str(hole_line);
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0)).unwrap();
        std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
    }
}

/// release_keys!(1) -> release ctrl
///
/// release_keys!(2) -> release alt
///
/// release_keys!(3) -> release shift
///
/// release_keys!(4) -> release ctrl + alt
///
/// release_keys!(5) -> release ctrl + shift
///
/// release_keys!(6) -> release alt + shift
///
/// release_keys!(7) -> release ctrl + alt + shift
///
/// release_keys!(_) -> release nothing
macro_rules! release_keys {
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

/// ctrl + alt + 5/8/9/0/1/2  1-permission 2-input password
///
/// 5 reload cfg
/// 8 show console
/// 9 hide console
///
/// ctrl + 1-9  ->  input user password
///
/// ctrl + shift + 0  ->  open setting
pub fn keyboard_monitor() {
    let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");
    if !cfg.monitor.default {
        return;
    }
    unsafe {
        AUTO_INPUT_ON_OFF = cfg.monitor.auto_input;
        AUTO_INPUT_ENGINEER_PERMISSION = cfg.monitor.auto_input_engineer_permission;
        AUTO_INPUT_ENGINEER_NAME = cfg.monitor.auto_input_engineer_name;
        AUTO_INPUT_ENGINEER_PASSWORD = cfg.monitor.auto_input_engineer_password;
    }
    // let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    KeybdKey::bind_all(|event| match inputbot::from_keybd_key(event) {
        Some(key) => {
            key_msg(format!("{:?}", key));

            // 下面是快捷鍵
            if KeybdKey::LControlKey.is_pressed() {
                if KeybdKey::LAltKey.is_pressed() {
                    release_keys!(7); //release all
                    
                    let capslock_state = if KeybdKey::CapsLockKey.is_toggled() {
                        KeybdKey::CapsLockKey.press();
                        KeybdKey::CapsLockKey.release();
                        true
                    } else {
                        false
                    };
                    match key {
                        '1' => unsafe {
                            inputbot::KeySequence(AUTO_INPUT_ENGINEER_PERMISSION.as_str()).send();
                            key_msg_debug("Engineer login");
                        },
                        '2' => unsafe {
                            inputbot::KeySequence(AUTO_INPUT_ENGINEER_NAME.as_str()).send();
                            KeybdKey::TabKey.press();
                            KeybdKey::TabKey.release();
                            inputbot::KeySequence(AUTO_INPUT_ENGINEER_PASSWORD.as_str()).send();
                            key_msg_debug("Engineer user");
                        },
                        '5' => unsafe {
                            let cfg = ConfigEnv::from_env()
                                .expect("Failed to initialize project configuration");
                            if !cfg.monitor.default {
                                return;
                            }
                            unsafe {
                                AUTO_INPUT_ON_OFF = cfg.monitor.auto_input;
                                AUTO_INPUT_ENGINEER_PERMISSION =
                                    cfg.monitor.auto_input_engineer_permission;
                                AUTO_INPUT_ENGINEER_NAME = cfg.monitor.auto_input_engineer_name;
                                AUTO_INPUT_ENGINEER_PASSWORD =
                                    cfg.monitor.auto_input_engineer_password;
                            }
                            key_msg_debug("Reload cfg");
                        },
                        // show console
                        '8' => unsafe {
                            AllocConsole();
                            key_msg_debug("show console");
                        },
                        // hide console
                        '9' => unsafe {

                            FreeConsole();
                            key_msg_debug("hide console");
                        },
                        // get window title
                        '0' => {

                            key_msg_debug(
                                format!(
                                    "Current window title: {}",
                                    get_foreground_window_title().unwrap()
                                )
                                .as_str(),
                            );
                        }

                        _ => {}
                    }

                    if capslock_state {
                        KeybdKey::CapsLockKey.press();
                        KeybdKey::CapsLockKey.release();
                    }
                } else {
                    // 已經在key_send 内部 release_key
                    match key {
                        '1' => {
                            key_send(1);
                        }
                        '2' => {
                            key_send(2);
                        }
                        '3' => {
                            key_send(3);
                        }
                        '4' => {
                            key_send(4);
                        }
                        '5' => {
                            key_send(5);
                        }
                        '6' => {
                            key_send(6);
                        }
                        '7' => {
                            key_send(7);
                        }
                        '8' => {
                            key_send(8);
                        }
                        '9' => {
                            key_send(9);
                        }

                        _ => (),
                    }
                }

                if KeybdKey::LShiftKey.is_pressed() {
                    match key {
                        '0' => {
                            release_keys!(7);

                            let current_dir =
                                std::env::current_dir().expect("Failed to get current directory");
                            let notepad_ini_path = current_dir.join("auto_input.ini");
                            // warn!("notepad_ini_path: {:?}", notepad_ini_path);
                            Command::new("notepad.exe")
                                .arg(notepad_ini_path)
                                .spawn()
                                .expect("Failed to execute command");
                        }
                        _ => {}
                    }
                }
            }
        }
        //println!("{:?}", key),
        // Local::now().format("%Y-%m-%d %H:%M:%S"),
        None => key_msg(format!("{:?}", event)),
    });
    MouseButton::bind_all(|event| {
        // println!("{:?},{:?}", event, MouseCursor::pos());
        key_msg(format!("{:?},{:?}", event, MouseCursor::pos()));
    });

    inputbot::handle_input_events();
}

pub fn processes_monitor() {
    let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");
    if !cfg.monitor.default {
        return;
    }
    let delay = cfg.monitor.refresh_interval;
    let monitor_process_array = &cfg.monitor.process;
    macro_rules! format_time {
        ($timestamp:expr) => {{
            let duration = chrono::Duration::seconds($timestamp);
            let hours = duration.num_hours();
            let minutes = duration.num_minutes() % 60;
            format!("{:02}:{:02}", hours, minutes)
        }};
    }

    let mut system = System::new_all();
    let monitor_process: Vec<&str> = monitor_process_array
        .trim_matches('"')
        .trim()
        .split(',')
        .map(|s| s.trim())
        .collect();
    loop {
        let processes = system.processes();
        'outer: for (id, process) in processes {
            // println!("PID: {}, Name: {:?}", pid, process.name());
            for i in &monitor_process {
                if (process.name().contains(i)) {
                    // println!("exe: {:?}\n", process.exe());
                    // println!("cmd: {:?}\n", process.cmd());
                    // println!("memory: {:?} MB\n", process.memory() / 1048576); // 1048576 = 1024*1024  //raw in bytes)
                    // println!(
                    //     "virtual_memory(sys): {:?} GB\n",
                    //     process.virtual_memory() / 1048576 / 1024
                    // ); //raw in bytes
                    // println!("status: {:?}\n", process.status());
                    // println!(
                    //     "start_time: {:?}\n",
                    //     chrono::naive::NaiveDateTime::from_timestamp_opt(
                    //         process.start_time() as i64,
                    //         0
                    //     )
                    //     .unwrap()
                    //         + chrono::Duration::hours(8)
                    // );
                    // println!("run_time: {:?}\n", format_time!(process.run_time() as i64));
                    // println!("cpu_usage: {:?}\n", process.cpu_usage()); //divide the returned value by the number of CPUs.
                    // println!("disk_usage: {:?}\n", process.disk_usage());
                    // disk_usage: DiskUsage { total_written_bytes: 7797746, written_bytes: 0, total_read_bytes: 82554875, read_bytes: 0 }

                    process_msg((format!("Name: {:?}, Cmd: {:?}, Memory: {:?} MB, VirtualMemory: {:?} GB, Status: {:?}, Start_time: {:?}, Run_time: {:?}, Cpu_usage: {:?}, Disk_usage: {:?}",
                process.name(),process.cmd(),process.memory() / 1048576,process.virtual_memory() / 1048576 / 1024,process.status(),chrono::naive::NaiveDateTime::from_timestamp_opt(process.start_time() as i64,0).unwrap() + chrono::Duration::hours(8),format_time!(process.run_time() as i64),process.cpu_usage(),process.disk_usage())));
                    break 'outer;
                }
            }
        }
        sleep(delay);
        system.refresh_processes();
    }
}
