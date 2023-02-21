//! # created by Terry on 2022-11-25
//!
//! file-watcher is a tool to watch file changes
use evtx::EvtxParser;
use hotwatch::{Event, Hotwatch};
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use platform_dirs::UserDirs;
use regex::Regex;
use std::{
    env,
    fs::{self},
    io::{Read, Write},
    net::TcpListener,
    ops::Add,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio}, 
};
extern crate self_update;
use chrono::{Datelike, FixedOffset, Utc};

mod session;
use crate::session::trace_msg;

mod tests;
/// CreateProcess parameter
const CREATE_NO_WINDOW: u32 = 0x08000000;
mod structs;
use crate::structs::ConfigEnv ;

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
    let output = String::from_utf8(output.stdout).unwrap();
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
    if let Err(e) = process.stdout.unwrap().read_to_string(&mut s) {
        panic!("couldn't read PS stdout: {e}")
    } else {
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
    match String::from_utf8(cmd1.stdout) {
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

    match String::from_utf8(cmd2.stdout) {
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
          local_ipaddress_get().unwrap_or("127.0.0.1".to_string()) + ":"+cfg.telnet.port.as_str()
    }else{
        cfg.telnet.default_ip.clone() + ":" + cfg.telnet.port.as_str()
    };
    info!("Listening on {}", &local_ip);
    let listener = TcpListener::bind(local_ip).expect("Failed to bind to port");
    
    for stream in listener.incoming() {

        match stream {
            Ok(mut stream) => {
                info!("New connection: {}", stream.peer_addr().unwrap());
                loop {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(bytes_read) => {
                            if bytes_read > 0 {
                                println!(
                                    "Received a message: {}",
                                    String::from_utf8_lossy(&buffer[..bytes_read])
                                );
                               process_message(&String::from_utf8_lossy(&buffer[..bytes_read]));
                                stream.write(b"return\r\n").unwrap();
                            }
                        }
                        Err(e) => {
                            warn!("Failed to receive data: {}", e);
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
fn process_message(s: &str) {
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
            _ =>(),
        }
     
    }

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
