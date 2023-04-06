#[cfg(test)]
mod test {

    use std::{
        fs::{self},
        io::{Read, Write},
        path::PathBuf,
        process::{Command, Stdio},
    };

    use encoding::all::GBK;
    use evtx::EvtxParser;
    use platform_dirs::UserDirs;
    use std::{ops::Add, path::Path};
    extern crate self_update;
    use crate::{local_ipaddress_get, sleep, structs::{ConfigEnv}};
    use chrono::{Datelike, FixedOffset, Utc};
use dotenv::dotenv;


    /// CLI pipe , example [tasklist | findstr "file-watch.exe"]
    #[test]
    fn test_pipe() {
        let pangram = r#"Get-SmbOpenFile|select ClientComputerName,Path"#;

        let process = match Command::new("powershell")
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
                    .for_each(|line| println!("{}", line.to_owned()));
                // .for_each(|line| trace_msg(line.to_owned()));
            }
        }
    }

    /// runas admin
    #[test]
    fn runas() {
        let pangram = r#"start file-watch.exe"#;
        // let pangram = r#"start-process PowerShell -verb runas | start file-watch.exe"#;
        let process = match std::os::windows::process::CommandExt::creation_flags(
            &mut Command::new("powershell"),
            0x08000000,
        )
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
                    .for_each(|line| println!("{}", line.to_owned()));
            }
        }
    }

    //get local ip
    #[test]
    fn get_ip() {
        println!(
            "local ip: {:?}",
            local_ipaddress_get().unwrap_or("127.0.0.1".to_string())
        );
    }

    #[test]
    #[allow(deprecated)]
    pub fn get_system_log() {
              dotenv().ok();

        let fp = PathBuf::from(r#"C:\Windows\System32\winevt\Logs\Application.evtx"#);
        let now = Utc::now().add(FixedOffset::east(8 * 3600));

        let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");

        // let key_word = "Level\": 2,";
        // let key_word2 = "3200";
        // let start_time = now - chrono::Duration::days(7);
        let key_word = &cfg.sys_log.key1;
        let key_word2 = &cfg.sys_log.key2;
        let start_time = now - chrono::Duration::days(cfg.sys_log.duration);

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

            // let key_word = r"<Level>2";

            let mut contents = String::new();
            // let count = parser.records().count();

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

    #[test]
    fn test_cfg() {
              dotenv().ok();

                let _cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");
}

/// chinese character decoding
#[test]
fn test_gbk(){
    use encoding::{DecoderTrap, Encoding};
    use encoding::all::GBK;
    let b:Vec<u8> = vec![13, 10, 211, 179, 207, 241, 195, 251, 179, 198, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 80, 73, 68, 32, 187, 225, 187, 176, 195, 251, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 187, 225, 187, 176, 35, 32, 32, 32, 32, 32, 32, 32, 196, 218, 180, 230, 202, 185, 211, 195, 32, 13, 10, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 13, 10, 102, 105, 108, 101, 45, 119, 97, 116, 99, 104, 46, 101, 120, 101, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 50, 50, 51, 50, 56, 32, 67, 111, 110, 115, 111, 108, 101, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 49, 32, 32, 32, 32, 32, 49, 48, 44, 55, 51, 54, 32, 75, 13, 10];
    println!("{}",GBK.decode(&b, DecoderTrap::Strict).unwrap());
}
}
