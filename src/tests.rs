#[cfg(test)]
mod test {

    use encoding::all::GBK;
    use evtx::EvtxParser;
    use inputbot::{
        KeybdKey::{self, *},
        MouseButton::{self, *},
        MouseCursor,
    };
    use platform_dirs::UserDirs;
    use std::{
        fs::{self},
        io::{Read, Write},
        path::PathBuf,
        process::{Command, Stdio},
    };
    use std::{ops::Add, path::Path};
    extern crate self_update;
    use crate::{local_ipaddress_get, sleep, structs::ConfigEnv};
    use chrono::{Datelike, FixedOffset, Local, Utc};
    use dotenv::dotenv;

    use sysinfo::{ProcessExt, System, SystemExt};

    /// 監控資源佔用
    #[test]
    fn test_processes_monitor() {
        /* Process {
            name: String,
            cmd: Vec<String>,
            exe: PathBuf,
            pid: Pid,
            user_id: Option<Uid>,
            environ: Vec<String>,
            cwd: PathBuf,
            root: PathBuf,
            pub(crate) memory: u64,
            pub(crate) virtual_memory: u64,
            parent: Option<Pid>,
            status: ProcessStatus,
            handle: Option<Arc<HandleWrapper>>,
            cpu_calc_values: CPUsageCalculationValues,
            start_time: u64,
            pub(crate) run_time: u64,
            cpu_usage: f32,
            pub(crate) updated: bool,
            old_read_bytes: u64,
            old_written_bytes: u64,
            read_bytes: u64,
            written_bytes: u64,
        } */
        let mut system = System::new_all();
        system.refresh_processes();

        let processes = system.processes();
        // .filter(|(_, process)| !process.name().to_lowercase().contains("system"))
        // .map(|(pid, process)| (*pid, process.name().to_string()))
        // .collect::<Vec<(i32, String)>>();

        // 1697338602 時間戳轉換到 HH:MM 宏
        macro_rules! format_time {
            ($timestamp:expr) => {{
                let duration = chrono::Duration::seconds($timestamp);
                let hours = duration.num_hours();
                let minutes = duration.num_minutes() % 60;
                format!("{:02}:{:02}", hours, minutes)
            }};
        }
        for (pid, process) in processes {
            // println!("PID: {}, Name: {:?}", pid, process.name());

            if (process.name().contains("3200_nV") || process.name().contains("vshost")) {
                // 將process信息都打印出來

                // println!("cmd: {:?}\n", process.cmd());
                println!("exe: {:?}\n", process.exe());
                // println!("pid: {:?}\n", process.pid());
                // println!("user_id: {:?}\n", process.user_id());
                // println!("environ: {:?}\n", process.environ());
                // println!("cwd: {:?}\n", process.cwd()); // is the path
                // println!("root: {:?}\n", process.root());
                println!("memory: {:?} MB\n", process.memory() / 1048576); // 1048576 = 1024*1024  //raw in bytes)
                println!(
                    "virtual_memory(sys): {:?} GB\n",
                    process.virtual_memory() / 1048576 / 1024
                ); //raw in bytes
                   // println!("parent: {:?}\n", process.parent());
                println!("status: {:?}\n", process.status());
                println!(
                    "start_time: {:?}\n",
                    chrono::naive::NaiveDateTime::from_timestamp_opt(
                        process.start_time() as i64,
                        0
                    )
                    .unwrap()
                        + chrono::Duration::hours(8)
                );
                println!("run_time: {:?}\n", format_time!(process.run_time() as i64));
                println!("cpu_usage: {:?}\n", process.cpu_usage()); //divide the returned value by the number of CPUs.
                                                                    // println!("disk_usage: {:?}\n", process.disk_usage());
                                                                    // disk_usage: DiskUsage { total_written_bytes: 7797746, written_bytes: 0, total_read_bytes: 82554875, read_bytes: 0 }
            }
        }
    }

    /// 監控鍵盤鼠標事件
    #[test]
    fn test_keyboard_monitor() {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        KeybdKey::bind_all(|event| match inputbot::from_keybd_key(event) {
            Some(key) => println!(
                "{} Pressed: {:?}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                key
            ),
            None => println!("Pressed: {:?}", event),
        });
        MouseButton::bind_all(|event| {
            println!("Pressed: {:?},{:?}", event, MouseCursor::pos());
        });

        inputbot::handle_input_events();
    }

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
    #[test]
    fn test_cfg_update() {
        crate::cfg_update("telnet.timeout", "\ntelnet.timeout=10 # seconds");
    }

    /// chinese character decoding
    #[test]
    fn test_gbk() {
        use encoding::all::GBK;
        use encoding::{DecoderTrap, Encoding};
        let b: Vec<u8> = vec![
            13, 10, 211, 179, 207, 241, 195, 251, 179, 198, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 80, 73, 68, 32, 187, 225, 187, 176,
            195, 251, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 187, 225, 187, 176,
            35, 32, 32, 32, 32, 32, 32, 32, 196, 218, 180, 230, 202, 185, 211, 195, 32, 13, 10, 61,
            61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
            61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
            61, 61, 61, 61, 61, 61, 32, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 32, 61, 61, 61,
            61, 61, 61, 61, 61, 61, 61, 61, 61, 13, 10, 102, 105, 108, 101, 45, 119, 97, 116, 99,
            104, 46, 101, 120, 101, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 50,
            50, 51, 50, 56, 32, 67, 111, 110, 115, 111, 108, 101, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 49, 32, 32, 32, 32, 32, 49, 48, 44, 55,
            51, 54, 32, 75, 13, 10,
        ];
        println!("{}", GBK.decode(&b, DecoderTrap::Strict).unwrap());
    }
}

#[cfg(test)]
mod cobra_tests {
    use std::{io::Read, net::TcpStream, thread::Thread};

    use crate::{cobra::COBRA, sleep};
    #[test]
    fn test_cobra() {
        COBRA::init();
    }

    #[test]
    fn test_cobra_connect() {
        COBRA::connect(14);
    }

    #[test]
    /// for  cobra type detection
    fn test_cobra_type() {
        let computer_name = if cfg!(debug_assertions) {
            println!("debug_assertions - Debug Mode");
            "HSLTN061".to_string()
        } else {
            println!("debug_assertions - Release Mode");
            hostname::get().unwrap().to_str().unwrap().to_string()
        };

        // if computer_name = 61-68,71,80 then return true
        println!(
            "{}",
            matches!(
                &computer_name[computer_name.len() - 3..].parse::<i32>(),
                Ok(61..=68) | Ok(71) | Ok(80)
            )
        );
    }
    #[test]
    fn test_test() {
        let s = vec!["a", "b", "c"];
        println!("{:=>5}{}", "=", s.join("\n"));
    }

    // 測試TCP監聽
    #[test]
    fn test_tcp_listening() {
        if let Ok(mut stream) = TcpStream::connect("192.168.0.114:2915") {
            let mut buffer = [0; 1024];
            // stream.set_read_timeout(dur)
            println!("默認超時時間: {:?}", stream.read_timeout().unwrap());
            loop {
                let now = std::ops::Add::add(
                    chrono::Utc::now(),
                    chrono::FixedOffset::east_opt(8 * 3600).unwrap(),
                );
                println!("{now}");
                sleep(1);
                match stream.read(&mut buffer) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            println!("接收")
                        } else {
                            println!("空字符")
                        }
                    }
                    Err(e) => {
                        panic!("Err: {e}")
                    }
                }
            }
        } else {
            println!("通訊失敗")
        }
    }

    use regex::Regex;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    /// read auto_input and send keys
    #[test]
    fn print_inputbot_key() {
        // 打印 enum inputbot::KeybdKey
        // for i in 0..=255 {
        //     println!("{i:>3}, {:?}",inputbot::KeybdKey::from(i));
        // }

        // 打开文本文件

        // let file = File::open("auto_input.ini").expect("Failed to open file");
        match File::open("auto_input.ini") {
            Ok(file) => {
                let reader = BufReader::new(file);
                // 文件打开成功，继续处理

                // 正则表达式匹配模式
                let pattern = Regex::new(r#"^(\d+),(\d+),(.*?),(.*?),(.*?)$"#).unwrap();
                let bracket_pattern = Regex::new(r#"(\[.*?])"#).unwrap();

                // 逐行读取并处理
                for line in reader.lines() {
                    if let Ok(line) = line {
                        // 匹配正则表达式
                        if let Some(captures) = pattern.captures(&line) {
                            // 解析匹配的数据
                            let index: u32 = captures[1].parse().unwrap();
                            let window_title_matching_pattern: u32 = captures[2].parse().unwrap();
                            let window_title: &str = &captures[3];
                            let delay: u32 = captures[4].parse().unwrap();
                            let strings: &str = &captures[5];

                            // 判断是否以 "//" 开头
                            if !line.starts_with("//") {
                                // 在这里进行你的处理逻辑
                                println!("Index: {}", index);
                                println!(
                                    "Window Title Matching Pattern: {}",
                                    window_title_matching_pattern
                                );
                                println!("Window Title: {}", window_title);
                                println!("Delay: {}", delay);
                                let mut prev_end = 0;
                                for capture in bracket_pattern.captures_iter(strings) {
                                    let start = capture.get(0).unwrap().start();
                                    let end = capture.get(0).unwrap().end();

                                    if prev_end < start {
                                        let outside_content = &strings[prev_end..start];
                               
                                        println!("{}", outside_content);
                                    }

                                    let bracket_content = &strings[start..end];
                                    println!("BRACKET: {}", bracket_content);

                                    prev_end = end;
                                }

                                if prev_end < strings.len() {
                                    let outside_content = &strings[prev_end..];
                                    println!("{}", outside_content);
                                }
                                // println!("Strings: {}", strings);
                                println!("---");
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // 文件打开失败，执行另一个函数
                log::error!("Failed to open file (auto_input.ini)")
            }
        }
    }
}


#[cfg(test)]
mod screen_test{
    use crate::screen_monitor::init;

    #[test]
    fn test_screen_record(){
        init()
    }
}