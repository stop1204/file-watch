// #! [windows_subsystem = "windows"]
use hotwatch::{Event, Hotwatch};
use log::{error, info, warn};
use std::process::Command;
use std::{thread::sleep, time::Duration};

mod session;
use crate::session::trace_msg;
/// https://github.com/francesca64/hotwatch
///
/// https://blog.csdn.net/luchengtao11/article/details/124076575
///
/// 基本文件    file: main.exe,config.ini,log4rs / Folder: Log
fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    info!("Initialize...");
    // trace_msg("Tracing...".to_string());
    let cfg = match std::fs::read_to_string("config.ini") {
        Ok(s) => s,
        Err(e) => {
            error!("config.toml: {}", e);
            std::process::exit(1);
        }
    };

    let mut hotwatch_vec: Vec<Hotwatch> = vec![];
    cfg.lines().for_each(|path| match watch_file(path) {
        Ok(v) => hotwatch_vec.push(v),
        Err(e) => error!("watching failed: {},{:?}", path, e),
    });

    loop {
        let cmd1 = Command::new("net")
            .arg("session")
            .output()
            .expect("process failed to execute");
        match String::from_utf8(cmd1.stdout) {
            Ok(v) => {
                if v.len() > 10 && !v.contains("no entries") {
                    info!(
                        "net session:\n{}",
                        &v[v.rfind("-\r\n").unwrap_or(0) + 5..v.rfind("\r\nThe").unwrap_or(0)]
                            .replacen("   ", "  ", 15)
                    );
                }
            }
            Err(e) => {
                trace_msg(format!("net session: {}", e));
            }
        }
        let cmd2 = Command::new("openfiles")
            .output()
            .expect("process failed to execute");

        // chinese charactor
        // String::from_utf8_lossy(format!("{:?}",cmd2).as_bytes())

        match String::from_utf8(cmd2.stdout) {
            Ok(v) => {
                if v.len() > 10 && !v.contains("No shared") {
                    trace_msg(format!(
                        "openfiles:\n{}",
                        &v[v.rfind("=\r\n").unwrap_or(0) + 5..].replacen("   ", "  ", 10)
                    ))
                }
            }
            Err(e) => {
                trace_msg(format!("openfiles: {}", e));
            }
        }
        sleep(Duration::from_secs(10));
    }
}

fn watch_file(s: &str) -> Result<Hotwatch, String> {
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
                "[NoticeWrite] File {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::NoticeRemove(path) => info!(
                "[NoticeRemove] File {:?}",
                path.file_name().unwrap_or(path.as_os_str())
            ),
        })
        .expect("failed to watch file!");
    Ok(hotwatch)
}
