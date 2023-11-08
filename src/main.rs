#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use dotenv::dotenv;
use file_watch::*;
use hotwatch::Hotwatch;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use regex::Regex;

use std::{path::PathBuf, thread::sleep, time::Duration};
mod structs;
use crate::structs::ConfigEnv;

/// https://github.com/francesca64/hotwatch
///
/// https://blog.csdn.net/luchengtao11/article/details/124076575
///
/// Basic required file: [main.exe],[config.ini],[log4rs]
///
#[allow(unused_variables)]
fn main() {
    cfg_update("telnet.timeout", "\ntelnet.timeout=30 # seconds");

    let (process_name, path_update_file, path_tmp_file): (String, PathBuf, PathBuf) =
        get_update_file_name();
    {
        dotenv().ok();
        log4rs::init_file("log4rs.yml", Default::default()).unwrap();
        info!("Initialize...");

        /*   trace_msg("debug".to_string());
        log::trace!("initialize done");
        log::debug!("debug");
        log::warn!("debug");
        error!("error"); */
        // trace_msg("Tracing...".to_string());
        repeatedly_execute(process_name);
    }

    let cfg_eng = ConfigEnv::from_env().expect("Failed to initialize project configuration");
    let cfg = match std::fs::read_to_string("config.ini") {
        Ok(s) => s,
        Err(e) => {
            error!("config.toml: {}", e);
            std::process::exit(1);
        }
    };

    // watching files change
    let mut hotwatch_vec: Vec<Hotwatch> = vec![];
    cfg.lines().for_each(|path| match watch_file(path) {
        Ok(v) => hotwatch_vec.push(v),
        Err(e) => error!("watching failed: {},{:?}", path, e),
    });

    // keyboard_monitor

    // listening on port 6666
    let thread1 = std::thread::spawn(move || {
        receive_message();
    });
    // 創建一個新的線程，用於監控進程狀態
    let thread2 = std::thread::spawn(move || {
        processes_monitor();
    });
    let thread3 = std::thread::spawn(move || {
        keyboard_monitor();
    });

    // replace whitespace
    let re = Regex::new(r"[ ]{2,}").unwrap();
    loop {
        // process_cmd(re.clone());
        powershell(r#"Get-SmbOpenFile|select ClientComputerName,Path"#);
        update(&path_update_file, &path_tmp_file).unwrap();

        if cfg!(debug_assertions) {
            sleep(Duration::from_secs(1));
        } else {
            sleep(Duration::from_secs(10));
        }
    }
}
