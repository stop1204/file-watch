// #![windows_subsystem = "windows"]
use hotwatch::{Event, Hotwatch};
use log::{error, info, warn};
use regex::Regex;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, process};
use std::{thread::sleep, time::Duration};
#[macro_use]
extern crate self_update;

mod session;
use crate::session::trace_msg;

/// CreateProcess
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// https://github.com/francesca64/hotwatch
///
/// https://blog.csdn.net/luchengtao11/article/details/124076575
///
/// base file: main.exe,config.ini,log4rs / Folder: Log
/// file-watcher is a tool to watch file changes
#[allow(unused_variables)]
fn main() {
    let (process_name, path_update_file, path_tmp_file): (String, PathBuf, PathBuf) = fun_name();
    {
        log4rs::init_file("log4rs.yml", Default::default()).unwrap();
        info!("Initialize...");
        /* trace_msg("debug".to_string());
        log::trace!("initialize done");
        log::debug!("debug");
        log::warn!("debug");
        error!("error");*/
        // trace_msg("Tracing...".to_string());
        repeatedly_execute(process_name);
    }

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

    // replace whitespace

    let re = Regex::new(r"[ ]{2,}").unwrap();
    loop {
        // process_cmd(re.clone());
        powershell();
        update(&path_update_file, &path_tmp_file).unwrap();

        if cfg!(debug_assertions) {
            sleep(Duration::from_secs(1));
        } else {
            sleep(Duration::from_secs(10));
        }
    }
}

fn fun_name() -> (String, PathBuf, PathBuf) {
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

fn watch_file(s: &str) -> Result<Hotwatch, String> {
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

// aoto exit when main.exe is run repeatedly
fn repeatedly_execute(process_name: String) {
    // deteact if XXX.exe is running
    let mut cmd = Command::new("tasklist");
    cmd.arg("/fi").arg(format!("imagename eq {}", process_name));
    let output = cmd.output().expect("failed to execute process");
    let output = String::from_utf8(output.stdout).unwrap();
    let mut count = 0;
    for line in output.lines() {
        if line.contains(process_name.as_str()) {
            count += 1;
        }
    }
    if count > 1 {
        info!("{} is running repeatedly, exit!", process_name);
        std::process::exit(0);
    }
}
fn powershell() {
    let pangram = r#"Get-SmbOpenFile|select ClientComputerName,Path"#;

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
#[allow(dead_code)]
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

/// need to be run as admin
/// need: update file name same as excutable file name
fn update(update_file: &PathBuf, tmp_file: &PathBuf) -> Result<(), Box<dyn ::std::error::Error>> {
    if !update_file.exists() {
        return Ok(());
    }
    info!("Update file");
    self_update::Move::from_source(&update_file)
        .replace_using_temp(&tmp_file)
        .to_dest(&::std::env::current_exe()?)?;
    Ok(())
}
