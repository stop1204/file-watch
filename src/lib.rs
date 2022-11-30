//! # created by Terry on 2022-11-25
//!
//! file-watcher is a tool to watch file changes
use hotwatch::{Event, Hotwatch};
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use regex::Regex;
use std::{
    env,
    io::{Read, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
   
};
extern crate self_update;

mod session;
use crate::session::trace_msg;
const CREATE_NO_WINDOW: u32 = 0x08000000;



#[cfg(test)]
mod test {

    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
    };

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
