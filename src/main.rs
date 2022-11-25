use std::{thread::sleep, time::Duration};

use hotwatch::{Event, Hotwatch};
use log::{error, info, warn};

/// https://github.com/francesca64/hotwatch
///
/// https://blog.csdn.net/luchengtao11/article/details/124076575
///
///
fn main() {
    info!("initialize...");
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();

    let cfg = match std::fs::read_to_string("config.ini") {
        Ok(s) => s,
        Err(e) => {
            error!("config.toml: {}", e);
            std::process::exit(1);
        }
    };

    let mut hotwatch_vec: Vec<Hotwatch> = vec![];
    cfg.lines().for_each(|path| {
        if let Ok(v) = watch_file(path) {
            hotwatch_vec.push(v);
            info!("watching path: {}", path);
        }
    });

    loop {
        sleep(Duration::from_secs(2));
    }
}

fn watch_file(s: &str) -> Result<Hotwatch, String> {
    let mut hotwatch = Hotwatch::new().expect("hotwatch failed to initialize!");
    hotwatch
        .watch(s, |event: Event| match event {
            Event::Create(path) => info!(
                "[Create] File {:?} was created!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Write(path) => info!(
                "[Write]  File {:?} was written to!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Remove(path) => warn!(
                "[Remove] File {:?} was removed!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Rename(from, to) => info!(
                "[Rename] File {:?} was renamed to {:?}",
                from.file_name().unwrap_or(from.as_os_str()),
                to.file_name().unwrap_or(to.as_os_str())
            ),
            Event::Chmod(path) => info!(
                "[Chmod] File {:?} had its permissions changed!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::Error(err, path) => {
                error!("[Error] Error {:?} occurred for file {:?}", err, path)
            }
            Event::Rescan => info!("Rescan"),
            Event::NoticeWrite(path) => info!(
                "[NoticeWrite] File {:?} was written to!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
            Event::NoticeRemove(path) => info!(
                "[NoticeRemove] File {:?} was removed!",
                path.file_name().unwrap_or(path.as_os_str())
            ),
        })
        .expect("failed to watch file!");
    Ok(hotwatch)
}
