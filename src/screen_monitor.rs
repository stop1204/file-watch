use std::fmt::Error;
use std::{fs};
use std::process::{Command,
                   // exit,
                   Stdio};
use log::{info, error, trace,
          // debug,
          warn};
use std::fs::{create_dir_all, remove_dir_all};
use std::path::Path;
use chrono::{Local, Duration as ChronoDuration, NaiveDate, Duration};
use crate::powershell2;
// use log4rs;
use crate::structs::ConfigEnv;


fn check_ffmpeg(ffmpeg_path: &str) -> Result<(), Error> {
    if Command::new(ffmpeg_path)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_err() {
        error!("ffmpeg not found. Please install ffmpeg and make sure it is in your PATH.");
        // exit(1); // this will cause the program to exit
        return Err(Error::default());
    }
    Ok(())
}


fn create_directory(path: &str) {
    if !Path::new(path).exists() {
        info!("Creating directory: {}", path);
        create_dir_all(path).expect("Failed to create directory");
    }
}


fn remove_old_directories(base_path: &str, expire_days: &i64) {
    let seven_days_ago = Local::now() - Duration::days(*expire_days);
    /*let old_date_path = format!("{}/{}", base_path, seven_days_ago.format("%Y-%m-%d").to_string());
    if Path::new(&old_date_path).exists() {
        info!("Removing old recordings directory: {}", old_date_path);
        remove_dir_all(&old_date_path).expect("Failed to remove old recordings directory");
    }*/
    let cutoff_date = seven_days_ago.date().naive_local();

    if let Ok(entries) = fs::read_dir(base_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(entry_name) = entry.file_name().into_string() {
                    if let Ok(entry_date) = NaiveDate::parse_from_str(&entry_name, "%Y-%m-%d") {
                        if entry_date < cutoff_date {
                            let old_date_path = format!("{}/{}", base_path, entry_name);
                            warn!("Removing old recordings directory: {}", old_date_path);
                            if let Err(e) = remove_dir_all(&old_date_path) {
                                error!("Failed to remove old recordings directory {}: {}", old_date_path, e);
                            }
                        }
                    }
                }
            }
        }
    } else {
        error!("Failed to read base directory: {}", base_path);
    }
}
/// ffmpeg -f gdigrab -framerate 30 -i desktop -c:v libx264 -preset ultrafast -crf 40 -pix_fmt yuv420p -t 5 output.mp4
#[allow(dead_code)]
fn _record_screen(ffmpeg_path: &str, file_path: &str, frame_rate: &u64, encoder: &String, preset: &String, crf: &u64, pix_fmt: &String, duration: &u64, resolution: &String, threads: &u64) {
    // powershell(r#"start file-watch.exe"#);
    let mut ffmpeg_command = Command::new(ffmpeg_path)
        .args(&[
            // hide console
            "/C", "start",

            "-hide_banner",
            "-f", "gdigrab", // 使用 gdigrab 进行屏幕捕获
            "-threads", threads.to_string().as_str(), //  0使用所有线程 , 限制綫程數 1
            // "-framerate", "30", // 帧率
            // "-i", "desktop", // 输入设备
            // "-c:v", "libx264", // 使用 libx264 编码
            // "-preset", "ultrafast", // 编码速度
            // "-crf", "40", // 编码质量
            // "-pix_fmt", "yuv420p", // 像素格式
            // "-t", "5", // 录制时长（秒）
            "-framerate", frame_rate.to_string().as_str(), // 帧率
            "-i", "desktop", // 输入设备
            "-vf",format!("scale={}",resolution).as_str(), // 分辨率
            "-c:v", encoder, // 使用 libx264 编码
            "-preset", preset, // 编码速度
            "-crf", crf.to_string().as_str(), // 编码质量
            "-pix_fmt", pix_fmt, // 像素格式
            "-t", duration.to_string().as_str(), // 录制时长（秒）
            "-loglevel", "quiet", // log level quiet
            file_path, // 输出文件
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ffmpeg process");
    // cmd code: ffmpeg -f gdigrab -framerate 30 -i desktop -c:v libx264 -preset ultrafast -crf 40 -pix_fmt yuv420p -t 5 output.mp4
    trace!("Recording screen to: {}", file_path);
    ffmpeg_command.wait().expect("Failed to wait on ffmpeg process");
}
/// powershell Start-Process -NoNewWindow -FilePath "ffmpeg.exe" -ArgumentList "-hide_banner -f gdigrab -threads 0 -framerate 30 -i desktop -vf scale=1920x1080 -c:v libx264 -preset ultrafast -crf 40 -pix_fmt yuv420p -t 5 -loglevel quiet output.mp4"
fn record_screen(ffmpeg_path: &str, file_path: &str, frame_rate: &u64, encoder: &str, preset: &str, crf: &u64, pix_fmt: &str, duration: &u64, resolution: &str, threads: &u64) {
    let ps_script = format!(
        "Start-Process -NoNewWindow -FilePath '{}' -ArgumentList '-hide_banner -f gdigrab -threads {} -framerate {} -i desktop -vf scale={} -c:v {} -preset {} -crf {} -pix_fmt {} -t {} -loglevel quiet {}'",
        ffmpeg_path,
        threads,
        frame_rate,
        resolution,
        encoder,
        preset,
        crf,
        pix_fmt,
        duration,
        file_path
    );
    powershell2(&ps_script);
    trace!("Recording screen to: {}", file_path);
}

/// ffmpeg -f gdigrab -framerate 15 -i desktop -c:v libx264 -preset ultrafast -crf 40 -pix_fmt yuv420p -t 600 -threads 1 -s 1920x1080 -f flv output.flv
///
/// 這個命令可以防止錄製中斷后的視頻損壞
pub fn init() {
    let cfg = ConfigEnv::from_env().expect("Failed to initialize project configuration");
    if !cfg.monitor_screen.default { return; }
    info!("screen_monitor init");


    // let base_path = "./log/screen";
    // let ffmpeg_path = "./ffmpeg.exe";
    let base_path = &cfg.monitor_screen.base_path;
    let ffmpeg_path = &cfg.monitor_screen.ffmpeg_path;
    let frame_rate = &cfg.monitor_screen.frame_rate;
    let encoder = &cfg.monitor_screen.encoder;
    let preset = &cfg.monitor_screen.preset;
    let crf = &cfg.monitor_screen.crf;
    let pix_fmt = &cfg.monitor_screen.pix_fmt;
    let duration = &cfg.monitor_screen.duration;
    let resolution = &cfg.monitor_screen.resolution;
    let threads = &cfg.monitor_screen.threads;
    let expire_days = &cfg.monitor_screen.expire_days;
    let format = &cfg.monitor_screen.format;
    // 检查 ffmpeg 是否可用
    if let Ok(_) = check_ffmpeg(ffmpeg_path) {} else {
        return;
    }

    loop {
        // 获取当前日期文件夹和时间戳
        let current_date = Local::now().format("%Y-%m-%d").to_string();
        let timestamp = Local::now().format("%H-%M-%S").to_string();
        let date_path = format!("{}/{}", base_path, current_date);

        let file_path = if format == "flv" {
            format!("-f flv {}/{}.{}", date_path, timestamp, format)
        } else {
            format!("{}/{}.{}", date_path, timestamp, format)
        };

        // 创建当前日期的文件夹
        create_directory(&date_path);

        // 删除expire_days天前的文件夹
        remove_old_directories(base_path,expire_days);

        // 录制屏幕
        record_screen(ffmpeg_path, &file_path, frame_rate, encoder, preset, crf, pix_fmt, duration,resolution,threads);
        // 这里的delay是应用于新的record_screen, 因为call cmd会变成独立线程
    }
}