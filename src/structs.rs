use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use serde::Deserialize;
///
///
///
///
#[derive(Deserialize, Clone)]
pub struct SysLogConfig {
    pub key1: String,
    pub key2: String,
    pub duration: i64,
    pub text_wrapping: usize,
}
#[derive(Deserialize, Clone)]
pub struct TelnetConfig {
    pub default: bool,
    pub default_ip: String,
    pub port: String,
    pub timeout: u64,
}

#[derive(Deserialize, Clone)]
pub struct MonitorConfig {
    pub default: bool,
    pub refresh_interval: u64,
    pub process: String,
}
#[derive(Deserialize, Clone)]
pub struct ConfigEnv {
    pub sys_log: SysLogConfig,
    pub telnet: TelnetConfig,
    pub monitor: MonitorConfig,
}
impl ConfigEnv {
    /// 从环境变量中初始化配置
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .unwrap();

        // Print out our settings (as a HashMap)

        settings.try_deserialize()
    }
    /* /// 从文件中初始化配置  cmd.toml
    pub fn from_file() -> Result<std::collections::HashMap<String, String>, config::ConfigError> {
        let settings = config::Config::builder()
            // Add in `./cmd.toml`
            .add_source(config::File::with_name("setting/cmd.toml"))
            .build()
            .unwrap();
        settings.try_deserialize::<std::collections::HashMap<String, String>>()
    }
    /// set other config (other.toml)
    pub fn set_other_key(key: &str, value: &str) -> Result<(), config::ConfigError> {
        // let mut settings = config::Config::default();
        // settings.set("web.addr", "
        let settings = config::Config::builder()
            // Add in `./cmd.toml`
            .add_source(config::File::with_name("setting/other.toml"))
            .set_override(key, value)
            .unwrap()
            .build()
            .unwrap();
        std::fs::write(
            "setting/other.toml",
            settings
                .try_deserialize::<std::collections::HashMap<String, String>>()
                .unwrap()
                .iter()
                .map(|(k, v)| k.to_owned() + "='" + v.as_str() + "'\n")
                .collect::<String>(),
        )
        .unwrap();
        Ok(())
    }
    pub fn get_other_key(key: &str) -> Result<String, config::ConfigError> {
        let settings = config::Config::builder()
            // Add in `./cmd.toml`
            .add_source(config::File::with_name("setting/other.toml"))
            .build()
            .unwrap();
        let map: std::collections::HashMap<String, String> = settings.try_deserialize()?;

        match map.get(key) {
            Some(v) => Ok(v.to_owned()),
            None => Ok("None".to_owned()),
        }
    } */
}

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: mpsc::Sender<Message>,
}
impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    ///
    /// # Panics
    ///
    /// The `new` function will panic if the size is zero.
    pub fn new(size: usize) -> ThreadPool {
        assert!(size > 0);
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        ThreadPool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.send(Message::NewJob(job)).unwrap();
    }
}
enum Message {
    NewJob(Job),
    Terminate,
}
impl Drop for ThreadPool {
    fn drop(&mut self) {
        // println!("Sending terminate message to all workers.");

        for _ in &self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        // println!("Shutting down all workers.");

        for worker in &mut self.workers {
            // println!("Shutting down worker {}", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap_or(());
            }
        }
    }
}
#[allow(dead_code)]
struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();

            match message {
                Message::NewJob(job) => {
                    // println!("Worker {}; executing.", id);

                    job();
                }
                Message::Terminate => {
                    // println!("Worker {} was told to terminate.", id);

                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
