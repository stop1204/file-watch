use std::{
    io::{self, ErrorKind, Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::structs::ThreadPool;

// 用來接收cobra回傳信息的Vec, 24個元素
pub static mut COBRA_MESSAGE: Vec<String> = Vec::new();

pub struct COBRA {}
impl COBRA {
    /// cobra type , 0=single 1=dual

    pub fn init() {
        unsafe {
            COBRA_MESSAGE = Vec::with_capacity(24);
            for i in 0..24 {
                COBRA_MESSAGE.push(String::new());
            }
        }
        println!("cobra init");

        if Self::cobra_type() {
            let single_head_id = vec![1, 2, 3, 7, 8, 9, 13, 14, 15, 19, 20, 21];
            let pool = ThreadPool::new(4);
            for id in single_head_id {
                pool.execute(move || {
                    COBRA::connect(id);
                });
            }
        } else {
            let pool = ThreadPool::new(4);

            for id in 1..=24 {
                pool.execute(move || {
                    COBRA::connect(id);
                });
            }
        }

        println!("cobra init end");
        /* unsafe {
            println!("{:=>30}\n{:?}\n{:=>30}", "", COBRA_MESSAGE, "");
        } */
    }

    fn cobra_type() -> bool {
        let computer_name = if cfg!(debug_assertions) {
            println!("debug_assertions - Debug Mode");
            "HSLTN063".to_string()
        } else {
            println!("debug_assertions - Release Mode");
            hostname::get().unwrap().to_str().unwrap().to_string()
        };

        // if computer_name = 61-68,71,80 then return true

        matches!(
            &computer_name[computer_name.len() - 3..].parse::<i32>(),
            Ok(61..=68) | Ok(71) | Ok(80)
        )
    }
    /// id = 1..24
    /// test connect to cobra
    pub fn connect(id: usize) {
        unsafe {
            if COBRA_MESSAGE.capacity() == 0 {
                println!("COBRA VEC::with_capacity(24)");
                COBRA_MESSAGE = Vec::with_capacity(24);
                for i in 0..24 {
                    COBRA_MESSAGE.push(String::new());
                }
            }
        }
        println!("cobra connect: {id}");
        let ip_address = format!("192.168.0.1{:0>2}:1000", id);
        COBRA::server_start(ip_address, id);
    }

    fn server_start(ip_address: String, id: usize) {
        let id_ = id.clone();
        println!("ip: {ip_address}");

        if let Ok(stream) = TcpStream::connect(ip_address.trim()) {
            println!("cobra server start: {id}");

            COBRA::handle_connection(stream, id_);
        } else {
            println!("{id}, Err: Connection failed");
        };
        println!("server_stop: {id}");
    }

    fn handle_connection(mut stream: TcpStream, id: usize) {
        println!("{} {:?} Connected", id, stream.local_addr());
        let mut buffer = [0; 1024];

        // loop {
        //M1 STATUS(UP)(S.O.T. 26.00)(T_CASE NaN)(FEEDBACK: T-EVAP)UP_SENSOR(TRUE)(ERRORS: )
        // stream.write(b"CONFIG READ()\r\n").unwrap();
        // match stream.write(b"SOM STATUS()\r\n") { // need ip 1300,1100,1000
        /* 1, SOM STATUS:
        SW Version:CC 21.8.23.1 CPU: 70.9 SOM Memory Available: 309664.0 SD Free Space: 6474.0 SOM Storage: 239392.0 SOM Time: Sun 09 Oct 2022 08:16:55 AM HKT */
        match stream.write(b"SOM STATUS()\r\n") {
            Ok(_) => (),
            Err(e) => {
                println!("{: >2}, {:?}", id, e);
                return;
            }
        }
        match stream.write(b"STATUS2()\r\n") {
            Ok(_) => (),
            Err(e) => {
                println!("{: >2}, {:?}", id, e);
                return;
            }
        }
        // 讀取兩次
        for i in 0..2 {
            match stream.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        let response = match std::str::from_utf8(&buffer[..bytes_read]) {
                            Ok(v) => v,
                            Err(e) => Err(io::Error::new(ErrorKind::Other, e)).unwrap(),
                        };

                        if response.contains("System Module Error") {
                            /* println!(
                                "{: >2}, {:?}",
                                id,
                                Self::find_str(&response.to_string(), "ERRORS", "TSD Millivolts")
                            ); */
                            // 不輸出errors内容
                            let res = response
                                .replace(
                                    Self::find_str(
                                        &response.to_string(),
                                        "ERRORS",
                                        "TSD Millivolts",
                                    ),
                                    "",
                                )
                                .replace("ERRORS", "");
                            // println!("{: >2}, {}", id, res);
                            unsafe {
                                COBRA_MESSAGE[id - 1]
                                    .push_str(format!("DATA_START {: >2}, ", id).as_str());
                                COBRA_MESSAGE[id - 1].push_str(res.as_str());
                                COBRA_MESSAGE[id - 1].push_str("DATA_END");

                                COBRA_MESSAGE[id - 1].push_str("\r\n");
                            }
                        } else {
                            // println!("{: >2}, {}", id, response.trim());
                            unsafe {
                                COBRA_MESSAGE[id - 1]
                                    .push_str(format!("DATA_START {: >2}, ", id).as_str());
                                COBRA_MESSAGE[id - 1].push_str(response.trim());
                                COBRA_MESSAGE[id - 1].push_str("DATA_END");

                                COBRA_MESSAGE[id - 1].push_str("\r\n");
                            }
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::ConnectionAborted => {
                    println!("{id: >2}, Other side disconnected");

                    // set_site_status(id, -1);
                }
                Err(e) => {
                    println!("{id: >2}, Some other error occurred: {e}");
                    // set_site_status(id, -1);
                } // }
                  // stream.write(response.as_bytes()).unwrap();
                  //                 stream.flush().unwrap();
                  // Self::sleep(1.0);
            }
        }
    }
    fn find_str<'a>(raw: &'a String, s1: &str, s2: &str) -> &'a str {
        //println!("raw: {:?} \n find: {:?},{:?}", raw,s1,s2);
        let p1 = if let Some(v) = raw.find(s1) {
            v + s1.len()
        } else {
            return "";
        };
        let p2 = match raw[p1..].find(s2) {
            Some(p2) => p2,
            None => p1 + 0,
        };

        //println!("raw: {:?} \n find: {:?} {:?},{:?} {:?}  len: {}", raw,s1, p1,s2,p2,p1 + s1.len());
        &raw[p1..p2 + p1]
    }

    fn sleep(secs: f64) {
        thread::sleep(Duration::from_secs(if secs < 0.0 {
            1.0 as u64
        } else {
            secs as u64
        }));
    }

    /// 解析成簡單可讀內容, 方便一眼判斷cobra 好壞
    fn parse_data() {
        !todo!()
    }
}
