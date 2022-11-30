mod session;
#[cfg(test)]
mod test {

    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
    };

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

    #[test]
    fn update() -> Result<(), Box<dyn ::std::error::Error>> {
        let tmp_dir = tempfile::Builder::new()
            // .prefix("file-watch")
            .tempdir_in(::std::env::current_dir()?)?;
            let bin_name = std::path::PathBuf::from("file-watch");
            
            let tmp_file = tmp_dir.path().join("replacement_tmp");
            let bin_path = tmp_dir.path().join(bin_name);
            println!("tmp_dir: {:?}", tmp_dir.path());
            println!("tmp_file: {:?}", tmp_file);
            println!("bin_path: {:?}", bin_path);

            panic!();
        self_update::Move::from_source(&bin_path)
            .replace_using_temp(&tmp_file)
            .to_dest(&::std::env::current_exe()?)?;

        Ok(())
    }
}
