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
}
#[derive(Deserialize, Clone)]
pub struct ConfigEnv {
    pub sys_log: SysLogConfig,
    pub telnet: TelnetConfig,
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
