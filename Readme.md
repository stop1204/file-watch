`2024年12月18日`
# Program Overview

This program, developed in **Rust**, is designed for efficient monitoring and automation tasks. It is lightweight, with a memory usage of only 5MB and CPU utilization below 1%, ensuring it operates seamlessly without impacting the production environment.

## Features and Components

### Main Program Files
- **`main.rs`**  
  The core entry point for launching various sub-services.

- **`lib.rs`**  
  Manages logging and functional utilities.

### Modules Overview
- **File Monitoring**  
  Monitors all file changes within a specified directory (`./config.ini`) to track potential issues such as file loss or unintended operations.

- **`cobra.rs`**  
  Gathers real-time status and version information of multiple Cobra machines via the Telnet protocol.  
  Key Use: Detect abnormal conditions (e.g., pressure drops or coolant leaks) to initiate proactive replacements.

- **`keyboard_monitor.rs`**
    - Logs keyboard and mouse activity to identify actions leading to crashes.
    - Automates keyboard input based on parameters in the configuration file (e.g., auto-login, manual command testing).

- **`process_monitor.rs`**  
  Tracks the status and runtime of processes, including CPU usage, to log critical data for analysis.

- **`screen_monitor.rs`**  
  Captures screen recordings with customizable settings (resolution, frame rate, encoder).  
  **Default**: Disabled.  
  **Use Case**: Troubleshooting machine crashes by recording pre-crash states.

- **`session.rs`**  
  Logs remote session activities, verifying if files are being accessed, modified, or deleted remotely. Works in conjunction with `event.log`.

### Configuration
- **`.env`**  
  Contains startup configuration items.

## Usage Scenarios
- **Crash Diagnostics**
    - Identify causes by combining input logs (`keyboard_monitor.rs`), session logs (`session.rs`), and screen recordings (`screen_monitor.rs`).
- **Proactive Maintenance**
    - Use `cobra.rs` to monitor machine parameters and replace units showing abnormal values.
- **Automated Testing**
    - Simulate inputs and commands using `keyboard_monitor.rs`.

## Default Settings
- File monitoring directory: `./config.ini`
- Screen recording: Disabled
- Memory usage: 5MB
- CPU usage: <1%

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
