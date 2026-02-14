use crate::terminator;
use crate::safety;
use sysinfo::{System, Pid};
use tracing::{info, warn, debug};
use std::fs;

/// Triggers a full system panic.
/// 
/// 1. Terminates the caller's process tree (recursive).
/// 2. (Future) Zeroizes sensitive data.
pub fn trigger_panic(system: &mut System) {
    warn!("\u{26A0}\u{FE0F} PANIC PROTOCOL TRIGGERED");
    
    let my_pid = std::process::id();
    
    // Build tree
    let map = terminator::build_parent_child_map(system);
    let tree = terminator::collect_process_tree(my_pid, &map, system);
    
    // Kill tree bottom-up
    for node in tree {
        if safety::is_safe_to_kill(node.pid, &node.name) {
            info!(pid = node.pid, name = node.name, "Terminating process (Panic)");
            if let Some(process) = system.process(Pid::from(node.pid as usize)) {
                process.kill();
            }
        }
    }
    
    // Zeroization logic
    zeroize();
    
    info!("Panic protocol complete. Self-destructing.");
    std::process::exit(1);
}

/// Securely deletes temporary files and sensitive logs.
pub fn zeroize() {
    info!("Zeroizing sensitive data...");
    
    let targets = ["scan_results.json", "output.txt", "stderr.txt"];
    for target in &targets {
        if fs::remove_file(target).is_ok() {
            debug!(file = target, "Zeroized successfully");
        }
    }
}
