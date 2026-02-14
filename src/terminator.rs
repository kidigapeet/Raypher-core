use std::collections::HashMap;
use sysinfo::{System, Pid};
use tracing::{info, warn, debug};
use serde::Serialize;

/// Represents a node in the process tree
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub name: String,
    pub children: Vec<u32>,
    pub depth: u32,
}

/// Builds a map of Parent PID -> [Child PIDs] from all running processes.
/// 
/// This is the foundation of recursive tree traversal.
pub fn build_parent_child_map(system: &System) -> HashMap<u32, Vec<u32>> {
    let mut map: HashMap<u32, Vec<u32>> = HashMap::new();

    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        if let Some(parent_pid) = process.parent() {
            let parent_u32 = parent_pid.as_u32();
            map.entry(parent_u32)
                .or_insert_with(Vec::new)
                .push(pid_u32);
        }
    }

    debug!(
        total_parents = map.len(),
        "Process parent-child map built"
    );

    map
}

/// Recursively collects ALL descendant PIDs of a target process.
/// 
/// The result is ordered so that children come before parents (bottom-up).
pub fn collect_process_tree(
    target_pid: u32,
    parent_child_map: &HashMap<u32, Vec<u32>>,
    system: &System,
) -> Vec<ProcessNode> {
    let mut tree = Vec::new();
    collect_recursive(target_pid, parent_child_map, system, &mut tree, 0);

    // Sort by depth DESCENDING so children are killed before parents
    tree.sort_by(|a, b| b.depth.cmp(&a.depth));

    info!(
        target_pid = target_pid,
        tree_size = tree.len(),
        "Process tree collected"
    );

    tree
}

fn collect_recursive(
    pid: u32,
    map: &HashMap<u32, Vec<u32>>,
    system: &System,
    result: &mut Vec<ProcessNode>,
    depth: u32,
) {
    // Guard against infinite recursion
    if depth > 100 {
        warn!(pid = pid, "Process tree too deep, stopping recursion");
        return;
    }

    // Guard against cycles
    if result.iter().any(|n| n.pid == pid) {
        return;
    }

    let name = system.process(Pid::from(pid as usize))
        .map(|p| p.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    let children = map.get(&pid).cloned().unwrap_or_default();

    result.push(ProcessNode {
        pid,
        name,
        children: children.clone(),
        depth,
    });

    for child_pid in children {
        collect_recursive(child_pid, map, system, result, depth + 1);
    }
}

/// Pretty-prints the process tree for visualization.
pub fn print_process_tree(tree: &[ProcessNode], target_pid: u32) {
    println!("\n\u{1F333} PROCESS TREE for PID {}:", target_pid);
    println!("{}", "─".repeat(50));

    // For display, we want depth ASCENDING
    let mut display_tree = tree.to_vec();
    display_tree.sort_by(|a, b| a.depth.cmp(&b.depth));

    for node in &display_tree {
        let indent = "  ".repeat(node.depth as usize);
        let safety_status = if crate::safety::is_safe_to_kill(node.pid, &node.name) {
            "\u{2705} (Targetable)"
        } else {
            "\u{1F6E1}\u{FE0F} [PROTECTED]"
        };
        println!("{}├─ PID {} [{}] {}", indent, node.pid, node.name, safety_status);
    }
    println!("{}", "─".repeat(50));
    println!("Total: {} processes in tree", tree.len());
}

/// Terminates all targetable processes in the collected tree.
pub fn terminate_tree(tree: &[ProcessNode], system: &System) {
    for node in tree {
        if crate::safety::is_safe_to_kill(node.pid, &node.name) {
            info!(pid = node.pid, name = node.name, "Terminating...");
            if let Some(process) = system.process(Pid::from(node.pid as usize)) {
                process.kill();
            }
        }
    }
}
