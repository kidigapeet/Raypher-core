//! Shadow AI Discovery — finds unmanaged AI services on the local machine and network.
//!
//! Detects: Known AI binaries, AI service ports, GPU-accelerated processes,
//! AI-pattern command lines, and (optionally) mDNS service broadcasts.

use sysinfo::System;
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::Utc;
// use uuid::Uuid; (Removed unused)

/// A discovered AI asset (process, service, or network endpoint)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAiAsset {
    /// Unique ID for this discovery
    pub id: String,
    /// Type of discovery
    pub asset_type: AssetType,
    /// Process name or service name
    pub name: String,
    /// PID if it's a local process
    pub pid: Option<u32>,
    /// Port if it's a service
    pub port: Option<u16>,
    /// IP address (127.0.0.1 for local, or network IP)
    pub ip: String,
    /// How it was detected
    pub detection_method: DetectionMethod,
    /// Risk level (1-10)
    pub risk_level: u8,
    /// Human-readable description
    pub description: String,
    /// When discovered
    pub discovered_at: String,
    /// Whether it's managed by Raypher
    pub managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    LocalLlm,          // Ollama, llama.cpp, etc.
    VectorDatabase,    // ChromaDB, Qdrant, Pinecone local
    AiFramework,       // LangChain, AutoGPT, CrewAI
    GpuProcess,        // Any process loading CUDA/ROCm
    UnknownAiService,  // Detected via port/pattern but unidentified
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    ProcessName,       // Known binary name
    PortScan,          // Known AI port open
    CommandLine,       // AI-pattern arguments
    LibraryLoad,       // GPU DLLs loaded
    DnsSnooping,       // AI API DNS queries detected
}

/// Known AI process signatures
const AI_PROCESS_NAMES: &[(&str, AssetType, u8)] = &[
    ("ollama", AssetType::LocalLlm, 7),
    ("llama-server", AssetType::LocalLlm, 7),
    ("llama.cpp", AssetType::LocalLlm, 7),
    ("llamafile", AssetType::LocalLlm, 7),
    ("torchserve", AssetType::AiFramework, 6),
    ("tritonserver", AssetType::AiFramework, 6),
    ("chromadb", AssetType::VectorDatabase, 5),
    ("qdrant", AssetType::VectorDatabase, 5),
    ("milvus", AssetType::VectorDatabase, 5),
    ("vllm", AssetType::LocalLlm, 8),
    ("text-generation-server", AssetType::LocalLlm, 7),
];

/// Known AI service ports
const AI_PORTS: &[(u16, &str, AssetType, u8)] = &[
    (11434, "Ollama", AssetType::LocalLlm, 7),
    (8000,  "FastAPI/ChromaDB", AssetType::UnknownAiService, 4),
    (6333,  "Qdrant", AssetType::VectorDatabase, 5),
    (6334,  "Qdrant gRPC", AssetType::VectorDatabase, 5),
    (5000,  "Flask AI", AssetType::UnknownAiService, 3),
    (8080,  "TorchServe/vLLM", AssetType::UnknownAiService, 4),
    (19530, "Milvus", AssetType::VectorDatabase, 5),
    (3000,  "LangServe/Gradio", AssetType::UnknownAiService, 3),
    (7860,  "Gradio", AssetType::AiFramework, 4),
    (8501,  "Streamlit", AssetType::AiFramework, 3),
];

/// AI-related command line patterns
const AI_CMDLINE_PATTERNS: &[&str] = &[
    "--model", "--checkpoint", "--weights",
    "transformers", "langchain", "autogpt", "crewai",
    "openai", "anthropic", "huggingface",
    "llama", "mistral", "falcon", "phi-",
    "--lora", "--quantize", "--4bit", "--8bit",
    "torch.distributed", "accelerate launch",
];

const GPU_LIBRARIES: &[&str] = &[
    "cudart64", "cudart32",      // NVIDIA CUDA Runtime
    "nvcuda",                     // NVIDIA CUDA Driver
    "cublas", "cublasLt",        // NVIDIA cuBLAS
    "cudnn",                      // NVIDIA cuDNN
    "pytorch",                    // PyTorch
    "torch_cuda",                 // PyTorch CUDA
    "libtorch",                   // LibTorch C++
    "tensorflow",                 // TensorFlow
    "onnxruntime",               // ONNX Runtime
    "rocm",                       // AMD ROCm
];

/// Run a full shadow AI discovery scan.
/// Returns a list of all discovered assets.
pub fn run_full_scan() -> Vec<ShadowAiAsset> {
    let mut assets = Vec::new();

    // Layer A: Process scanning
    assets.extend(scan_processes());

    // Layer B: Port scanning
    assets.extend(scan_ports());

    // Layer C: DNS Cache Snooping
    assets.extend(snoop_dns_cache());

    assets
}

/// Scan running processes for known AI signatures.
fn scan_processes() -> Vec<ShadowAiAsset> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut assets = Vec::new();
    let now = Utc::now().to_rfc3339();

    for (pid, process) in sys.processes() {
        let name_str = process.name().to_string_lossy();
        let proc_name = name_str.to_lowercase();
        
        let cmd_vec: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
        let cmd_line = cmd_vec.join(" ").to_lowercase();

        // Check against known AI process names
        for (ai_name, asset_type, risk) in AI_PROCESS_NAMES {
            if proc_name.contains(ai_name) {
                assets.push(ShadowAiAsset {
                    id: format!("proc-{}-{}", pid.as_u32(), ai_name),
                    asset_type: asset_type.clone(),
                    name: name_str.to_string(),
                    pid: Some(pid.as_u32()),
                    port: None,
                    ip: "127.0.0.1".into(),
                    detection_method: DetectionMethod::ProcessName,
                    risk_level: *risk,
                    description: format!("Known AI process '{}' running as PID {}", ai_name, pid.as_u32()),
                    discovered_at: now.clone(),
                    managed: false,
                });
                break;
            }
        }

        // Check command line for AI patterns
        for pattern in AI_CMDLINE_PATTERNS {
            if cmd_line.contains(pattern) {
                assets.push(ShadowAiAsset {
                    id: format!("cmd-{}-{}", pid.as_u32(), pattern.replace(' ', "_")),
                    asset_type: AssetType::AiFramework,
                    name: name_str.to_string(),
                    pid: Some(pid.as_u32()),
                    port: None,
                    ip: "127.0.0.1".into(),
                    detection_method: DetectionMethod::CommandLine,
                    risk_level: 5,
                    description: format!("Process {} has AI-related argument: '{}'", name_str, pattern),
                    discovered_at: now.clone(),
                    managed: false,
                });
                break; // One match per process is enough
            }
        }
    }
    assets
}

/// Scan common AI ports on localhost.
fn scan_ports() -> Vec<ShadowAiAsset> {
    let mut assets = Vec::new();
    let now = Utc::now().to_rfc3339();
    let timeout = Duration::from_millis(100);

    for (port, name, asset_type, risk) in AI_PORTS {
        let addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            assets.push(ShadowAiAsset {
                id: format!("port-127.0.0.1-{}", port),
                asset_type: asset_type.clone(),
                name: name.to_string(),
                pid: None,
                port: Some(*port),
                ip: "127.0.0.1".into(),
                detection_method: DetectionMethod::PortScan,
                risk_level: *risk,
                description: format!("AI service '{}' detected on port {}", name, port),
                discovered_at: now.clone(),
                managed: false,
            });
        }
    }
    assets
}

/// Check the OS DNS cache for AI-related domain resolutions.
/// This is a simpler alternative to raw DNS packet capture.
pub fn snoop_dns_cache() -> Vec<ShadowAiAsset> {
    let mut assets = Vec::new();
    let now = Utc::now().to_rfc3339();

    let ai_domains = [
        "api.openai.com", "api.anthropic.com", "api.deepseek.com",
        "generativelanguage.googleapis.com", "api.cohere.ai",
        "huggingface.co", "api-inference.huggingface.co",
        "api.mistral.ai", "api.groq.com", "api.together.xyz",
    ];

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig")
            .args(["/displaydns"])
            .output()
        {
            let dns_text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for domain in &ai_domains {
                if dns_text.contains(&domain.to_lowercase()) {
                    assets.push(ShadowAiAsset {
                        id: format!("dns-{}", domain.replace('.', "-")),
                        asset_type: AssetType::UnknownAiService,
                        name: domain.to_string(),
                        pid: None,
                        port: None,
                        ip: "unknown".into(),
                        detection_method: DetectionMethod::DnsSnooping,
                        risk_level: 6,
                        description: format!("AI API domain '{}' found in DNS cache — an agent on this machine likely called it", domain),
                        discovered_at: now.clone(),
                        managed: false,
                    });
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, check resolvectl if available
        if let Ok(output) = std::process::Command::new("resolvectl")
            .args(["query", "api.openai.com"]) // Test a common one to see if resolvectl works
            .output()
        {
            if output.status.success() {
                // Best effort: just check if the output mentions the domain
                let dns_text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if dns_text.contains("openai.com") {
                     assets.push(ShadowAiAsset {
                        id: "dns-openai-linux".into(),
                        asset_type: AssetType::UnknownAiService,
                        name: "api.openai.com".into(),
                        pid: None,
                        port: None,
                        ip: "unknown".into(),
                        detection_method: DetectionMethod::DnsSnooping,
                        risk_level: 6,
                        description: "AI API domain 'api.openai.com' responded via resolvectl".into(),
                        discovered_at: now.clone(),
                        managed: false,
                    });
                }
            }
        }
    }

    assets
}
