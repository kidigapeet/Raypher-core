use crate::scanner::{ProcessData, RiskLevel};
use tracing::{info, debug};

/// Result of a heuristic analysis pass
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    pub level: RiskLevel,
    pub reason: String,
    pub matched_rule: String,
    pub analysis_layer: u8, // 1, 2, or 3
}

/// LEVEL 1: Binary name matching against known AI/ML process names.
/// This is the fastest check — O(1) hash lookup.
///
/// RATIONALE: These binaries are legitimate tools, but their PRESENCE
/// on a machine indicates AI workloads that Raypher should monitor.
pub fn analyze_level1_binary_name(proc: &ProcessData) -> Option<HeuristicResult> {
    let name_lower = proc.name.to_lowercase();

    // AI/ML Runtime Binaries — MEDIUM risk (legitimate but monitored)
    let ai_runtime_binaries: &[(&str, &str)] = &[
        ("ollama", "Local LLM inference server"),
        ("uvicorn", "ASGI server — likely serving an AI API"),
        ("torchserve", "PyTorch model serving"),
        ("tritonserver", "NVIDIA Triton inference server"),
        ("vllm", "vLLM high-throughput LLM serving"),
        ("text-generation", "HuggingFace TGI server"),
        ("llamacpp", "llama.cpp inference"),
        ("koboldcpp", "KoboldCpp LLM server"),
        ("localai", "LocalAI inference server"),
        ("lmstudio", "LM Studio desktop LLM"),
        ("jan", "Jan AI local LLM"),
        ("gpt4all", "GPT4All local inference"),
        ("mlflow", "MLflow model tracking/serving"),
        ("bentoml", "BentoML model serving"),
        ("ray", "Ray distributed AI framework"),
        ("celery", "Task queue — often used for AI pipelines"),
    ];

    for (binary, description) in ai_runtime_binaries {
        if name_lower.contains(binary) {
            return Some(HeuristicResult {
                level: RiskLevel::Medium,
                reason: format!("AI runtime detected: {} ({})", binary, description),
                matched_rule: format!("L1_BINARY_{}", binary.to_uppercase()),
                analysis_layer: 1,
            });
        }
    }

    // Interpreter binaries — LOW risk (need Level 2 arg analysis)
    let interpreters: &[&str] = &[
        "python", "python3", "python3.11", "python3.12",
        "node", "nodejs", "deno", "bun",
        "ruby", "java", "dotnet",
    ];

    for interp in interpreters {
        if name_lower.starts_with(interp) {
            return Some(HeuristicResult {
                level: RiskLevel::Low,
                reason: format!("Interpreter detected: {} — requires argument analysis", interp),
                matched_rule: format!("L1_INTERP_{}", interp.to_uppercase()),
                analysis_layer: 1,
            });
        }
    }

    None
}

/// LEVEL 2: Command-line argument analysis.
/// Only runs on processes that passed Level 1 as interpreters.
///
/// This is the CRITICAL detection layer. A process named "python.exe"
/// is harmless. A process named "python.exe -m langchain.agents"
/// is an autonomous AI agent that needs governance.
pub fn analyze_level2_arguments(proc: &ProcessData) -> Option<HeuristicResult> {
    let args_joined = proc.cmd.join(" ").to_lowercase();

    // TIER A: CRITICAL — Autonomous agent frameworks (self-directing AI)
    let critical_keywords: &[(&str, &str)] = &[
        ("langchain", "LangChain agent framework"),
        ("langgraph", "LangGraph stateful agent orchestration"),
        ("autogen", "Microsoft AutoGen multi-agent framework"),
        ("crewai", "CrewAI multi-agent orchestration"),
        ("autogpt", "AutoGPT autonomous agent"),
        ("babyagi", "BabyAGI task-driven agent"),
        ("metagpt", "MetaGPT multi-agent framework"),
        ("superagi", "SuperAGI autonomous agent platform"),
        ("agentgpt", "AgentGPT web-based autonomous agent"),
        ("openclaw", "Open Claw AI agent"),
        ("swarm", "OpenAI Swarm agent framework"),
        ("phidata", "Phidata agent framework"),
    ];

    for (keyword, description) in critical_keywords {
        if args_joined.contains(keyword) {
            return Some(HeuristicResult {
                level: RiskLevel::Critical,
                reason: format!("Autonomous agent framework detected: {} ({})", keyword, description),
                matched_rule: format!("L2_CRITICAL_{}", keyword.to_uppercase()),
                analysis_layer: 2,
            });
        }
    }

    // TIER B: HIGH — LLM API access patterns
    let high_keywords: &[(&str, &str)] = &[
        ("openai", "OpenAI API access"),
        ("anthropic", "Anthropic Claude API access"),
        ("together", "Together AI API access"),
        ("replicate", "Replicate model API"),
        ("huggingface_hub", "HuggingFace Hub API"),
        ("cohere", "Cohere API access"),
        ("api_key", "API key in arguments — credential exposure"),
        ("sk-", "OpenAI API key pattern"),
        ("claude-", "Claude model invocation"),
        ("gpt-3.5", "GPT-3.5 model invocation"),
        ("gpt-4", "GPT-4 model invocation"),
    ];

    for (keyword, description) in high_keywords {
        if args_joined.contains(keyword) {
            return Some(HeuristicResult {
                level: RiskLevel::High,
                reason: format!("LLM API access detected: {} ({})", keyword, description),
                matched_rule: format!("L2_HIGH_{}", keyword.to_uppercase()),
                analysis_layer: 2,
            });
        }
    }

    // TIER C: MEDIUM — ML libraries and frameworks
    let medium_keywords: &[&str] = &[
        "transformers", "torch", "tensorflow", "pytorch",
        "scikit-learn", "keras", "jax", "flax",
        "sentence-transformers", "embeddings",
    ];

    for keyword in medium_keywords {
        if args_joined.contains(keyword) {
            return Some(HeuristicResult {
                level: RiskLevel::Medium,
                reason: format!("ML library detected: {}", keyword),
                matched_rule: format!("L2_MEDIUM_{}", keyword.to_uppercase()),
                analysis_layer: 2,
            });
        }
    }

    None
}

pub fn analyze_level3_environment(proc: &ProcessData) -> Option<HeuristicResult> {
    let env_vars: &[(&str, &str)] = &[
        ("OPENAI_API_KEY", "Found OpenAI credentials in environment"),
        ("ANTHROPIC_API_KEY", "Found Anthropic credentials in environment"),
        ("GOOGLE_API_KEY", "Found Google AI credentials in environment"),
        ("LANGCHAIN_", "LangChain configuration in environment"),
        ("HF_TOKEN", "HuggingFace token in environment"),
        ("MISTRAL_API_KEY", "Mistral credentials in environment"),
        ("GROQ_API_KEY", "Groq credentials in environment"),
    ];

    for (var, reason) in env_vars {
        if proc.environ.iter().any(|e| e.starts_with(var)) {
            return Some(HeuristicResult {
                level: RiskLevel::High,
                reason: reason.to_string(),
                matched_rule: format!("L3_ENV_{}", var.replace("_", "")),
                analysis_layer: 3,
            });
        }
    }

    None
}

/// Master heuristic analysis function.
/// Runs all levels in sequence and returns the highest-risk result.
pub fn analyze_process(proc: &mut ProcessData) {
    // Level 1: Binary name check (fast)
    if let Some(result) = analyze_level1_binary_name(proc) {
        debug!(
            pid = proc.pid,
            name = %proc.name,
            rule = %result.matched_rule,
            "Level 1 match"
        );
        
        // If it's an interpreter, also run Level 2
        if result.level == RiskLevel::Low {
            if let Some(level2) = analyze_level2_arguments(proc) {
                proc.risk_level = level2.level;
                proc.risk_reason = level2.reason;
                return;
            }
        }
        
        proc.risk_level = result.level;
        proc.risk_reason = result.reason;
        return;
    }

    // Level 2: Direct argument check (for non-interpreter processes)
    if let Some(result) = analyze_level2_arguments(proc) {
        proc.risk_level = result.level;
        proc.risk_reason = result.reason;
        return;
    }

    // Level 3: Environment analysis (future)
    if let Some(result) = analyze_level3_environment(proc) {
        proc.risk_level = result.level;
        proc.risk_reason = result.reason;
        return;
    }

    // No matches — mark as None
    proc.risk_level = RiskLevel::None;
    proc.risk_reason = "No risk indicators detected".to_string();
}

/// Batch analysis — runs heuristics on all processes
pub fn analyze_all(processes: &mut [ProcessData]) {
    for proc in &mut *processes {
        analyze_process(proc);
    }
    
    info!(
        total = processes.len(),
        critical = processes.iter().filter(|p| p.risk_level == RiskLevel::Critical).count(),
        high = processes.iter().filter(|p| p.risk_level == RiskLevel::High).count(),
        medium = processes.iter().filter(|p| p.risk_level == RiskLevel::Medium).count(),
        "Heuristic analysis complete"
    );
}
