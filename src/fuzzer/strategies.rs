use async_trait::async_trait;
use bytes::Bytes;

#[async_trait]
pub trait FuzzingStrategy: Send + Sync {
    fn name(&self) -> &str;
    
    async fn generate_input(&mut self) -> Bytes;
    
    async fn update_with_result(&mut self, result: FuzzingResult);
}

#[derive(Debug, Clone)]
pub struct FuzzingResult {
    pub coverage: CoverageInfo,
    pub crash: bool,
    pub timeout: bool,
    pub output: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CoverageInfo {
    pub branches_covered: u64,
    pub total_branches: u64,
    pub edges_covered: u64,
    pub total_edges: u64,
}
