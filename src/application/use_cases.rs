//! Use cases representing application workflows

use std::sync::Arc;
use tracing::{debug, info};

use super::errors::ApplicationError;
use super::services::{AnalysisService, ReportService};
use crate::domain::{AnalysisReport, Ecosystem, Vulnerability, VulnerabilityId};

/// Use case for analyzing dependencies in a file
pub struct AnalyzeDependencies {
    analysis_service: Arc<dyn AnalysisService>,
}

impl AnalyzeDependencies {
    /// Create a new analyze dependencies use case
    pub fn new(analysis_service: Arc<dyn AnalysisService>) -> Self {
        Self { analysis_service }
    }

    /// Execute the dependency analysis workflow
    #[tracing::instrument(skip(self, file_content))]
    pub async fn execute(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
    ) -> Result<AnalysisReport, ApplicationError> {
        info!(
            "Executing dependency analysis use case for ecosystem: {:?}",
            ecosystem
        );

        let analysis_result = self
            .analysis_service
            .analyze_dependencies(file_content, ecosystem)
            .await?;

        info!(
            "Dependency analysis completed - {} packages, {} vulnerabilities",
            analysis_result.metadata.total_packages, analysis_result.metadata.total_vulnerabilities
        );

        Ok(analysis_result)
    }
}

/// Use case for retrieving vulnerability details
pub struct GetVulnerabilityDetails {
    analysis_service: Arc<dyn AnalysisService>,
}

impl GetVulnerabilityDetails {
    /// Create a new get vulnerability details use case
    pub fn new(analysis_service: Arc<dyn AnalysisService>) -> Self {
        Self { analysis_service }
    }

    /// Execute the vulnerability details retrieval workflow
    #[tracing::instrument(skip(self))]
    pub async fn execute(
        &self,
        vulnerability_id: &VulnerabilityId,
    ) -> Result<Vulnerability, ApplicationError> {
        info!(
            "Executing vulnerability details retrieval for ID: {}",
            vulnerability_id.as_str()
        );

        let vulnerability = self
            .analysis_service
            .get_vulnerability_details(vulnerability_id)
            .await?;

        debug!(
            "Retrieved vulnerability details for {}: {} ({})",
            vulnerability_id.as_str(),
            vulnerability.summary,
            vulnerability.severity
        );

        Ok(vulnerability)
    }
}

/// Use case for generating analysis reports
pub struct GenerateReport {
    report_service: Arc<dyn ReportService>,
}

impl GenerateReport {
    /// Create a new generate report use case
    pub fn new(report_service: Arc<dyn ReportService>) -> Self {
        Self { report_service }
    }

    /// Execute the report generation workflow
    #[tracing::instrument(skip(self, analysis))]
    pub async fn execute(
        &self,
        analysis: &AnalysisReport,
        format: ReportFormat,
    ) -> Result<String, ApplicationError> {
        info!(
            "Executing report generation for analysis {} in format: {:?}",
            analysis.id, format
        );

        let report = match format {
            ReportFormat::Text => {
                debug!("Generating text format report");
                self.report_service.generate_report(analysis).await?
            }
            ReportFormat::Html | ReportFormat::Json => {
                debug!("Generating JSON format report");
                // Note: generate_html_report actually generates JSON format
                // as per the implementation in ReportServiceImpl
                self.report_service.generate_html_report(analysis).await?
            }
        };

        info!(
            "Report generation completed - {} characters in {:?} format",
            report.len(),
            format
        );

        Ok(report)
    }
}

/// Supported report formats
#[derive(Debug, Clone)]
pub enum ReportFormat {
    Text,
    Html,
    Json,
}
