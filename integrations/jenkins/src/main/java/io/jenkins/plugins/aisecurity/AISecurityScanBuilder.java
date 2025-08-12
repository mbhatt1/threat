package io.jenkins.plugins.aisecurity;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import hudson.*;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.PrintStream;
import java.util.*;

/**
 * AI Security Scanner build step
 */
public class AISecurityScanBuilder extends Builder implements SimpleBuildStep {
    
    private String repository;
    private String branch;
    private String businessCriticality;
    private String awsCredentialsId;
    private boolean failOnCritical;
    private int failOnHighThreshold;
    private boolean incremental;
    private boolean generateReports;
    private List<String> customPolicies;
    
    @DataBoundConstructor
    public AISecurityScanBuilder() {
        // Required empty constructor
    }
    
    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, 
                       @Nonnull EnvVars env, @Nonnull Launcher launcher, 
                       @Nonnull TaskListener listener) throws InterruptedException, IOException {
        
        PrintStream logger = listener.getLogger();
        logger.println("🔍 Starting AI Security Scan...");
        
        // Get AWS credentials
        AmazonWebServicesCredentials awsCreds = null;
        if (awsCredentialsId != null && !awsCredentialsId.isEmpty()) {
            awsCreds = CredentialsProvider.findCredentialById(
                awsCredentialsId, 
                AmazonWebServicesCredentials.class, 
                run
            );
        }
        
        // Prepare scan configuration
        AISecurityScanConfig config = new AISecurityScanConfig();
        config.setRepository(expandVariable(repository, env));
        config.setBranch(expandVariable(branch, env));
        config.setBusinessCriticality(businessCriticality);
        config.setIncremental(incremental);
        config.setCustomPolicies(customPolicies);
        
        // Get global configuration
        AISecurityGlobalConfig globalConfig = AISecurityGlobalConfig.get();
        config.setAwsRegion(globalConfig.getAwsRegion());
        config.setCeoLambdaArn(globalConfig.getCeoLambdaArn());
        config.setApiEndpoint(globalConfig.getApiEndpoint());
        config.setResultsBucket(globalConfig.getResultsBucket());
        
        // Execute scan
        AISecurityScanner scanner = new AISecurityScanner(awsCreds, listener);
        AISecurityScanResult result = scanner.performScan(workspace, config);
        
        // Process results
        processScanResults(run, workspace, result, listener);
        
        // Check failure conditions
        checkFailureConditions(result, listener);
    }
    
    private void processScanResults(Run<?, ?> run, FilePath workspace, 
                                   AISecurityScanResult result, TaskListener listener) 
                                   throws IOException, InterruptedException {
        
        PrintStream logger = listener.getLogger();
        
        // Log summary
        logger.println("📊 Scan Summary:");
        logger.println("   Scan ID: " + result.getScanId());
        logger.println("   Total Findings: " + result.getTotalFindings());
        logger.println("   Critical: " + result.getCriticalFindings());
        logger.println("   High: " + result.getHighFindings());
        logger.println("   Business Risk Score: " + result.getBusinessRiskScore() + "/100");
        logger.println("   AI Confidence: " + result.getAiConfidenceScore() + "%");
        
        // Set build variables
        run.addAction(new AISecurityBuildAction(result));
        EnvVars env = run.getEnvironment(listener);
        env.put("AI_SCAN_ID", result.getScanId());
        env.put("AI_CRITICAL_COUNT", String.valueOf(result.getCriticalFindings()));
        env.put("AI_HIGH_COUNT", String.valueOf(result.getHighFindings()));
        env.put("AI_RISK_SCORE", String.valueOf(result.getBusinessRiskScore()));
        env.put("AI_CONFIDENCE", String.valueOf(result.getAiConfidenceScore()));
        
        // Generate reports
        if (generateReports) {
            generateSecurityReports(workspace, result, listener);
        }
    }
    
    private void generateSecurityReports(FilePath workspace, AISecurityScanResult result, 
                                       TaskListener listener) throws IOException, InterruptedException {
        
        PrintStream logger = listener.getLogger();
        logger.println("📄 Generating security reports...");
        
        // Create reports directory
        FilePath reportsDir = workspace.child("security-reports");
        reportsDir.mkdirs();
        
        // Generate HTML report
        String htmlReport = result.getHtmlReport();
        if (htmlReport != null) {
            FilePath htmlFile = reportsDir.child("security-scan-report.html");
            htmlFile.write(htmlReport, "UTF-8");
            logger.println("   ✅ HTML report: security-reports/security-scan-report.html");
        }
        
        // Generate SARIF report
        String sarifReport = result.getSarifReport();
        if (sarifReport != null) {
            FilePath sarifFile = reportsDir.child("security-scan.sarif");
            sarifFile.write(sarifReport, "UTF-8");
            logger.println("   ✅ SARIF report: security-reports/security-scan.sarif");
        }
        
        // Generate JUnit report
        String junitReport = result.getJunitReport();
        if (junitReport != null) {
            FilePath junitFile = reportsDir.child("security-tests.xml");
            junitFile.write(junitReport, "UTF-8");
            logger.println("   ✅ JUnit report: security-reports/security-tests.xml");
        }
    }
    
    private void checkFailureConditions(AISecurityScanResult result, TaskListener listener) 
                                      throws AbortException {
        
        PrintStream logger = listener.getLogger();
        
        // Check critical findings
        if (failOnCritical && result.getCriticalFindings() > 0) {
            logger.println("❌ Build failed: " + result.getCriticalFindings() + " critical findings detected!");
            throw new AbortException("Critical security findings detected");
        }
        
        // Check high findings threshold
        if (failOnHighThreshold > 0 && result.getHighFindings() > failOnHighThreshold) {
            logger.println("❌ Build failed: " + result.getHighFindings() + " high findings exceed threshold of " + failOnHighThreshold);
            throw new AbortException("High security findings exceed threshold");
        }
        
        logger.println("✅ Security scan passed!");
    }
    
    private String expandVariable(String value, EnvVars env) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        return env.expand(value);
    }
    
    // Getters and setters
    public String getRepository() {
        return repository;
    }
    
    @DataBoundSetter
    public void setRepository(String repository) {
        this.repository = repository;
    }
    
    public String getBranch() {
        return branch;
    }
    
    @DataBoundSetter
    public void setBranch(String branch) {
        this.branch = branch;
    }
    
    public String getBusinessCriticality() {
        return businessCriticality;
    }
    
    @DataBoundSetter
    public void setBusinessCriticality(String businessCriticality) {
        this.businessCriticality = businessCriticality;
    }
    
    public String getAwsCredentialsId() {
        return awsCredentialsId;
    }
    
    @DataBoundSetter
    public void setAwsCredentialsId(String awsCredentialsId) {
        this.awsCredentialsId = awsCredentialsId;
    }
    
    public boolean isFailOnCritical() {
        return failOnCritical;
    }
    
    @DataBoundSetter
    public void setFailOnCritical(boolean failOnCritical) {
        this.failOnCritical = failOnCritical;
    }
    
    public int getFailOnHighThreshold() {
        return failOnHighThreshold;
    }
    
    @DataBoundSetter
    public void setFailOnHighThreshold(int failOnHighThreshold) {
        this.failOnHighThreshold = failOnHighThreshold;
    }
    
    public boolean isIncremental() {
        return incremental;
    }
    
    @DataBoundSetter
    public void setIncremental(boolean incremental) {
        this.incremental = incremental;
    }
    
    public boolean isGenerateReports() {
        return generateReports;
    }
    
    @DataBoundSetter
    public void setGenerateReports(boolean generateReports) {
        this.generateReports = generateReports;
    }
    
    public List<String> getCustomPolicies() {
        return customPolicies;
    }
    
    @DataBoundSetter
    public void setCustomPolicies(List<String> customPolicies) {
        this.customPolicies = customPolicies;
    }
    
    @Symbol("aiSecurityScan")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }
        
        @Nonnull
        @Override
        public String getDisplayName() {
            return "AI Security Scan";
        }
        
        @POST
        public FormValidation doCheckFailOnHighThreshold(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                int threshold = Integer.parseInt(value);
                if (threshold < 0) {
                    return FormValidation.error("Threshold must be non-negative");
                }
                return FormValidation.ok();
            } catch (NumberFormatException e) {
                return FormValidation.error("Please enter a valid number");
            }
        }
        
        public ListBoxModel doFillBusinessCriticalityItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("Low", "low");
            items.add("Normal", "normal");
            items.add("High", "high");
            items.add("Critical", "critical");
            return items;
        }
        
        public ListBoxModel doFillAwsCredentialsIdItems(@AncestorInPath Item item,
                                                        @QueryParameter String credentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && 
                    !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }
            
            return result
                .includeEmptyValue()
                .includeMatchingAs(
                    item instanceof Queue.Task ? ((Queue.Task) item).getDefaultAuthentication() : ACL.SYSTEM,
                    item,
                    AmazonWebServicesCredentials.class,
                    Collections.emptyList(),
                    CredentialsProvider.NONE
                )
                .includeCurrentValue(credentialsId);
        }
    }
}