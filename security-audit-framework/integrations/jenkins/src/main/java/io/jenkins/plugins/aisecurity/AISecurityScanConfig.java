package io.jenkins.plugins.aisecurity;

import java.io.Serializable;
import java.util.List;

/**
 * Configuration for AI Security Scan
 */
public class AISecurityScanConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String repository;
    private String branch;
    private String businessCriticality = "normal";
    private boolean incremental = false;
    private List<String> customPolicies;
    
    // AWS Configuration
    private String awsRegion;
    private String ceoLambdaArn;
    private String apiEndpoint;
    private String resultsBucket;
    private String scanTable;
    
    // Scan Options
    private boolean checkDependencies = true;
    private boolean checkSecrets = true;
    private boolean checkSast = true;
    private boolean checkIac = true;
    private boolean checkContainers = true;
    private int transitiveDepth = 2;
    private String costOptimization = "balanced";
    
    // Getters and setters
    public String getRepository() {
        return repository;
    }
    
    public void setRepository(String repository) {
        this.repository = repository;
    }
    
    public String getBranch() {
        return branch;
    }
    
    public void setBranch(String branch) {
        this.branch = branch;
    }
    
    public String getBusinessCriticality() {
        return businessCriticality;
    }
    
    public void setBusinessCriticality(String businessCriticality) {
        this.businessCriticality = businessCriticality;
    }
    
    public boolean isIncremental() {
        return incremental;
    }
    
    public void setIncremental(boolean incremental) {
        this.incremental = incremental;
    }
    
    public List<String> getCustomPolicies() {
        return customPolicies;
    }
    
    public void setCustomPolicies(List<String> customPolicies) {
        this.customPolicies = customPolicies;
    }
    
    public String getAwsRegion() {
        return awsRegion;
    }
    
    public void setAwsRegion(String awsRegion) {
        this.awsRegion = awsRegion;
    }
    
    public String getCeoLambdaArn() {
        return ceoLambdaArn;
    }
    
    public void setCeoLambdaArn(String ceoLambdaArn) {
        this.ceoLambdaArn = ceoLambdaArn;
    }
    
    public String getApiEndpoint() {
        return apiEndpoint;
    }
    
    public void setApiEndpoint(String apiEndpoint) {
        this.apiEndpoint = apiEndpoint;
    }
    
    public String getResultsBucket() {
        return resultsBucket;
    }
    
    public void setResultsBucket(String resultsBucket) {
        this.resultsBucket = resultsBucket;
    }
    
    public String getScanTable() {
        return scanTable;
    }
    
    public void setScanTable(String scanTable) {
        this.scanTable = scanTable;
    }
    
    public boolean isCheckDependencies() {
        return checkDependencies;
    }
    
    public void setCheckDependencies(boolean checkDependencies) {
        this.checkDependencies = checkDependencies;
    }
    
    public boolean isCheckSecrets() {
        return checkSecrets;
    }
    
    public void setCheckSecrets(boolean checkSecrets) {
        this.checkSecrets = checkSecrets;
    }
    
    public boolean isCheckSast() {
        return checkSast;
    }
    
    public void setCheckSast(boolean checkSast) {
        this.checkSast = checkSast;
    }
    
    public boolean isCheckIac() {
        return checkIac;
    }
    
    public void setCheckIac(boolean checkIac) {
        this.checkIac = checkIac;
    }
    
    public boolean isCheckContainers() {
        return checkContainers;
    }
    
    public void setCheckContainers(boolean checkContainers) {
        this.checkContainers = checkContainers;
    }
    
    public int getTransitiveDepth() {
        return transitiveDepth;
    }
    
    public void setTransitiveDepth(int transitiveDepth) {
        this.transitiveDepth = transitiveDepth;
    }
    
    public String getCostOptimization() {
        return costOptimization;
    }
    
    public void setCostOptimization(String costOptimization) {
        this.costOptimization = costOptimization;
    }
}