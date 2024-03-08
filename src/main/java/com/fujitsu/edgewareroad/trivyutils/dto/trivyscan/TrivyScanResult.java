package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TrivyScanResult
{
    @JsonProperty("Target")
    private String target;

    @JsonProperty("Class")
    private String targetClass;

    @JsonProperty("Type")
    private String targetType;

    @JsonProperty("Vulnerabilities")
    private TrivyScanPackageVulnerabilities vulnerabilities = new TrivyScanPackageVulnerabilities();

    public TrivyScanResult() {
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getTargetClass() {
        return targetClass;
    }

    public void setTargetClass(String targetClass) {
        this.targetClass = targetClass;
    }

    public String getTargetType() {
        return targetType;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public TrivyScanPackageVulnerabilities getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(TrivyScanPackageVulnerabilities vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}