package com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class EPSSData {
    @JsonProperty("cve")
    private String vulnerabilityID;
    @JsonProperty("epss")
    private Double epssScore;
    @JsonProperty
    private Double percentile;
    @JsonProperty
    private Date date;

    public String getVulnerabilityID() {
        return vulnerabilityID;
    }
    public void setVulnerabilityID(String vulnerabilityID) {
        this.vulnerabilityID = vulnerabilityID;
    }
    public Double getEpssScore() {
        return epssScore;
    }
    public void setEpssScore(Double epssScore) {
        this.epssScore = epssScore;
    }
    public Double getPercentile() {
        return percentile;
    }
    public void setPercentile(Double percentile) {
        this.percentile = percentile;
    }
    public Date getDate() {
        return date;
    }
    public void setDate(Date date) {
        this.date = date;
    }
}