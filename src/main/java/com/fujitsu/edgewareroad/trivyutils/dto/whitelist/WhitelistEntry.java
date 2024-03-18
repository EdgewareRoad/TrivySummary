package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class WhitelistEntry implements Comparable<WhitelistEntry> {
    @JsonProperty(required = true)
    private String vulnerabilityID;
    @JsonProperty(required = true)
    private String reason;
    @JsonProperty(required = true)
    private LocalDate nextReviewDate;
    @JsonProperty(required = false)
    private LocalDate approvalDate;
    @JsonProperty(required = false)
    private String approvedBy;

    protected WhitelistEntry()
    {
    }

    public WhitelistEntry(
        @JsonProperty(value = "vulnerabilityID", required = true) String vulnerabilityID,
        @JsonProperty(value = "reason", required = true) String reason,
        @JsonProperty(value = "nextReviewDate", required = true) LocalDate nextReviewDate,
        @JsonProperty(value = "approvalDate", required = false) LocalDate approvalDate,
        @JsonProperty(value = "approvedBy", required = false) String approvedBy
        )
    {
        this.vulnerabilityID = vulnerabilityID;
        this.reason = reason;
        this.nextReviewDate = nextReviewDate;
        this.approvalDate = approvalDate;
        this.approvedBy = approvedBy;
    }

    public String getVulnerabilityID() {
        return vulnerabilityID;
    }
    public void setVulnerabilityID(String vulnerabilityID) {
        this.vulnerabilityID = vulnerabilityID;
    }
    public String getReason() {
        return reason;
    }
    public void setReason(String reason) {
        this.reason = reason;
    }
    public LocalDate getNextReviewDate() {
        return nextReviewDate;
    }
    public void setNextReviewDate(LocalDate nextReviewDate) {
        this.nextReviewDate = nextReviewDate;
    }
    public LocalDate getApprovalDate() {
        return approvalDate;
    }
    public void setApprovalDate(LocalDate approvalDate) {
        this.approvalDate = approvalDate;
    }
    public String getApprovedBy() {
        return approvedBy;
    }
    public void setApprovedBy(String approvedBy) {
        this.approvedBy = approvedBy;
    }

    @Override
    public int compareTo(WhitelistEntry that) {
        if (that == null) return 1;

        if (this.vulnerabilityID == null)
        {
            if (that.vulnerabilityID == null)
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }

        return this.vulnerabilityID.compareTo(that.vulnerabilityID);
    }

    @Override
    public boolean equals(Object arg0) {
        if (arg0 == null) return false;
        if (!WhitelistEntry.class.isInstance(arg0)) return false;
        if (vulnerabilityID == null) return vulnerabilityID == ((WhitelistEntry)arg0).vulnerabilityID;
        return vulnerabilityID.equals(((WhitelistEntry)arg0).vulnerabilityID);
    }

    @Override
    public int hashCode() {
        return vulnerabilityID != null ? vulnerabilityID.hashCode() : 0;
    }
}
