package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import java.time.LocalDate;

import org.springframework.util.StringUtils;

public class WhitelistEntryBuilder {
    private WhitelistEntry entry = new WhitelistEntry();

    public WhitelistEntryBuilder setVulnerabilityID(String vulnerabilityID) {
        entry.setVulnerabilityID(vulnerabilityID);
        return this;
    }
    public WhitelistEntryBuilder setReason(String reason) {
        entry.setReason(reason);
        return this;
    }
    public WhitelistEntryBuilder setNextReviewDate(LocalDate nextReviewDate) {
        entry.setNextReviewDate(nextReviewDate);
        return this;
    }
    public WhitelistEntryBuilder setApprovalDate(LocalDate approvalDate) {
        entry.setApprovalDate(approvalDate);
        return this;
    }
    public WhitelistEntryBuilder setApprovedBy(String approvedBy) {
        entry.setApprovedBy(approvedBy);
        return this;
    }
    
    public WhitelistEntry build()
    {
        if (!StringUtils.hasText(entry.getVulnerabilityID()) || !StringUtils.hasText(entry.getReason()) || entry.getNextReviewDate() == null)
        {
            throw new IllegalArgumentException("WhitelistEntry does not have the minimum mandatory data");
        }
        return entry;
    }
}
