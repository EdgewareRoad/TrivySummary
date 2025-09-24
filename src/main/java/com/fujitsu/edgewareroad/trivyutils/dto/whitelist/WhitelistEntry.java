package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor()
@Builder
@JsonDeserialize(builder = WhitelistEntry.WhitelistEntryBuilder.class)
public class WhitelistEntry implements Comparable<WhitelistEntry> {
    @JsonProperty(required = true)
    private @NonNull @Getter @Setter String vulnerabilityID;
    @JsonProperty(required = true)
    private @NonNull @Getter @Setter String reason;
    @JsonProperty(required = true)
    private @NonNull @Getter @Setter LocalDate nextReviewDate;
    @JsonProperty(required = false)
    private @Getter @Setter LocalDate approvalDate;
    @JsonProperty(required = false)
    private @Getter @Setter String approvedBy;

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
