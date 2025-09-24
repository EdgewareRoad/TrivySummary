package com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.VulnerabilitySeverity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor 
@AllArgsConstructor
public class PriorityModel {
    @JsonProperty
    private @Getter PriorityModelType type = PriorityModelType.SEVERITYONLY;
    @JsonProperty("criticalPriorityThresholds")
    private @Getter VulnerabilityScorePriorityThresholds criticalThresholds = null;
    @JsonProperty("highPriorityThresholds")
    private @Getter VulnerabilityScorePriorityThresholds highThresholds = null;
    @JsonProperty("mediumPriorityThresholds")
    private @Getter VulnerabilityScorePriorityThresholds mediumThresholds = null;

    public VulnerabilityScorePriorityThresholds getThresholds(VulnerabilityPriority priority)
    {
        switch(priority)
        {
            case CRITICAL:
                return criticalThresholds;
            case HIGH:
                return highThresholds;
            case MEDIUM:
                return mediumThresholds;
            default:
                return null;
        }
    }

    public static VulnerabilityPriority getPriorityOnlyFromVendorSeverity(VulnerabilitySeverity vendorSeverity)
    {
        switch(vendorSeverity)
        {
            case CRITICAL:
                return VulnerabilityPriority.CRITICAL;
            case HIGH:
                return VulnerabilityPriority.HIGH;
            case MEDIUM:
                return VulnerabilityPriority.MEDIUM;
            default:
                return VulnerabilityPriority.LOW;
        }
    }

    public VulnerabilityPriority getPriority(VulnerabilitySeverity vendorSeverity, Double cvssScore, Double epssScore)
    {
        // We do get EPSS scores which are not returned from the API and this invariably means that they've disappeared from live consideration (i.e. in Trivy but not in redHat or NVD), so we reset these to zero.
        // Note this doesn't affect SEVERITYONLY which will be forced in Offline mode (which will always have zero EPSS scores, of course) so this is a safe operation.
        if (epssScore == null) epssScore = 0.0d;

        switch (getType()) {
            case SEVERITYONLY:
                return getPriorityOnlyFromVendorSeverity(vendorSeverity);
            
            case RECTANGULAR:
                if (criticalThresholds != null && cvssScore >= criticalThresholds.getMinimumCvss() && (epssScore >= criticalThresholds.getMinimumEpss()))
                    return VulnerabilityPriority.CRITICAL;
                else if (highThresholds != null && cvssScore >= highThresholds.getMinimumCvss() && (epssScore >= highThresholds.getMinimumEpss()))
                    return VulnerabilityPriority.HIGH;
                else if (mediumThresholds != null && cvssScore >= mediumThresholds.getMinimumCvss() && (epssScore >= mediumThresholds.getMinimumEpss()))
                    return VulnerabilityPriority.MEDIUM;
                else
                    // We've not matched a priority so we must assume a LOW priority
                    return VulnerabilityPriority.LOW;
            
            case ELLIPTICAL:
            if (criticalThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, criticalThresholds))
                return VulnerabilityPriority.CRITICAL;
            else if (highThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, highThresholds))
                return VulnerabilityPriority.HIGH;
            else if (mediumThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, mediumThresholds))
                return VulnerabilityPriority.MEDIUM;
            else
                // We've not matched a priority so we must assume a LOW priority
                return VulnerabilityPriority.LOW;

            default:
                // We should never get to this point
                throw new RuntimeException("Code error: Unhandled priority model type");
        }
    }

    private boolean withinEllipticalModeThresholds(double cvssScore, double epssScore, VulnerabilityScorePriorityThresholds priorityThresholds)
    {
        double ellipseCVSSAxis = 10.0d - priorityThresholds.getMinimumCvss();
        double ellipseEPSSAxis = 1.0d - priorityThresholds.getMinimumEpss();
        double ellipseCVSSPoint = 10.0d - cvssScore;
        double ellipseEPSSPoint = 1.0d - epssScore;

        double insideEllipsisScore = (Math.pow(ellipseCVSSPoint, 2) / Math.pow(ellipseCVSSAxis, 2)) + (Math.pow(ellipseEPSSPoint, 2) / Math.pow(ellipseEPSSAxis, 2));
        return (insideEllipsisScore <= 1.0d);
    }
}
