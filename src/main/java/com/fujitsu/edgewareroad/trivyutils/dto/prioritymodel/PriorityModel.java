package com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.VulnerabilitySeverity;

public class PriorityModel {
    @JsonProperty
    private PriorityModelType type = PriorityModelType.SEVERITYONLY;
    @JsonProperty
    private VulnerabilityScorePriorityThresholds criticalPriorityThresholds = null;
    @JsonProperty
    private VulnerabilityScorePriorityThresholds highPriorityThresholds = null;
    @JsonProperty
    private VulnerabilityScorePriorityThresholds mediumPriorityThresholds = null;

    public PriorityModel()
    {
    }

    public PriorityModel(PriorityModelType type, VulnerabilityScorePriorityThresholds critical, VulnerabilityScorePriorityThresholds high, VulnerabilityScorePriorityThresholds medium)
    {
        this.type = type;
        this.criticalPriorityThresholds = critical;
        this.highPriorityThresholds = high;
        this.mediumPriorityThresholds = medium;
    }

    public PriorityModelType getType()
    {
        return type;
    }

    public VulnerabilityScorePriorityThresholds getThresholds(VulnerabilityPriority priority)
    {
        switch(priority)
        {
            case CRITICAL:
                return criticalPriorityThresholds;
            case HIGH:
                return highPriorityThresholds;
            case MEDIUM:
                return mediumPriorityThresholds;
            default:
                return null;
        }
    }

    public VulnerabilityScorePriorityThresholds getCriticalThresholds()
    {
        return criticalPriorityThresholds;
    }
    public VulnerabilityScorePriorityThresholds getHighThresholds()
    {
        return highPriorityThresholds;
    }
    public VulnerabilityScorePriorityThresholds getMediumThresholds()
    {
        return mediumPriorityThresholds;
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
                if (criticalPriorityThresholds != null && cvssScore >= criticalPriorityThresholds.getMinimumCVSS() && (epssScore >= criticalPriorityThresholds.getMinimumEPSS()))
                    return VulnerabilityPriority.CRITICAL;
                else if (highPriorityThresholds != null && cvssScore >= highPriorityThresholds.getMinimumCVSS() && (epssScore >= highPriorityThresholds.getMinimumEPSS()))
                    return VulnerabilityPriority.HIGH;
                else if (mediumPriorityThresholds != null && cvssScore >= mediumPriorityThresholds.getMinimumCVSS() && (epssScore >= mediumPriorityThresholds.getMinimumEPSS()))
                    return VulnerabilityPriority.MEDIUM;
                else
                    // We've not matched a priority so we must assume a LOW priority
                    return VulnerabilityPriority.LOW;
            
            case ELLIPTICAL:
            if (criticalPriorityThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, criticalPriorityThresholds))
                return VulnerabilityPriority.CRITICAL;
            else if (highPriorityThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, highPriorityThresholds))
                return VulnerabilityPriority.HIGH;
            else if (mediumPriorityThresholds != null && withinEllipticalModeThresholds(cvssScore, epssScore, mediumPriorityThresholds))
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
        double ellipseCVSSAxis = 10.0d - priorityThresholds.getMinimumCVSS();
        double ellipseEPSSAxis = 1.0d - priorityThresholds.getMinimumEPSS();
        double ellipseCVSSPoint = 10.0d - cvssScore;
        double ellipseEPSSPoint = 1.0d - epssScore;

        double insideEllipsisScore = (Math.pow(ellipseCVSSPoint, 2) / Math.pow(ellipseCVSSAxis, 2)) + (Math.pow(ellipseEPSSPoint, 2) / Math.pow(ellipseEPSSAxis, 2));
        return (insideEllipsisScore <= 1.0d);
    }
}
