package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.time.ZonedDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
public class TrivyScan
{
    @JsonProperty("SchemaVersion")
    private @Getter @Setter int schemaVersion;

    @JsonProperty("CreatedAt")
    private @Getter @Setter ZonedDateTime createdAt;

    @JsonProperty("ArtifactName")
    private @Getter @Setter String artifactName;

    @JsonProperty("ArtifactType")
    private @Getter @Setter String artifactType;

 //   @JsonProperty("Metadata")
 //   private @Getter @Setter TrivyScanMetadata metadata;

    @JsonProperty("Results")
    private @Getter @Setter TrivyScanResult[] results;

    /**
     * Gets the complete set of vulnerabilities for this scan, irrespective of the targeted result.
     * Good for overview reports
     * @return All vulnerabilities in this scan, ordered by severity (highest first)
     */
    public TrivyScanPackageVulnerabilities getAllPackageVulnerabilities()
    {
        TrivyScanPackageVulnerabilities vulnerabilitiesToReturn = new TrivyScanPackageVulnerabilities();

        if (results != null)
        {
            for(TrivyScanResult result : results)
            {
                vulnerabilitiesToReturn.addAll(result.getVulnerabilities());
            }
        }
        return vulnerabilitiesToReturn;
    }
}