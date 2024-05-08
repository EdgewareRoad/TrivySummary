package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TrivyScan
{
    @JsonProperty("SchemaVersion")
    private int schemaVersion;

    @JsonProperty("CreatedAt")
    private LocalDate createdAt;

    @JsonProperty("ArtifactName")
    private String artifactName;

    @JsonProperty("ArtifactType")
    private String artifactType;

    @JsonProperty("Metadata")
    private TrivyScanMetadata metadata;

    @JsonProperty("Results")
    private TrivyScanResult[] results;

    public TrivyScan() {
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(int schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public LocalDate getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDate createdAt) {
        this.createdAt = createdAt;
    }    

    public String getArtifactName() {
        return artifactName;
    }

    public void setArtifactName(String artifactName) {
        this.artifactName = artifactName;
    }

    public String getArtifactType() {
        return artifactType;
    }

    public void setArtifactType(String artifactType) {
        this.artifactType = artifactType;
    }

    public TrivyScanMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(TrivyScanMetadata metadata) {
        this.metadata = metadata;
    }

    public TrivyScanResult[] getResults() {
        return results;
    }

    public void setResults(TrivyScanResult[] results) {
        this.results = results;
    }

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
                for(TrivyScanPackageVulnerability vulnerability : result.getVulnerabilities())
                {
                    vulnerabilitiesToReturn.add(vulnerability);
                }
            }
        }
        return vulnerabilitiesToReturn;
    }
}