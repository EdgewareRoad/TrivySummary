package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TrivyScanMetadataImageConfig
{
    private String architecture;
    private String container;
    private String created;
    @JsonProperty("docker_version")
    private String dockerVersion;
    private TrivyScanMetadataImageConfigHistoryItem[] history;
    @JsonProperty("os")
    private String os;
    public TrivyScanMetadataImageConfig() {
    }
    public String getArchitecture() {
        return architecture;
    }
    public void setArchitecture(String architecture) {
        this.architecture = architecture;
    }
    public String getContainer() {
        return container;
    }
    public void setContainer(String container) {
        this.container = container;
    }
    public String getCreated() {
        return created;
    }
    public void setCreated(String created) {
        this.created = created;
    }
    public String getDockerVersion() {
        return dockerVersion;
    }
    public void setDockerVersion(String dockerVersion) {
        this.dockerVersion = dockerVersion;
    }
    public TrivyScanMetadataImageConfigHistoryItem[] getHistory() {
        return history;
    }
    public void setHistory(TrivyScanMetadataImageConfigHistoryItem[] history) {
        this.history = history;
    }
    public String getOS() {
        return os;
    }
    public void setOS(String os) {
        this.os = os;
    }
}