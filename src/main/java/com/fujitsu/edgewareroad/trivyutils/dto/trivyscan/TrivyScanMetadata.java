package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TrivyScanMetadata
{
    @JsonProperty("OS")
    private TrivyScanMetadataOS os;

    @JsonProperty("ImageID")
    private String imageID;

    @JsonProperty("DiffIDs")
    private String[] diffIDs;

    @JsonProperty("RepoTags")
    private String[] repoTags;

    @JsonProperty("RepoDigests")
    private String[] repoDigests;

    @JsonProperty("ImageConfig")
    private TrivyScanMetadataImageConfig imageConfig;

    public TrivyScanMetadata() {
    }

    public TrivyScanMetadataOS getOS() {
        return os;
    }

    public void setOS(TrivyScanMetadataOS os) {
        this.os = os;
    }

    public String getImageID() {
        return imageID;
    }

    public void setImageID(String imageID) {
        this.imageID = imageID;
    }

    public String[] getDiffIDs() {
        return diffIDs;
    }

    public void setDiffIDs(String[] diffIDs) {
        this.diffIDs = diffIDs;
    }

    public String[] getRepoTags() {
        return repoTags;
    }

    public void setRepoTags(String[] repoTags) {
        this.repoTags = repoTags;
    }

    public String[] getRepoDigests() {
        return repoDigests;
    }

    public void setRepoDigests(String[] repoDigests) {
        this.repoDigests = repoDigests;
    }

    public TrivyScanMetadataImageConfig getImageConfig() {
        return imageConfig;
    }

    public void setImageConfig(TrivyScanMetadataImageConfig imageConfig) {
        this.imageConfig = imageConfig;
    }
}