package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TrivyScanMetadataOS
{
    @JsonProperty("Family")
    private String family;

    @JsonProperty("Name")
    private String name;

    public TrivyScanMetadataOS() {
    }

    public String getFamily() {
        return family;
    }

    public void setFamily(String family) {
        this.family = family;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}