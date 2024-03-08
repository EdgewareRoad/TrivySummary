package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TrivyScanMetadataImageConfigHistoryItem
{
    @JsonProperty("created")
    private Date created;

    @JsonProperty("created_by")
    private String createdBy;

    @JsonProperty("empty_layer")
    private Boolean empty_layer;

    
    public TrivyScanMetadataImageConfigHistoryItem() {
    }
    public Date getCreated() {
        return created;
    }
    public void setCreated(Date created) {
        this.created = created;
    }
    public String getCreatedBy() {
        return createdBy;
    }
    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }
    public Boolean getEmpty_layer() {
        return empty_layer;
    }
    public void setEmpty_layer(Boolean empty_layer) {
        this.empty_layer = empty_layer;
    }
}