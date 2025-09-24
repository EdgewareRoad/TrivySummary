package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
public class TrivyScanMetadataImageConfigHistoryItem
{
    @JsonProperty("created")
    private @Getter @Setter Date created;

    @JsonProperty("created_by")
    private @Getter @Setter String createdBy;

    @JsonProperty("empty_layer")
    private @Getter @Setter Boolean empty_layer;
}