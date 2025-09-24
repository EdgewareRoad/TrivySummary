package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
public class TrivyScanMetadataOS
{
    @JsonProperty("Family")
    private @Getter @Setter String family;

    @JsonProperty("Name")
    private @Getter @Setter String name;
}