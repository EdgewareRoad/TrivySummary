package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrivyScanMetadataImageConfig
{
    private @Getter @Setter String architecture;
    private @Getter @Setter String container;
    private @Getter @Setter String created;
    @JsonProperty("docker_version")
    private @Getter @Setter String dockerVersion;
    private @Getter @Setter TrivyScanMetadataImageConfigHistoryItem[] history;
    @JsonProperty("os")
    private @Getter @Setter String os;
}