package com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EPSSResponse {
    @JsonProperty
    private @Getter @Setter String status;
    @JsonProperty("status-code")
    private @Getter @Setter int statusCode;
    @JsonProperty
    private @Getter @Setter String version;
    @JsonProperty
    private @Getter @Setter String access;
    @JsonProperty
    private @Getter @Setter int total;
    @JsonProperty
    private @Getter @Setter int offset;
    @JsonProperty
    private @Getter @Setter int limit;
    @JsonProperty
    private @Getter @Setter EPSSData[] data;
}
