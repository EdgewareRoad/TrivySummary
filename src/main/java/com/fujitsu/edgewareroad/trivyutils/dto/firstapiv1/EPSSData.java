package com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

public class EPSSData {
    @JsonProperty("cve")
    private @Getter @Setter String vulnerabilityID;
    @JsonProperty("epss")
    private @Getter @Setter Double epssScore;
    @JsonProperty
    private @Getter @Setter Double percentile;
    @JsonProperty
    private @Getter @Setter Date date;
}