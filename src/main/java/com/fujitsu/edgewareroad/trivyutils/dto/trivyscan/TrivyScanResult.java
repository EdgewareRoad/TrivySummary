package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
public class TrivyScanResult
{
    @JsonProperty("Target")
    private @Getter @Setter String target;

    @JsonProperty("Class")
    private @Getter @Setter String targetClass;

    @JsonProperty("Type")
    private @Getter @Setter String targetType;

    @JsonProperty("Vulnerabilities")
    private @Getter @Setter TrivyScanPackageVulnerabilities vulnerabilities = new TrivyScanPackageVulnerabilities();
}