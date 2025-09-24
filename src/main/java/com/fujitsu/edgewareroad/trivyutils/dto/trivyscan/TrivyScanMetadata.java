package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
public class TrivyScanMetadata
{
    @JsonProperty("OS")
    private @Getter @Setter TrivyScanMetadataOS os;

    @JsonProperty("ImageID")
    private @Getter @Setter String imageID;

    @JsonProperty("DiffIDs")
    private @Getter @Setter String[] diffIDs;

    @JsonProperty("RepoTags")
    private @Getter @Setter String[] repoTags;

    @JsonProperty("RepoDigests")
    private @Getter @Setter String[] repoDigests;

    @JsonProperty("ImageConfig")
    private @Getter @Setter TrivyScanMetadataImageConfig imageConfig;
}