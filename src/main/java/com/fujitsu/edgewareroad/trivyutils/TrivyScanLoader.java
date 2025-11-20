package com.fujitsu.edgewareroad.trivyutils;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.boot.json.JsonParseException;

import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;

public class TrivyScanLoader {
    public TrivyScanLoader()
    {
    }

    private static final ObjectMapper mapper = JsonMapper.builder()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, false)
        .configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true)
        .build();

    public static TrivyScan loadTrivyScan(InputStream isTrivyScanResults)
        throws JsonParseException, IOException
    {
        TrivyScan results = mapper.readValue(isTrivyScanResults, TrivyScan.class);
        return results;
    }
}
