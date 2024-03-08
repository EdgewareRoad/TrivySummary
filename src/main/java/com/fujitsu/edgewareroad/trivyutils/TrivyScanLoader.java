package com.fujitsu.edgewareroad.trivyutils;

import java.io.IOException;
import java.io.InputStream;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;

public class TrivyScanLoader {
    public TrivyScanLoader()
    {

    }

    public static TrivyScan loadTrivyScan(InputStream isTrivyScanResults)
        throws JsonParseException, JsonMappingException, IOException
    {
        ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, false)
            .configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true);
        TrivyScan results = mapper.readValue(isTrivyScanResults, TrivyScan.class);
        return results;
    }
}
