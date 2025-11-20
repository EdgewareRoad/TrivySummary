package com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.VulnerabilitySeverity;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

public class PriorityModelTests {
    @Test
    public void testSampleEllipticalHappyPath() throws StreamReadException, DatabindException, IOException
    {
        ObjectMapper mapper = JsonMapper.builder()
            .configure(SerializationFeature.INDENT_OUTPUT, true)
            .build();

        try (InputStream input = this.getClass().getResourceAsStream("/samplePriorityModelElliptical.json")) {
            PriorityModel model = mapper.readValue(input, PriorityModel.class);
            System.out.println(mapper.writeValueAsString(model));

            assertEquals(PriorityModelType.ELLIPTICAL, model.getType());
            assertEquals(VulnerabilityPriority.CRITICAL, model.getPriority(VulnerabilitySeverity.LOW, 8.0, 0.7));
            assertEquals(VulnerabilityPriority.HIGH, model.getPriority(VulnerabilitySeverity.LOW, 8.0, 0.4));
            assertEquals(VulnerabilityPriority.MEDIUM, model.getPriority(VulnerabilitySeverity.LOW, 8.0, 0.1));
            assertEquals(VulnerabilityPriority.LOW, model.getPriority(VulnerabilitySeverity.CRITICAL, 8.0, 0.01));
        }
    }
}
