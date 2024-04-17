package com.fujitsu.edgewareroad.trivyutils;

import org.junit.jupiter.api.Test;

import com.fujitsu.edgewareroad.trivyutils.dto.VulnerabilityScorePriorityThresholds;

public class GenerateGraphTest {
    @Test
    public void testSimple()
    {
        String svg = GenerateGraph.GetSVG(null, new VulnerabilityScorePriorityThresholds(null, null));
        System.out.println(svg);
    }
}
