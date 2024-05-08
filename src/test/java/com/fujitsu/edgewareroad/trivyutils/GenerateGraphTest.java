package com.fujitsu.edgewareroad.trivyutils;

import org.junit.jupiter.api.Test;

import com.fujitsu.edgewareroad.trivysummary.TrivySummary;

public class GenerateGraphTest {
    @Test
    public void testSimple()
    {
        String svg = GenerateGraph.GetSVG(null, new TrivySummary.Configuration());
        System.out.println(svg);
    }
}
