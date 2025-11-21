package com.fujitsu.edgewareroad.trivyutils;

import org.junit.jupiter.api.Test;

import com.fujitsu.edgewareroad.trivysummary.TrivySummary;

public class GenerateGraphTest {
    @Test
    public void testSimple()
    {
        TrivySummary worker = new TrivySummary();
        String svg = GenerateGraph.GetSVG(null, worker.getConfiguration());
        System.out.println(svg);
    }
}
