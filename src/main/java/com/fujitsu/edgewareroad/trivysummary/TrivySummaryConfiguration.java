package com.fujitsu.edgewareroad.trivysummary;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:application.properties")
public class TrivySummaryConfiguration {
    @Value("${trivysummary.version}")
    private String version;

    public String getVersion() {
        return version;
    }
}
