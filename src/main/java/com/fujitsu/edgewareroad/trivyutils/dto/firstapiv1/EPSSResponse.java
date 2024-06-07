package com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EPSSResponse {
    @JsonProperty
    private String status;
    @JsonProperty("status-code")
    private int statusCode;
    @JsonProperty
    private String version;
    @JsonProperty
    private String access;
    @JsonProperty
    private int total;
    @JsonProperty
    private int offset;
    @JsonProperty
    private int limit;
    @JsonProperty
    private EPSSData[] data;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    public EPSSData[] getData() {
        return data;
    }

    public void setData(EPSSData[] data) {
        this.data = data;
    }

}
