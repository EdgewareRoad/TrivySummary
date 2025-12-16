package com.fujitsu.edgewareroad.trivyutils;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HttpClientWithRetries {

    public class HttpClientRequestExceededRetriesException extends Exception {
        public HttpClientRequestExceededRetriesException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private HttpClient client;
    private int maxRetries;
    private long delayInMillis;

    public HttpClientWithRetries(HttpClient client, int maxRetries, java.time.Duration delay) {
        this.client = client;
        this.maxRetries = maxRetries;
        this.delayInMillis = delay.toMillis();
    }

    public HttpResponse<String> sendWithRetries(HttpRequest request) throws HttpClientRequestExceededRetriesException {
        int attempts = 0;

        while (true) {
            try {
                // Attempt to send the request
                return client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (IOException | InterruptedException ex) {
                attempts++;
                if (attempts > maxRetries) {
                    throw new HttpClientRequestExceededRetriesException("Maximum retry attempts reached.", ex);
                }
                System.out.println("Request failed, retrying... (" + attempts + "/" + maxRetries + ")");
                try {
                    Thread.sleep(delayInMillis);
                } catch (InterruptedException ie) {
                    // Swallow the interruption during sleep
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

}