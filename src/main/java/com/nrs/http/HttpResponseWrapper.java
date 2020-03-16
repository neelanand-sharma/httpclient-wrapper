package com.nrs.http;

import java.util.Map;

/**
 * Wrapper for HTTP response. Encapsulates the response status code and the
 * response data.
 * 
 * @author <a href="mailto:nrs.freelance@gmail.com">Neelanand Sharma</a>
 *
 */
public class HttpResponseWrapper {

    private int status;
    private String response;
    private Map<String, String> headers;

    public HttpResponseWrapper(int status, String response) {
        this.status = status;
        this.response = response;
    }

    public HttpResponseWrapper(int status, String response,
            Map<String, String> responseHeaders) {
        this(status, response);
        this.headers = responseHeaders;
    }

    public int getStatus() {
        return status;
    }

    public String getResponse() {
        return response;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    @Override
    public String toString() {
        return "HttpResponseWrapper [status=" + status + ", response="
                + response + ", headers=" + headers + "]";
    }

}
