package com.nrs.http;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nrs.utils.Util;

/**
 * Wrapper for HTTP request which encapsulates different attributes responsible
 * for fulfillment of the request.
 * 
 * @author <a href="mailto:nrs.freelance@gmail.com">Neelanand Sharma</a>
 *
 */
public class HttpRequestWrapper {

    public enum Type {
        GET, POST, PUT, DELETE, PATCH;
    }

    private String url;
    private Map<String, String> headers = Collections.emptyMap();
    private Object payload;
    private Type type;
    private String[] allowedSuccessCodes = { "2**" };
    private Set<Integer> possibleHttpErrorCodes = Collections.emptySet();
    private Set<String> possibleHttpErrorMessages = Collections.emptySet();

    /**
     * Prepares a request wrapper object using supplied values.
     * <p>
     * {@code allowedSuccessCodes} defaults to 2**.
     * 
     * @param type
     *            {@link Type} of HTTP request
     * @param url
     *            request URL
     * @param headers
     *            request headers (Optional)
     * @param payload
     *            request payload (Optional)
     * @param allowedSuccessCodes
     *            array of allowed succcess HTTP codes. Support regex values,
     *            viz. 200, 4**, etc. (Optional)
     */
    public HttpRequestWrapper(Type type, String url,
            Map<String, String> headers, Object payload,
            String[] allowedSuccessCodes) {
        this(type, url, headers, payload, allowedSuccessCodes, null, null);
    }

    /**
     * Prepares a request wrapper object using supplied values.
     * <p>
     * Please note:
     * <ul>
     * <li>{@code allowedSuccessCodes} defaults to 2**.</li>
     * <li>{@code possibleHttpErrorCodes} represent error response codes which
     * need to explicitly validated in special scenarios. <i>This parameter is
     * optional</i>.</li>
     * <li>{@code possibleHttpErrorMessages} represents a set of error message
     * substring (case sensistive) to be compared within the response body to
     * flag exception cases. <i>This parameter is optional</i>.</li>
     * </ul>
     * 
     * @param type
     *            {@link Type} of HTTP request
     * @param url
     *            request URL
     * @param headers
     *            request headers (Optional)
     * @param payload
     *            request payload (Optional)
     * @param allowedSuccessCodes
     *            array of allowed succcess HTTP codes. Support regex values,
     *            viz. 200, 4**, etc. (Optional)
     * @param possibleHttpErrorCodes
     *            a {@code Set} of error codes to validate explicitly (Optional)
     * @param possibleHttpErrorMessages
     *            a {@code Set} of error message substrings to validate
     *            explicitly (Optional)
     */
    public HttpRequestWrapper(Type type, String url,
            Map<String, String> headers, Object payload,
            String[] allowedSuccessCodes, Set<Integer> possibleHttpErrorCodes,
            Set<String> possibleHttpErrorMessages) {
        this.url = url;
        this.payload = payload;
        this.type = type;

        if (!Util.isEmpty(headers)) {
            this.headers = headers;
        }

        if (!Util.isEmpty(allowedSuccessCodes)) {
            this.allowedSuccessCodes = allowedSuccessCodes;
        }

        if (!Util.isEmpty(possibleHttpErrorCodes)) {
            this.possibleHttpErrorCodes = possibleHttpErrorCodes;
        }

        if (!Util.isEmpty(possibleHttpErrorMessages)) {
            this.possibleHttpErrorMessages = possibleHttpErrorMessages;
        }
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }

    public Type getType() {
        return type;
    }

    public List<String> getAllowedSuccessCodes() {
        return Collections.unmodifiableList(Arrays.asList(allowedSuccessCodes));
    }

    public Set<Integer> getPossibleHttpErrorCodes() {
        return Collections.unmodifiableSet(possibleHttpErrorCodes);
    }

    public Set<String> getPossibleHttpErrorMessages() {
        return Collections.unmodifiableSet(possibleHttpErrorMessages);
    }

    @Override
    public String toString() {
        return "HttpRequestWrapper [url=" + url + ", headers=" + headers
                + ", payload=" + payload + ", type=" + type
                + ", allowedSuccessCodes="
                + Arrays.toString(allowedSuccessCodes)
                + ", possibleHttpErrorCodes=" + possibleHttpErrorCodes
                + ", possibleHttpErrorMessages=" + possibleHttpErrorMessages
                + "]";
    }

}
