package com.nrs.http.exception;

/**
 * Exception providing details of HTTP request execution.
 * 
 * @author <a href="mailto:nrs.freelance@gmail.com">Neelanand Sharma</a>
 *
 */
public class HttpException extends Exception {

    private static final long serialVersionUID = -2075411694242224061L;

    private String url;
    private int errorCode;

    public HttpException(String url) {
        this.url = url;
    }

    public HttpException(Throwable cause) {
        super(cause);
    }

    public HttpException(String url, Throwable cause) {
        super(cause);
        this.url = url;
    }

    public HttpException(String url, String message) {
        super(message);
        this.url = url;
    }

    public HttpException(String url, String message, Throwable cause) {
        super(message, cause);
        this.url = url;
    }

    public HttpException(String url, int errorCode, String message,
            Throwable cause) {
        this(url, message, cause);
        this.errorCode = errorCode;
    }

    public String getUrl() {
        return url;
    }

    public int getErrorCode() {
        return errorCode;
    }

    @Override
    public String toString() {
        return "HttpException [url=" + url + ", errorCode=" + errorCode
                + ", getMessage()=" + getMessage() + ", getCause()="
                + getCause() + "]";
    }
}
