package com.nrs.http;

/**
 * Constants related to HTTP client.
 * 
 * @author <a href="mailto:nrs.freelance@gmail.com">Neelanand Sharma</a>
 *
 */
public interface HttpConfigConstants {
    public static final String HTTPS_PROXYHOST = "https.proxyHost";
    public static final String HTTPS_PROXYPORT = "https.proxyPort";
    public static final String HTTP_PROXYHOST = "http.proxyHost";
    public static final String HTTP_PROXYPORT = "http.proxyPort";
    public static final String NO_PROXY_HOSTS = "http.nonProxyHosts";
    public static final String HTTPS_PROXYUSER = "https.proxyUser";
    public static final String HTTPS_PROXYPASSWORD = "https.proxyPassword";
    public static final String HTTP_PROXYUSER = "http.proxyUser";
    public static final String HTTP_PROXYPASSWORD = "http.proxyPassword";
    public static final String SSL_PROTOCOL_VERSION = "sslProtocolVersion";

    public static final String BASIC = "Basic";
    public static final String AUTHORIZATION = "Authorization";
    public static final String UTF8 = "UTF-8";
    public static final String SSL = "SSL";
    public static final String TLS_V1 = "TLSv1";
    public static final String TLS_V1_2 = "TLSv1.2";
    public static final String HTTP = "http";
    public static final String HTTPS = "https";
    public static final String COOKIE = "Cookie";

    public static final String HEADER_KEY_AUTHORIZATION = "Authorization";
    public static final String HEADER_KEY_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_KEY_ACCEPT = "Accept";
    public static final String HEADER_KEY_CONTENT_CHARSET = "Content-Charset";

    public static final String HTTP_SOCKET_TIMEOUT = "http.socket.timeout";

    /**
     * Option that can be passed into setup that will indicate the client
     * certificate for client certificate authentication.
     */
    public static final String OPT_CLIENT_CERTIFICATE = "clientCertificate";

    /**
     * Option that can be passed into setup that will indicate the private key
     * for client certificate authentication.
     */
    public static final String OPT_CLIENT_KEY_SPEC = "clientKeySpec";

    /**
     * Option that can be passed into setup that will causes all certificates to
     * be trusted when using SSL. This defaults to false if not set.
     */
    public static final String OPT_TRUST_ALL_CERTS = "trustAllCerts";

    /**
     * Option that can be passed into setup that will causes no validations to
     * be performed on host names for certificates when using SSL. This defaults
     * to false if not set.
     */
    public static final String OPT_ALLOW_ALL_HOSTS = "allowAllHosts";

    /**
     * Option that may be passed into setup that will allow configuration of the
     * maximum number of connections per host
     */
    public static final String OPT_MAX_HOST_CONNECTIONS = "maxHostConnections";

    /**
     * Option that may be passed into setup that will allow configuration of the
     * maximum number of total connections
     */
    public static final String OPT_MAX_TOTAL_CONNECTIONS = "maxTotalConnections";

    /**
     * Optional that may be passed into setup that will specify the timeout in
     * seconds to close idle connections
     */
    public static final String OPT_CLOSE_IDLE_CONNECTIONS = "closeIdleConnections";

    /**
     * Optional that may be passed into setup that will specify to use STANDARD
     * cookie specs
     */
    public static final String OPT_HTTP_COOKIE_SPECS_STANDARD = "httpCookieSpecsStandard";
    
    /**
     * Optional that may be passed to set socket timeout
     */
    public static final String OPT_SOCKET_TIMEOUT = "http.socket.timeout";
    
    /**
     * Optional that may be passed to set connection timeout
     */
    public static final String OPT_CONNECTION_TIMEOUT = "http.connection.timeout";

    /**
     * All of the options accepted by setup.
     */
    public static final String[] OPTS = { OPT_CLOSE_IDLE_CONNECTIONS,
            OPT_TRUST_ALL_CERTS, OPT_MAX_HOST_CONNECTIONS,
            OPT_MAX_TOTAL_CONNECTIONS, OPT_HTTP_COOKIE_SPECS_STANDARD,
            OPT_CLIENT_CERTIFICATE, OPT_CLIENT_KEY_SPEC, OPT_ALLOW_ALL_HOSTS, OPT_SOCKET_TIMEOUT, OPT_CONNECTION_TIMEOUT };
}
