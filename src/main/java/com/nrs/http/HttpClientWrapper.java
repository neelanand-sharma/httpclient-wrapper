package com.nrs.http;

import java.io.Closeable;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.HostnameVerifier;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.nrs.http.exception.HttpException;
import com.nrs.utils.LoggingUtil;
import com.nrs.utils.Util;

/**
 * Generic facade implementation for sending HTTP requests and retrieving the
 * response.
 * 
 * @see HttpConfigConstants
 * @see HttpRequestWrapper
 * @see HttpResponseWrapper
 * @author <a href="mailto:nrs.freelance@gmail.com">Neelanand Sharma</a>
 *
 */
public class HttpClientWrapper implements Closeable {
    private static final Class<HttpClientWrapper> CLASS = HttpClientWrapper.class;

    private static List<String> noProxyHostList = null;

    private HttpClientContext httpClientContext = HttpClientContext.create();
    private HttpClientBuilder httpClientBuilder = HttpClients.custom();
    private CloseableHttpClient httpClient = null;

    private HttpClientWrapper() {
    }

    /**
     * Configures and returns an instance of {@code HttpClientWrapper} using the
     * supplied parameters.
     * 
     * @param host
     *            target host name / IP
     * @param port
     *            target host port for HTTP / HTTPS communication
     * @param configureHttps
     *            if {@code true} HTTPS related settings will be configured if
     *            the same are provided in {@code options}
     * @param username
     *            user for authentication <i>(Optional)</i>
     * @param password
     *            authentication password <i>(Cannot be optional if
     *            {@code username} value is provided)</i>
     * @param options
     *            HTTP options, if any, viz. HTTPS protocol, HTTPS post, client
     *            certificate and key <i>(Refer
     *            {@link HttpConfigConstants}.{@code OPT_*} for valid
     *            options)</i>
     * @return an instance of {@code HttpClientWrapper}
     * @throws HttpException
     */
    public static HttpClientWrapper configure(String host, Integer port,
            boolean configureHttps, String username, String password,
            Map<String, Object> options) throws HttpException {
        LoggingUtil.entering(CLASS, "configure",
                new Object[] { host, port, configureHttps,
                        (Util.isEmpty(options)) ? null : options.keySet() });
        HttpClientWrapper clientWrapper = new HttpClientWrapper();
        if (null == port || port < 0) {
            port = (configureHttps) ? 443 : 80;
        }
        clientWrapper.setAuthentication(host, port, username, password);
        try {
            clientWrapper.checkProxy(host);
        } catch (MalformedURLException e) {
            LoggingUtil.error(CLASS,
                    "Error while configuring proxy settings: {0}",
                    new Object[] { e.getMessage() });
            throw new HttpException(e);
        }
        if (configureHttps) {
            try {
                clientWrapper.setUpHttpsProtocol(options);
            } catch (KeyManagementException | UnrecoverableKeyException
                    | NoSuchAlgorithmException | KeyStoreException
                    | CertificateException | IOException e) {
                LoggingUtil.error(CLASS,
                        "Error while configuring HTTPS properties: {0}",
                        new Object[] { e.getMessage() });
                throw new HttpException(e);
            }
        }

        clientWrapper.httpClient = clientWrapper.httpClientBuilder.build();
        LoggingUtil.exiting(CLASS, "configure",
                new Object[] { host, port, configureHttps,
                        (Util.isEmpty(options)) ? null : options.keySet() },
                "Http client configured!");
        return clientWrapper;
    }

    /**
     * Executes the underlying HTTP request depending upon the values of
     * {@code request} object.
     * 
     * @param request
     *            {@link HttpRequestWrapper} object containing request
     *            information
     * @return {@link HttpResponseWrapper} object containing the status code and
     *         the response string
     * @throws HttpException
     */
    public HttpResponseWrapper execute(HttpRequestWrapper request)
            throws HttpException {
        LoggingUtil.entering(CLASS, "execute",
                new Object[] { request.getUrl() });
        try {
            HttpRequestBase httpRequest;
            switch (request.getType()) {
                case GET:
                    httpRequest = new HttpGet(request.getUrl());
                    break;

                case POST:
                    httpRequest = new HttpPost(request.getUrl());
                    break;

                case PUT:
                    httpRequest = new HttpPut(request.getUrl());
                    break;

                case PATCH:
                    httpRequest = new HttpPatch(request.getUrl());
                    break;

                case DELETE:
                    httpRequest = new HttpDeleteWithBody(request.getUrl());
                    break;

                default:
                    throw new HttpException(
                            "Unsupported request type: " + request.getType());
            }

            if (httpRequest instanceof HttpEntityEnclosingRequestBase) {
                Object payload = request.getPayload();
                if (null != payload) {
                    if (payload instanceof String) {
                        ((HttpEntityEnclosingRequestBase) httpRequest)
                                .setEntity(new StringEntity(
                                        payload.toString().trim(), "UTF-8"));
                    } else if (payload instanceof Map
                            && !Util.isEmpty((Map) payload)) {
                        List<BasicNameValuePair> parametersBody = new ArrayList<>();
                        ((Map<String, Object>) payload).entrySet().stream()
                                .forEach(entry -> parametersBody.add(
                                        new BasicNameValuePair(entry.getKey(),
                                                String.valueOf(
                                                        entry.getValue()))));

                        String contentCharset = request.getHeaders().get(
                                HttpConfigConstants.HEADER_KEY_CONTENT_CHARSET);
                        contentCharset = Util.isEmpty(contentCharset)
                                ? HttpConfigConstants.UTF8
                                : contentCharset;

                        ((HttpEntityEnclosingRequestBase) httpRequest)
                                .setEntity(new UrlEncodedFormEntity(
                                        parametersBody, contentCharset));
                    }
                }
            }
            httpRequest.setHeaders(prepareHeaders(request.getHeaders()));
            setupCookies(httpRequest);
            LoggingUtil.debug(CLASS, "Attempting to handle response for failure"
                    + " and returning the outcome...", null);
            HttpResponseWrapper response = handleFailedRequest(request,
                    sendRequest(httpRequest));
            LoggingUtil.exiting(CLASS, "execute",
                    new Object[] { request.getUrl() }, MessageFormat.format(
                            "Response status {0}", response.getStatus()));
            return response;
        } catch (Exception e) {
            if (!(e instanceof HttpException)) {
                throw new HttpException(request.getUrl(), e);
            }
            throw (HttpException) e;
        }
    }

    /**
     * Sends the HTTP request and returns an object of
     * {@code HttpResponseWrapper} containing the response.
     * 
     * @param httpRequest
     *            {@code HttpRequestBase} for execution
     * @return {@code HttpResponseWrapper} object containing the status code and
     *         the response string
     * @throws Exception
     */
    private HttpResponseWrapper sendRequest(HttpRequestBase httpRequest)
            throws Exception {
        LoggingUtil.entering(CLASS, "sendRequest", null);
        String responseEntity = null;
        int statusCode = 404;
        Map<String, String> responseHeaders = new HashMap<>();
        try (CloseableHttpResponse response = httpClient.execute(httpRequest,
                httpClientContext)) {
            HttpEntity entity = response.getEntity();
            Arrays.stream(response.getAllHeaders())
                    .forEach(head -> responseHeaders.put(head.getName(),
                            head.getValue()));
            responseEntity = (null != entity)
                    ? EntityUtils.toString(entity, HttpConfigConstants.UTF8)
                    : null;
            statusCode = response.getStatusLine().getStatusCode();
            EntityUtils.consume(entity);
        }
        LoggingUtil.exiting(CLASS, "sendRequest", null,
                MessageFormat.format("Response status {0}", statusCode));
        return new HttpResponseWrapper(statusCode, responseEntity,
                responseHeaders);
    }

    /**
     * Gets a list of {@code Cookie}s in current HTTP context.
     * 
     * @return {@code List} of {@code Cookie}s if any, otherwise an empty list
     */
    public List<Cookie> getCookies() {
        LoggingUtil.entering(CLASS, "getCookies", null);
        List<Cookie> cookies = Collections.emptyList();
        if (httpClientContext.getCookieStore() != null && !Util
                .isEmpty(httpClientContext.getCookieStore().getCookies())) {
            cookies = httpClientContext.getCookieStore().getCookies().stream()
                    .filter(cookie -> null != cookie)
                    .collect(Collectors.toList());
        }
        LoggingUtil.exiting(CLASS, "getCookies", null,
                MessageFormat.format("Cookie size {0}", cookies.size()));
        return cookies;
    }

    /**
     * Adds supplied {@code cookies} to the current HTTP context.
     * 
     * @param cookies
     *            {@code List} of {@code Cookie} objects
     */
    public void addCookies(List<Cookie> cookies) {
        LoggingUtil.entering(CLASS, "addCookies", null);
        BasicCookieStore basicCookieStore = new BasicCookieStore();
        if (!Util.isEmpty(cookies)) {
            cookies.stream().filter(cookie -> null != cookie)
                    .forEach(cookie -> basicCookieStore.addCookie(cookie));
        }
        httpClientContext.setCookieStore(basicCookieStore);
        LoggingUtil.exiting(CLASS, "addCookies", null, null);
    }

    /**
     * Handles the response to check if the response status is in accordance to
     * the <i>allowed success codes</i> of the {@code request}. If not,
     * {@code HttpException} is thrown.
     * <p>
     * The default set of allowed status code is 2**.
     * 
     * @param request
     *            {@code HttpRequestWrapper} object containing the allowed
     *            success codes
     * @param response
     *            {@code HttpResponseWrapper} object containing the response
     *            status
     * @return {@code HttpResponseWrapper}
     * @throws HttpException
     *             if the response status is not part of the allowed success
     *             codes
     */
    private static HttpResponseWrapper handleFailedRequest(
            HttpRequestWrapper request, HttpResponseWrapper response)
            throws HttpException {
        LoggingUtil.entering(CLASS, "handleFailedRequest", null);
        boolean success = false;
        int responseStatus = response.getStatus();
        for (String successCode : request.getAllowedSuccessCodes()) {
            // The status can be 204 or 2* or 20*
            int starIndex = successCode.indexOf("*");
            if (starIndex != -1) {
                String startingSequence = successCode.substring(0, starIndex);
                if (String.valueOf(responseStatus)
                        .startsWith(startingSequence)) {
                    success = true;
                    break;
                }
            } else if (String.valueOf(responseStatus).equals(successCode)) {
                success = true;
                break;
            }
        }

        if (!success) {
            throw new HttpException(request.getUrl(), response.getStatus(),
                    response.getResponse(), null);
        } else if (success
                && (!Util.isEmpty(request.getPossibleHttpErrorCodes()) || !Util
                        .isEmpty(request.getPossibleHttpErrorMessages()))) {
            Set<Integer> errorCodes = request.getPossibleHttpErrorCodes();
            if (!Util.isEmpty(errorCodes)
                    && errorCodes.contains(responseStatus)) {
                LoggingUtil.debug(CLASS,
                        "Status code \"{0}\" encountered "
                                + "in error code list: {1}",
                        new Object[] { responseStatus, errorCodes });
                throw new HttpException(request.getUrl(), responseStatus,
                        response.getResponse(), null);
            }
            Set<String> errorMessages = request.getPossibleHttpErrorMessages();
            if (!Util.isEmpty(errorMessages)) {
                String body = response.getResponse();
                for (String errorMessage : errorMessages) {
                    if (body.contains(errorMessage)) {
                        LoggingUtil.debug(CLASS,
                                "Error message \"{0}\" found in body.",
                                new Object[] { errorMessage });
                        throw new HttpException(request.getUrl(),
                                responseStatus, response.getResponse(), null);
                    }
                }
            }
        }

        LoggingUtil.exiting(CLASS, "handleFailedRequest", null, MessageFormat
                .format("Response status {0}", response.getStatus()));
        return response;
    }

    /**
     * Sets the server authentication credentials.
     * 
     * @param host
     *            target host name / IP
     * @param port
     *            target host port
     * @param username
     *            user for authentication <i>(Optional)</i>
     * @param password
     *            authentication password <i>(Cannot be optional if
     *            {@code username} value is provided)</i>
     */
    private void setAuthentication(String host, int port, String username,
            String password) {
        LoggingUtil.entering(CLASS, "setAuthentication", new Object[] { host,
                port, username, Util.isEmpty(password) ? null : "*****" });
        if (!Util.isEmpty(username) && !Util.isEmpty(password)) {
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(new AuthScope(host, port),
                    new UsernamePasswordCredentials(username, password));
            httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
        }
        LoggingUtil
                .exiting(CLASS, "setAuthentication",
                        new Object[] { host, port, username,
                                Util.isEmpty(password) ? null : "*****" },
                        null);
    }

    private void setUpHttpsProtocol(Map<String, Object> options)
            throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, UnrecoverableKeyException,
            CertificateException, IOException {
        LoggingUtil.entering(CLASS, "setUpHttpsProtocol", null);
        SSLContextBuilder sslContextBuilder = SSLContexts.custom();
        prepareKeyManager(sslContextBuilder, options);

        boolean trustAllCerts = (!Util.isEmpty(options))
                ? Util.otob(
                        options.get(HttpConfigConstants.OPT_TRUST_ALL_CERTS))
                : false;
        LoggingUtil.debug(CLASS, "Trust all certificates = {0}",
                new Object[] { trustAllCerts });
        // Set trust strategy to trust all certificates
        if (trustAllCerts) {
            sslContextBuilder.loadTrustMaterial(null,
                    TrustSelfSignedStrategy.INSTANCE);
        }

        boolean allowAllHosts = (!Util.isEmpty(options))
                ? Util.otob(
                        options.get(HttpConfigConstants.OPT_ALLOW_ALL_HOSTS))
                : false;
        LoggingUtil.debug(CLASS, "Allow all hosts = {0}",
                new Object[] { allowAllHosts });
        HostnameVerifier verifier = (!allowAllHosts)
                ? new DefaultHostnameVerifier()
                : new NoopHostnameVerifier();
        SSLConnectionSocketFactory secureFactory = new SSLConnectionSocketFactory(
                sslContextBuilder.build(), null, null, verifier);

        Registry registry = RegistryBuilder.create()
                .register(HttpConfigConstants.HTTP,
                        PlainConnectionSocketFactory.getSocketFactory())
                .register(HttpConfigConstants.HTTPS, secureFactory).build();
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(
                registry);
        cm.setMaxTotal(200);
        cm.setDefaultMaxPerRoute(20);
        httpClientBuilder.setConnectionManager(cm);

        LoggingUtil.exiting(CLASS, "setUpHttpsProtocol", null, null);
    }

    /**
     * Set proxy connectivity parameters by checking system-level HTTPS / HTTP
     * proxy settings.
     * <p>
     * Following system variables are checked to set proxy:
     * <ul>
     * <li><b>For HTTPS proxy</b>
     * <ul>
     * <li><i>https.proxyHost</i> - HTTPS proxy host</li>
     * <li><i>https.proxyPort</i> - HTTPS proxy port</li>
     * <li><i>https.proxyUser</i> - HTTPS proxy user</li>
     * <li><i>https.proxyPassword</i> - HTTPS proxy password</li>
     * </ul>
     * </li>
     * <li><b>For HTTP proxy</b>
     * <ul>
     * <li><i>http.proxyHost</i> - HTTP proxy host</li>
     * <li><i>http.proxyPort</i> - HTTP proxy port</li>
     * <li><i>http.proxyUser</i> - HTTP proxy user</li>
     * <li><i>http.proxyPassword</i> - HTTP proxy password</li>
     * </ul>
     * </li>
     * </ul>
     */
    protected static void setProxy(HttpClientBuilder httpBuilder) {
        LoggingUtil.entering(CLASS, "setProxy", null);
        String httpsHost = System
                .getProperty(HttpConfigConstants.HTTPS_PROXYHOST);
        String httpsPort = System
                .getProperty(HttpConfigConstants.HTTPS_PROXYPORT);
        String httphost = System
                .getProperty(HttpConfigConstants.HTTP_PROXYHOST);
        String httpPort = System
                .getProperty(HttpConfigConstants.HTTP_PROXYPORT);

        HttpHost proxy = null;
        String proxyUser = null;
        String proxyPassword = null;
        if (!Util.isEmpty(httpsHost) && !Util.isEmpty(httpsPort)) {
            proxyUser = System.getProperty(HttpConfigConstants.HTTPS_PROXYUSER);
            proxyPassword = System
                    .getProperty(HttpConfigConstants.HTTPS_PROXYPASSWORD);
            proxy = new HttpHost(httpsHost, Integer.parseInt(httpsPort));
        } else if (!Util.isEmpty(httphost) && !Util.isEmpty(httpPort)) {
            proxyUser = System.getProperty(HttpConfigConstants.HTTP_PROXYUSER);
            proxyPassword = System
                    .getProperty(HttpConfigConstants.HTTP_PROXYPASSWORD);
            proxy = new HttpHost(httphost, Integer.parseInt(httpPort));
        }

        if (null != proxy) {
            httpBuilder.setProxy(proxy);

            if (!Util.isEmpty(proxyUser) && !Util.isEmpty(proxyPassword)) {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                        new AuthScope(proxy.getHostName(), proxy.getPort()),
                        new UsernamePasswordCredentials(proxyUser,
                                proxyPassword));
                httpBuilder.setDefaultCredentialsProvider(credsProvider);
            }
        }
        LoggingUtil.exiting(CLASS, "setProxy", null, null);
    }

    /**
     * Checks for proxy configurations and sets the proxy host if present.
     * 
     * @param request
     *            {@code HttpRequestWrapper} object for which proxy needs to be
     *            checked
     * @throws MalformedURLException
     */
    private void checkProxy(String host) throws MalformedURLException {
        LoggingUtil.entering(CLASS, "checkProxy", null);
        if (noProxyHostList == null) {
            if (System
                    .getProperty(HttpConfigConstants.NO_PROXY_HOSTS) != null) {
                String noProxyHost = System
                        .getProperty(HttpConfigConstants.NO_PROXY_HOSTS);
                if (noProxyHost != null && noProxyHost.length() > 0) {
                    String[] noProxyHostArr = noProxyHost
                            .split(Pattern.quote("|"));
                    noProxyHostList = Collections
                            .synchronizedList(new ArrayList<String>(
                                    Arrays.asList(noProxyHostArr)));
                }
            }
        }

        if (Util.isEmpty(noProxyHostList)
                || checkNoProxyHost(noProxyHostList, host)) {
            setProxy(httpClientBuilder);
        }
        LoggingUtil.exiting(CLASS, "checkProxy", null, null);
    }

    /**
     * Check whether the host exists in no proxy hosts configuration.
     * 
     * @param noProxyHostList
     * @param host
     * @return if host exists in no proxy hosts configuration
     */
    private static boolean checkNoProxyHost(List<String> noProxyHosts,
            String hostToCheck) {
        LoggingUtil.entering(CLASS, "checkNoProxyHost", null);
        Boolean noProxyHost = Boolean.TRUE;
        if (!Util.isEmpty(noProxyHosts)) {
            for (String proxyHost : noProxyHosts) {
                if (proxyHost.startsWith("*")) {
                    proxyHost = "[\\w \\. -]" + proxyHost;
                }
                Matcher matcher = Pattern.compile(proxyHost)
                        .matcher(hostToCheck);
                if (matcher.matches()) {
                    noProxyHost = false;
                }
            }
        }
        LoggingUtil.exiting(CLASS, "checkNoProxyHost", null, noProxyHost);
        return noProxyHost;
    }

    /**
     * Prepares headers for consumption by the HttpClient using the supplied
     * {@code headerMap}.
     * 
     * @param headerMap
     *            {@code Map} containing header key-value pairs
     * @return {@code array} of {@code Header} objects
     */
    private static Header[] prepareHeaders(Map<String, String> headerMap) {
        LoggingUtil.entering(CLASS, "prepareHeaders", null);
        Header[] headers = new Header[] {};
        if (!Util.isEmpty(headerMap)) {
            List<Header> headerList = new ArrayList<>(headerMap.size());
            for (Map.Entry<String, String> header : headerMap.entrySet()) {
                if (!Util.isEmpty(header.getValue())) {
                    headerList.add(new BasicHeader(header.getKey(),
                            header.getValue()));
                }
            }
            headers = headerList.toArray(headers);
        }
        LoggingUtil.exiting(CLASS, "prepareHeaders", null, headerMap.keySet());
        return headers;
    }

    /**
     * Prepares {@code sslContextBuilder} to support client certificate
     * authentication for SSL, if the client certificate information is provided
     * via {@code options}.
     * <p>
     * Required option keys are:
     * <ul>
     * <li>HttpConfigConstants.OPT_CLIENT_CERTIFICATE - Client certificate</li>
     * <li>HttpConfigConstants.OPT_CLIENT_KEY_SPEC - Client certificate key</li>
     * </ul>
     * 
     * @param sslContextBuilder
     * @param options
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    private static void prepareKeyManager(
            final SSLContextBuilder sslContextBuilder,
            final Map<String, Object> options)
            throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException {
        LoggingUtil.entering(CLASS, "prepareKeyManager", null);
        if (Util.isEmpty(options)) {
            return;
        }

        String publicKey = (String) options
                .get(HttpConfigConstants.OPT_CLIENT_CERTIFICATE);
        String keySpec = (String) options
                .get(HttpConfigConstants.OPT_CLIENT_KEY_SPEC);

        boolean certAbsent = Util.isEmpty(publicKey);
        boolean keyAbsent = Util.isEmpty(keySpec);
        if (certAbsent && !keyAbsent) {
            throw new IllegalArgumentException(
                    "Client certificate cannot be empty.");
        } else if (!certAbsent && keyAbsent) {
            throw new IllegalArgumentException(
                    "Certificate key cannot be empty.");
        } else if (certAbsent && keyAbsent) {
            LoggingUtil.debug(CLASS, "Client certificate or private key "
                    + "is empty. Skipping client " + "certificate loading.",
                    null);
            return;
        }

        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null, null);

        // parse private key
        PEMParser keyReader = new PEMParser(new StringReader(keySpec));
        PEMKeyPair keyPair = (PEMKeyPair) keyReader.readObject();
        keyReader.close();
        if (null == keyPair) {
            throw new IllegalArgumentException(
                    "Unable to process the certificate private key.");
        }
        PrivateKeyInfo privateKeySpec = keyPair.getPrivateKeyInfo();
        PrivateKey privateKey = (new JcaPEMKeyConverter())
                .getPrivateKey(privateKeySpec);

        // Generate certificate chain
        PEMParser certReader = new PEMParser(new StringReader(publicKey));
        X509CertificateHolder certHolder = (X509CertificateHolder) certReader
                .readObject();
        certReader.close();
        if (null == certHolder) {
            throw new IllegalArgumentException(
                    "Unable to process the certificate.");
        }
        Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(certHolder);
        Certificate[] chain = { cert };

        SecureRandom secureRandom = new SecureRandom();
        int secureInt = secureRandom.nextInt(32);
        while (secureInt == 0) {
            secureInt = secureRandom.nextInt(32);
        }
        char[] keyStorePassword = RandomStringUtils
                .randomAlphanumeric(secureInt).toCharArray();
        clientKeyStore.setKeyEntry("TestEntry", privateKey, keyStorePassword,
                chain);

        sslContextBuilder.loadKeyMaterial(clientKeyStore, keyStorePassword);
        LoggingUtil.exiting(CLASS, "prepareKeyManager", null,
                "Client Certificate Loaded!");
    }

    /**
     * Adds cookie information from earlier request in current HTTP context.
     * 
     * @param httpRequest
     */
    private void setupCookies(HttpRequestBase httpRequest) {
        LoggingUtil.entering(CLASS, "setupCookies", null);
        List<Cookie> cookies = getCookies();
        if (!cookies.isEmpty()) {
            RequestConfig localConfig = RequestConfig.custom()
                    .setCookieSpec(CookieSpecs.DEFAULT).build();
            httpRequest.setConfig(localConfig);
            cookies.stream().filter(cookie -> null != cookie)
                    .forEach(cookie -> {
                        httpRequest.setHeader(HttpConfigConstants.COOKIE,
                                cookie.toString());
                    });
        }
        LoggingUtil.exiting(CLASS, "setupCookies", null, null);
    }

    @Override
    public void close() throws IOException {
        LoggingUtil.entering(CLASS, "close", null);
        if (null != httpClient) {
            httpClient.close();
        }
        LoggingUtil.exiting(CLASS, "close", null, null);
    }

    /**
     * Parses the {@code payload} object and returns an equivalent JSON
     * representation.
     *
     * @param payload
     *            object to convert into JSON
     * @return JON representation of {@code payload}
     * @throws Exception
     */
    // public static String preparePayloadJson(Object payload) throws Exception
    // {
    // return (null == payload) ? null
    // : (!(payload instanceof String)) ? JsonUtil.render(payload)
    // : String.valueOf(payload);
    // }

    /**
     * Custom HTTP DELETE request implementation for web service endpoints.
     * <p>
     * Some endpoints need body to be supplied in the DELETE request and hence
     * {@link HttpDelete} cannot be used here.
     * 
     */
    class HttpDeleteWithBody extends HttpEntityEnclosingRequestBase {
        private static final String METHOD_NAME = "DELETE";

        HttpDeleteWithBody() {
            super();
        }

        HttpDeleteWithBody(final String uri) {
            super();
            setURI(URI.create(uri));
        }

        HttpDeleteWithBody(final URI uri) {
            super();
            setURI(uri);
        }

        @Override
        public String getMethod() {
            return METHOD_NAME;
        }

    }

}
