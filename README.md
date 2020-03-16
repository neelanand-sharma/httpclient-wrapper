## Generic HTTP Client Framework
The Generic HTTP Client Framework provides simple interface for HTTP communication using wrapper implementations over Apache HTTP Client API.

The motivations for development of the generic HTTP client framework are listed below:
1. Making available a simple API facade for HTTP communication capabilities.
2. Supporting all common scenarios under one hood viz. proxy configuration, cookie support, client certificate authentication etc.
3. Fixing a clear boundary between the HTTP communication layer and the consumer.
4. More specific exception mechanism which involves around the HTTP operations.

### Prerequisite
This project depends upon the [Common Utilities](https://github.com/neelanand-sharma/common-utilities) project.

## Features
1. Well defined functional boundary between the HTTP request-response flow.
2. Abstraction to the underlying third party library being used for HTTP communication. Single point of impact due to upgrades.
3. Standardized mechanism for handling HTTP communication resulting in uniform coding practice.
4. Dedicated exceptions for upper layers to handle the business flow.
5. Support for client certificate authentication, proxy configuration, cookies.  

## The Key Elements
This section provides the detailed information of various classes and their uptake for making the HTTP framework work end-to-end.

#### [`HttpClientWrapper.java`](src/main/java/com/nrs/http/HttpClientWrapper.java)
`HttpClientWrapper` implements the `Closable` interface and acts as a wrapper around the Apache HTTP Client library.

#### Creation of the HTTP client wrapper instance
An instance of the same can be obtained via the `configure()` method by supplying the available arguments which are explained as under:
1. `host`: Target host's name / IP
2. `port`: Target host's port for HTTP / HTTPS communication
3. `configureHttps`: Configures HTTPS related settings if the same are provided via *options* parameter
4. `username`: User for authentication **(Optional)**
5. `password`: Authentication password __(Cannot be optional if *username* value is provided)__
6. `options`: HTTP options, if any, viz. HTTPS protocol, HTTPS post, client certificate and key (Refer [`HttpConfigConstants.java`](src/main/java/com/nrs/http/HttpConfigConstants.java) for valid options indicated by prefix **OPT_**)</i>

#### Execution of HTTP request using the HTTP client wrapper instance
HTTP requests can be executed by invoking `execute()` method and supplying a `HttpRequestWrapper` object which holds request information.

#### Sample code
```
HttpRequestWrapper request = new HttpRequestWrapper(...);
HttpResponseWrapper response;
try (HttpClientWrapper client = HttpClientWrapper.configure(
        url.getHost(), url.getPort(),
        HttpConfigConstants.HTTPS.equals(url.getProtocol()), username, password,
        httpOptions)) {
    response = client.execute(request);
} catch (HttpException | IOException e) {
}
```

#### [`HttpRequestWrapper.java`](src/main/java/com/nrs/http/HttpRequestConfig.java)
`HttpRequestWrapper` is a composite class which encapsulates the request information. An instance of `HttpRequestWrapper` can be constructed by providing below details:
1. `type`: Type of request method i.e. GET, PUT, POST, etc. defined in enum `HttpRequestWrapper.Type`.
2. `url`: Request URL.
3. `headers`: Map of header names and corresponding values. **(Optional)**
4. `payload`: Request body. Supports `Map` for form data and `String` for raw body.
5. `allowedSuccessCodes`: `Array` of success response codes. If not provided, defaults to __2**__ wild card match. **(Optional)** 
6. `possibleHttpErrorCodes`: `Set` of HTTP error response codes to explicitly indicate an error condition even though the request is a success. **(Optional)**
7. `possibleHttpErrorMessages`: `Set` of sub-strings to explicitly check for in the response body to indicate an error condition even though the request is a success. **(Optional)**

#### [`HttpResponseWrapper.java`](src/main/java/com/nrs/http/HttpResponseConfig.java)
`HttpResponseWrapper` is a simple class which provides access to the response of the executed HTTP request. developers can access the response body, status code and the headers, if any, by respective getter methods.
