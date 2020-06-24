import ballerina/cache;
import ballerina/encoding;
import ballerina/http;
import ballerina/log;
import ballerina/runtime;
import ballerina/stringutils;

# Object for Proxy endpoint.
#
# + idsClient - HTTP client endpoint for Identity Server
# + gatewayConfig - Gateway configuration object
public type Client client object {

    private http:Client idsClient;
    private GatewayConfiguration gatewayConfig;
    private cache:Cache|() authenticationCache;
    private cache:Cache|() authorizationCache;

    public function __init(GatewayConfiguration _gatewayConfig) {
        self.gatewayConfig = _gatewayConfig;
        http:ClientConfiguration epConfig = {
            secureSocket: {
                trustStore: {
                    path: self.gatewayConfig.truststorePath,
                    password: self.gatewayConfig.truststorePassword
                },
                verifyHostname: true
            },
            timeoutInMillis: self.gatewayConfig.timeoutInMillis
        };
        if (self.gatewayConfig?.circuitBreaker is CircuitBreakerConfiguration) {
            CircuitBreakerConfiguration circuitBreakerConf = <CircuitBreakerConfiguration>self.gatewayConfig?.circuitBreaker;
            log:printDebug("Circuit breaker enabled");
            epConfig.circuitBreaker = {
                rollingWindow: {
                    timeWindowInMillis: circuitBreakerConf.timeWindowInMillis,
                    bucketSizeInMillis: circuitBreakerConf.bucketSizeInMillis,
                    requestVolumeThreshold: circuitBreakerConf.requestVolumeThreshold
                },
                failureThreshold: circuitBreakerConf.failureThreshold,
                resetTimeInMillis: circuitBreakerConf.resetTimeInMillis,
                statusCodes: circuitBreakerConf.statusCodes
            };
        } else {
            log:printDebug("Circuit breaker disabled");
        }
        if (self.gatewayConfig?.authenticationCache != ()) {
            CacheConfiguration? cacheConf = self.gatewayConfig?.authenticationCache;
            self.authenticationCache = new ({
                capacity: <int>cacheConf?.size,
                evictionFactor: <float>cacheConf?.evictionFactor,
                defaultMaxAgeInSeconds: <int>cacheConf?.maxAgeInSeconds,
                cleanupIntervalInSeconds: <int>cacheConf?.cleanupIntervalInSeconds
            });
        } else {
            self.authenticationCache = ();
        }
        if (self.gatewayConfig?.authorizationCache != ()) {
            CacheConfiguration? cacheConf = self.gatewayConfig?.authorizationCache;
            self.authorizationCache = new ({
                capacity: <int>cacheConf?.size,
                evictionFactor: <float>cacheConf?.evictionFactor,
                defaultMaxAgeInSeconds: <int>cacheConf?.maxAgeInSeconds,
                cleanupIntervalInSeconds: <int>cacheConf?.cleanupIntervalInSeconds
            });
        } else {
            self.authorizationCache = ();
        }
        self.idsClient = new (self.gatewayConfig.idsEndpoint, epConfig);
    }

    # Perform OAuth2 token validation and XACML authorization then forwards the payload to the remote endpoint.
    #
    # + caller - the `http:Caller` that makes the request
    # + request - the `http:Request` object for the current request
    # + targetClient - An `http:Client` configured in your project for the remote endpoint
    # + serviceUrl - path of the remote resource
    # + authorizationEnabled - if `true` make a xacml query to the policy decision point, passing as a parameters the current logged username, the path of the remote resource and the http request method
    # + transformCallback - callback function called before forwarding payload to remote endpoint. The `nil` value `()` represent the absence of callback function to manipulate the request.
    public remote function gateway(http:Caller caller, http:Request request, http:Client targetClient, string serviceUrl, boolean authorizationEnabled, (function (http:Request, json) returns (http:Request))|() transformCallback) {
        var response = self->process(caller, request, targetClient, serviceUrl, authorizationEnabled, transformCallback);
        var result = self->responseToCaller(caller, <@untainted>response);
    }

    # Perform OAuth2 token validation and XACML authorization
    #
    # + caller - the `http:Caller` that makes the request
    # + request - the `http:Request` object for the current request
    # + targetClient - An `http:Client` configured in your project for the remote endpoint
    # + serviceUrl - path of the remote resource
    # + authorizationEnabled - if `true` make a xacml query to the policy decision point, passing as a parameters the current logged username, the path of the remote resource and the http request method
    # + transformCallback - callback function called before forwarding payload to remote endpoint. The `nil` value `()` represent the absence of callback function to manipulate the request.
    # + return - If success returns the remote service response object, else returns error
    public remote function process(http:Caller caller, http:Request request, http:Client targetClient, string serviceUrl, boolean authorizationEnabled, (function (http:Request, json) returns (http:Request))|() transformCallback) returns @untainted http:Response|error? {
        boolean|error authResponse = check self.authenticate(request);
        json userInfo = check self.getUserInfo();
        if (authorizationEnabled) {
            boolean|error authorized = check self.authorization(request.rawPath, request.method, userInfo.sub.toString());
        }
        var transformedRequest = request;
        request.rawPath = serviceUrl;
        if (!(transformCallback is ())) {
            transformedRequest = transformCallback(request, userInfo);
        }
        log:printDebug("Forward request to inner service.");
        http:Response|error clientResponse = targetClient->forward(transformedRequest.rawPath, transformedRequest);
        return clientResponse;
    }

    # Send remote service response back to the caller
    #
    # + caller - the `http:Caller` that makes the request
    # + response - the `http:Request` object for the current request
    # + return - error object in case of exception
    public remote function responseToCaller(http:Caller caller, http:Response|error? response) returns error? {
        if (response is error) {
            var serviceResponse = self.sendError(caller, response);
        } else {
            log:printDebug("Send response to client.");
            var gtwResponse = caller->respond(response);
        }
    }

    private function authenticate(http:Request request) returns @untainted boolean|error {
        boolean|error authResponse;
        if (!request.hasHeader("Authorization")) {
            authResponse = error("401", message = "Authentication failed, missing Access Token.");
        } else {
            string|error accessToken = check self.getAccessToken(request);
            var ctx = runtime:getInvocationContext();
            ctx.attributes["accessToken"] = <any>accessToken;
            if (self.cacheHasKey(self.authenticationCache, check accessToken)) {
                authResponse = true;
            } else {
                authResponse = check self.verifyAccessToken(check accessToken);
                if (!(check authResponse)) {
                    authResponse = error("401", message = "Authentication failed.");
                }
            }
        }
        return authResponse;
    }

    private function getAccessToken(http:Request request) returns @untainted string|error {
        return stringutils:replace(request.getHeader("Authorization"), "Bearer ", "");
    }

    private function verifyAccessToken(string accessToken) returns @untainted boolean|error {
        boolean|error verifyResponse;
        log:printDebug("Check accessToken: " + accessToken);
        http:Request request = new;
        request.addHeader("Content-type", "application/x-www-form-urlencoded");
        request = self.setBasicAuth(request);
        var response = self.idsClient->post(self.gatewayConfig.idsIntrospectPath + "?token=" + accessToken, request);
        if (response is error) {
            log:printError("Error during Token validation - ", response);
            verifyResponse = response;
        } else {
            json payload = check response.getJsonPayload();
            log:printDebug("AccessToken status: " + payload.active.toString());
            verifyResponse = boolean.constructFrom(check payload.active);
        }
        return verifyResponse;
    }

    private function getUserInfo() returns @untainted json|error {
        var ctx = runtime:getInvocationContext();
        string accessToken = <string>ctx.attributes["accessToken"];
        log:printDebug("Retrieve User info: " + accessToken);
        http:Request request = new;
        request.addHeader("Authorization", "Bearer " + accessToken);
        json|error userInfoResult = {};
        if (self.cacheHasKey(self.authenticationCache, accessToken)) {
            userInfoResult = <json>self.getFromCache(self.authenticationCache, accessToken);
            log:printDebug("User info retrieved from cache: " + userInfoResult.toString());
        } else {
            var idsAuthResponse = trap self.idsClient->get(self.gatewayConfig.idsUserInfoPath, message = request);
            if (idsAuthResponse is error) {
                log:printError("Error during user info loading - ", idsAuthResponse);
                userInfoResult = idsAuthResponse;
            } else {
                json payload = check idsAuthResponse.getJsonPayload();
                log:printDebug("User info: " + payload.toString());
                if (self.gatewayConfig?.authenticationCache != ()) {
                    cache:Error? put = self.addToCache(self.authenticationCache, accessToken, <@untainted>payload);
                    log:printDebug("User info cached.");
                }                
                userInfoResult = payload;
            }
        }
        return userInfoResult;
    }

    private function authorization(string resourceId, string actionId, string subjectId) returns @untainted boolean|error {
        boolean|error authorized;
        string resourceKey = resourceId;
        int? index = resourceId.indexOf("?");
        if (index is int) {
            resourceKey = resourceId.substring(0, index);
        }
        string authzKey = resourceKey.concat("_", actionId, "_", subjectId);
        if (self.cacheHasKey(self.authorizationCache, authzKey)) {
            authorized = <boolean>self.getFromCache(self.authorizationCache, authzKey);
            log:printDebug("Authorization result from cache: " + authorized.toString());
        } else {
            json requestPayload = self.createAuthzRequest(resourceKey, actionId, subjectId);
            log:printDebug("Check authorization: " + requestPayload.toJsonString());
            http:Request request = new;
            request.addHeader("Content-type", "application/json");
            request.addHeader("Accept", "application/json");
            request = self.setBasicAuth(request);
            request.setJsonPayload(<@untainted>requestPayload);
            var response = trap self.idsClient->post(<@untainted>self.gatewayConfig.idsAuthorizationPath, <@untainted>request);
            if (response is error) {
                log:printError("Error during authorization request - ", response);
                authorized = response;
            } else {
                map<json> authzResponse = <map<json>>response.getJsonPayload();
                log:printDebug("Authorization result: " + authzResponse.toJsonString());
                json[] responseArray = <json[]>authzResponse["Response"];
                json responseElement = responseArray[0];
                string authzResult = responseElement.Decision.toString();
                authorized = authzResult.toString().toLowerAscii() == "permit";
                if (self.gatewayConfig?.authorizationCache != ()) {
                    cache:Error? put = self.addToCache(self.authorizationCache, <@untainted>authzKey, check <@untainted>authorized);
                    log:printDebug("Authorization cached.");
                }
            }
        }
        if (authorized is boolean && !authorized) {
            authorized = error("403", message = "Authorization denied.");
        }
        return authorized;
    }

    private function setBasicAuth(http:Request request) returns http:Request {
        string creds = self.gatewayConfig.idsUsername + ":" + self.gatewayConfig.idsPassword;
        byte[] inputByteArr = creds.toBytes();
        string authInfo = encoding:encodeBase64Url(inputByteArr);
        request.addHeader("Authorization", "Basic " + authInfo);
        return request;
    }

    private function sendError(http:Caller caller, error reason) returns error? {
        http:Response responseError = new;
        responseError.statusCode = http:STATUS_UNAUTHORIZED;
        responseError.setTextPayload(reason.detail()?.message.toString());
        var gtwResponse = caller->respond(responseError);
        return gtwResponse;
    }

    private function cacheHasKey(cache:Cache? cache, string key) returns boolean {
        boolean hasKey = false;
        if (cache is cache:Cache) {
            cache:Cache authCache = <cache:Cache>cache;
            hasKey = authCache.hasKey(key);
        } else {
            hasKey = false;
        }
        return hasKey;
    }

    private function getFromCache(cache:Cache? cache, string key) returns any|error {
        any|error result = ();
        if (cache is cache:Cache) {
            cache:Cache authCache = <cache:Cache>cache;
            result = authCache.get(key);
        }
        return result;
    }

    private function addToCache(cache:Cache? cache, string key, any value) {
        if (cache is cache:Cache) {
            cache:Cache authCache = <cache:Cache>cache;
            cache:Error? put = authCache.put(key, value);
        }
    }

    private function createAuthzRequest(string resourceId, string actionId, string subjectId) returns (json) {
        return {
            "Request": {
                "AccessSubject": {
                    "Attribute": [{
                        "AttributeId": "subject-id",
                        "Value": subjectId
                    }]
                },
                "Resource": {
                    "Attribute": [{
                        "AttributeId": "resource-id",
                        "Value": resourceId
                    }]
                },
                "Action": {
                    "Attribute": [{
                        "AttributeId": "action-id",
                        "Value": actionId
                    }]
                }
            }
        };
    }

};

public type CacheConfiguration record {
    int size;
    float evictionFactor;
    int maxAgeInSeconds;
    int cleanupIntervalInSeconds;
};

public type CircuitBreakerConfiguration record {
    int timeWindowInMillis;
    int bucketSizeInMillis;
    int requestVolumeThreshold;
    float failureThreshold;
    int resetTimeInMillis;
    int[] statusCodes;
};

public type GatewayConfiguration record {
    string idsEndpoint;
    string idsUsername;
    string idsPassword;
    string truststorePath;
    string truststorePassword;
    string idsIntrospectPath = "/oauth2/introspect";
    string idsUserInfoPath = "/oauth2/userinfo?schema=openid";
    string idsAuthorizationPath = "/api/identity/entitlement/decision/pdp";
    CacheConfiguration authenticationCache?;
    CacheConfiguration authorizationCache?;
    CircuitBreakerConfiguration circuitBreaker?;
    int timeoutInMillis = 20000;
};
