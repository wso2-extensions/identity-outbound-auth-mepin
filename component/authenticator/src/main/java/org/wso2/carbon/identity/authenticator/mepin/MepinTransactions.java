/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.mepin;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

/**
 * Mepin transactions.
 */
public class MepinTransactions {

    private static Log log = LogFactory.getLog(MepinTransactions.class);

    /**
     * Create the transaction for the Mepin request.
     *
     * @param mepinID            the mepin id
     * @param sessionID          the session id
     * @param url                the url
     * @param username           the user name
     * @param password           the password
     * @param clientId           the client id
     * @param header             the header
     * @param message            the message
     * @param shortMessage       short message
     * @param confirmationPolicy the confirmation policy
     * @param callbackUrl        the callback url
     * @param expiryTime         the expiry time
     * @return the transaction response
     * @throws IOException
     */
    protected String createTransaction(String mepinID, String sessionID, String url,
                                       String username, String password, String clientId,
                                       String header, String message, String shortMessage,
                                       String confirmationPolicy, String callbackUrl,
                                       String expiryTime) throws IOException, AuthenticationFailedException {
        if (log.isDebugEnabled()) {
            log.debug("Started handling transaction creation");
        }
        String query = String.format(MepinConstants.MEPIN_QUERY, URLEncoder.encode(sessionID, MepinConstants.CHARSET),
                URLEncoder.encode(shortMessage, MepinConstants.CHARSET),
                URLEncoder.encode(header, MepinConstants.CHARSET), URLEncoder.encode(message, MepinConstants.CHARSET),
                URLEncoder.encode(clientId, MepinConstants.CHARSET),
                URLEncoder.encode(mepinID, MepinConstants.CHARSET), URLEncoder.encode(expiryTime, MepinConstants.CHARSET),
                URLEncoder.encode(callbackUrl, MepinConstants.CHARSET),
                URLEncoder.encode(confirmationPolicy, MepinConstants.CHARSET)
        );
        String response = postRequest(url, query, username, password);
        if (log.isDebugEnabled()) {
            log.debug("MePin JSON Response: " + response);
        }
        return response;
    }

    /**
     * Send post request with basic authentication.
     *
     * @param url      the url
     * @param query    the query
     * @param username the user name
     * @param password the password
     * @return the response
     * @throws IOException
     */
    protected String postRequest(String url, String query, String username, String password)
            throws IOException, AuthenticationFailedException {
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        String responseString = "";
        HttpsURLConnection connection = null;
        URLConnection urlConnection;
        try {
            urlConnection = new URL(url).openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                connection = (HttpsURLConnection) urlConnection;
                connection.setDoOutput(true);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT_CHARSET, MepinConstants.CHARSET);
                connection.setRequestProperty(MepinConstants.HTTP_CONTENT_TYPE, MepinConstants.HTTP_POST_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);
                OutputStream output = connection.getOutputStream();
                output.write(query.getBytes(MepinConstants.CHARSET));
                int status = connection.getResponseCode();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Response Code :" + status);
                }
                switch (status) {
                    case 200:
                        responseString = getResponse(connection.getInputStream());
                        break;
                    case 500:
                        responseString = getResponse(connection.getErrorStream());
                        return MepinConstants.FAILED;
                }
            }
        } catch (IOException e) {
            if (connection != null) {
                if (connection.getErrorStream() != null) {
                    responseString = getResponse(connection.getErrorStream());
                    return MepinConstants.FAILED;
                }
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString;
    }

    /**
     * Get the response of the transaction.
     *
     * @param connectionStream the connection stream
     * @return the response
     * @throws AuthenticationFailedException
     */
    protected String getResponse(InputStream connectionStream) throws AuthenticationFailedException {
        String line;
        String responseString;
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            bufferedReader = new BufferedReader(new InputStreamReader(connectionStream));
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            responseString = stringBuilder.toString();
            if (log.isDebugEnabled()) {
                log.debug("MePIN Response :" + responseString);
            }
            return responseString;
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while creating buffered reader with connection stream", e);
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    throw new AuthenticationFailedException("Error while closing buffered Reader of connection", e);
                }
            }
        }
    }

    /**
     * Get the response from transaction.
     *
     * @param url           the url
     * @param transactionId the transaction Id
     * @param clientId      the client id
     * @param username      the user name
     * @param password      the password
     * @return the response String
     * @throws IOException
     */
    protected String getTransaction(String url, String transactionId, String clientId, String username, String password)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Started handling transaction creation");
        }
        String authString = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authString.getBytes()));
        HttpsURLConnection connection = null;
        URLConnection urlConnection;
        BufferedReader bufferedReader = null;
        String responseString = "";
        InputStream inputStream = null;
        url = url + "?transaction_id=" + URLEncoder.encode(transactionId, MepinConstants.CHARSET) + "&client_id="
                + URLEncoder.encode(clientId, MepinConstants.CHARSET);
        if (log.isDebugEnabled()) {
            log.debug("The transaction url is " + url);
        }
        try {
            urlConnection = new URL(url).openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                connection = (HttpsURLConnection) urlConnection;
                connection.setRequestMethod(MepinConstants.HTTP_GET);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC
                        + encoding);
                String response = "";
                int statusCode = connection.getResponseCode();
                if ((statusCode == 200) || (statusCode == 201)) {
                    inputStream = connection.getInputStream();
                    bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String output;
                    while ((output = bufferedReader.readLine()) != null) {
                        responseString += output;
                    }
                } else {
                    inputStream = connection.getErrorStream();
                    bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                    String output;
                    while ((output = bufferedReader.readLine()) != null) {
                        responseString += output;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("MePIN Status Response: " + response);
                    }
                    return MepinConstants.FAILED;
                }
            }
        } catch (IOException e) {
            throw new IOException("Error while opening the connection", e);
        } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (inputStream != null) {
                inputStream.close();
            }
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString;
    }

    /**
     * Get user information from mepin authenticated user.
     *
     * @param username    the user name
     * @param password    the password
     * @param accessToken the access token
     * @return the user information
     * @throws AuthenticationFailedException
     */
    protected String getUserInformation(String username, String password, String accessToken)
            throws AuthenticationFailedException {
        String responseString = "";
        HttpsURLConnection connection = null;
        URLConnection urlConnection;
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        try {
            String query = String.format(MepinConstants.ACCESS_TOKEN_QUERY_PARAM, URLEncoder.encode(accessToken,
                    MepinConstants.CHARSET));
            urlConnection = new URL(MepinConstants.MEPIN_GET_USER_INFO_URL + "?" + query).openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                connection = (HttpsURLConnection) urlConnection;
                connection.setRequestMethod(MepinConstants.HTTP_GET);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC
                        + encoding);
                int status = connection.getResponseCode();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Response Code :" + status);
                }
                if (status == 200) {
                    responseString = getResponse(connection.getInputStream());
                } else {
                    return MepinConstants.FAILED;
                }
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while get user information from mepin ", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString;
    }
}