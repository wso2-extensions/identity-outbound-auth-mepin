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

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.authenticator.mepin.model.MepinTransaction;
import org.wso2.carbon.identity.authenticator.mepin.model.MepinUserInfo;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;

/**
 * Mepin transactions.
 */
public class MepinTransactions {

    private static Log log = LogFactory.getLog(MepinTransactions.class);

    /**
     * Create the transaction for the Mepin request.
     *
     * @param mepinID            the mepin id
     * @param url                the url
     * @param username           the user name
     * @param password           the password
     * @param appId              the application id created at the mepin portal
     * @param header             the header
     * @param message            the message
     * @param shortMessage       short message
     * @param confirmationPolicy the confirmation policy
     * @param callbackUrl        the callback url
     * @param expiryTime         the expiry time
     * @return the transaction response
     * @throws IOException
     * @throws AuthenticationFailedException
     */
    protected String createTransaction(String mepinID, String url,
                                       String username, String password, String appId,
                                       String header, String message, String shortMessage,
                                       String confirmationPolicy, String callbackUrl,
                                       String expiryTime) throws IOException, AuthenticationFailedException {
        if (log.isDebugEnabled()) {
            log.debug("Started handling transaction creation");
        }
        MepinTransaction mepinTransaction = new MepinTransaction();
        mepinTransaction.setAction(MepinConstants.TRANSACTIONS_CREATE);
        mepinTransaction.setApp_id(appId);
        //set as a long random hex string, 32 bytes.
        mepinTransaction.setIdentifier(getRandomHexString());
        mepinTransaction.setMepin_id(mepinID);
        mepinTransaction.setShort_message(shortMessage);
        mepinTransaction.setHeader(header);
        mepinTransaction.setMessage(message);
        mepinTransaction.setConfirmation_policy(confirmationPolicy);
        mepinTransaction.setExpiry_time(expiryTime);
        String mepinTransactionStr = new Gson().toJson(mepinTransaction);
        String postData = MepinConstants.MEPIN_DATA + mepinTransactionStr;
        String response = postRequest(url, postData, username, password);
        if (log.isDebugEnabled()) {
            log.debug("MePin JSON Response: " + response);
        }
        return response;
    }

    /**
     * Send post request with basic authentication.
     *
     * @param url      the url
     * @param payload    the payload string
     * @param username the user name
     * @param password the password
     * @return the response
     * @throws IOException
     */
    protected String postRequest(String url, String payload, String username, String password)
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
                connection.setRequestMethod(MepinConstants.HTTP_POST);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_POST_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION,
                        MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);
                OutputStream outputStream = connection.getOutputStream();
                outputStream.write(payload.getBytes());
                outputStream.flush();
                outputStream.close();
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
     * Generates a random hex string with 32 bytes.
     *
     * @return random hex string
     */
    private String getRandomHexString() {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while (sb.length() < 32) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, 32);
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
     * @param appId      the client id
     * @param username      the user name
     * @param password      the password
     * @return the response String
     * @throws IOException
     */
    protected String getTransaction(String url, String transactionId, String appId, String username, String password)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Started handling transaction creation");
        }
        MepinTransaction mepinTransaction = new MepinTransaction();
        mepinTransaction.setAction(MepinConstants.TRANSACTIONS_GET);
        mepinTransaction.setApp_id(appId);
        mepinTransaction.setTransaction_id(transactionId);
        String getTransactionStr = new Gson().toJson(mepinTransaction);
        String postData = MepinConstants.MEPIN_DATA + getTransactionStr;
        String authString = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authString.getBytes()));
        HttpsURLConnection connection = null;
        URLConnection urlConnection;
        BufferedReader bufferedReader = null;
        String responseString = "";
        InputStream inputStream = null;
        OutputStream outputStream = null;
        if (log.isDebugEnabled()) {
            log.debug("The transaction url is " + url);
        }
        try {
            urlConnection = new URL(url).openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                connection = (HttpsURLConnection) urlConnection;
                connection.setRequestMethod(MepinConstants.HTTP_POST);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_POST_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION, MepinConstants.HTTP_AUTHORIZATION_BASIC
                        + encoding);
                connection.setDoOutput(true);
                outputStream = connection.getOutputStream();
                outputStream.write(postData.getBytes());
                outputStream.flush();

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
            if (outputStream != null) {
                outputStream.close();
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
     * @param appId       the application id created at the mepin portal
     * @param accessToken the access token
     * @return the user information
     * @throws AuthenticationFailedException
     */
    protected String getUserInformation(String username, String password, String appId, String accessToken)
            throws AuthenticationFailedException {
        String responseString = "";
        HttpsURLConnection connection = null;
        OutputStream outputStream = null;
        URLConnection urlConnection;
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));

        try {
            urlConnection = new URL(MepinConstants.MEPIN_ENDPOINT).openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                connection = (HttpsURLConnection) urlConnection;
                connection.setRequestMethod(MepinConstants.HTTP_POST);
                connection.setRequestProperty(MepinConstants.HTTP_ACCEPT, MepinConstants.HTTP_POST_CONTENT_TYPE);
                connection.setRequestProperty(MepinConstants.HTTP_AUTHORIZATION,
                        MepinConstants.HTTP_AUTHORIZATION_BASIC + encoding);
                //construct user info form body
                MepinUserInfo userInfo = new MepinUserInfo();
                userInfo.setAction(MepinConstants.USER_INFO_GET);
                userInfo.setApp_id(appId);
                userInfo.setAccess_token(accessToken);
                String userInfoStr = new Gson().toJson(userInfo);
                String postData = MepinConstants.MEPIN_DATA + userInfoStr;
                //set user info request body
                connection.setDoOutput(true);
                outputStream = connection.getOutputStream();
                outputStream.write(postData.getBytes());
                outputStream.flush();

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
            if(outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    log.error("Error while closing the output stream for user info request.", e);
                }
            }
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString;
    }
}