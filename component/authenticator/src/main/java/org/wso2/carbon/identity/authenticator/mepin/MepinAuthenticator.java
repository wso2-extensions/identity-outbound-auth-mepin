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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.mepin.exception.MepinException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator for MePIN
 */
public class MepinAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8948601002969608129L;
    private static final Log log = LogFactory.getLog(MepinAuthenticator.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getMepinParameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(MepinConstants.AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside MepinAuthenticator canHandle");
        }
        return ((!StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)))
                || (!StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_LOGIN))));
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN))) {
            // if the request comes with MOBILE_NUMBER, it will go through this flow.
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_LOGIN))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(MepinConstants.AUTHENTICATION)
                    .equals(MepinConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is Mepin, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String tenantDomain = context.getTenantDomain();
            context.setProperty(MepinConstants.AUTHENTICATION, MepinConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(MepinConstants.USER_NAME));
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                    .getProperty(MepinConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: Could not find the authenticated user."
                            + " The user name " + username + " might be null");
                }
                throw new AuthenticationFailedException("Authentication failed: Could not find the authenticated user."
                        + " The user name " + username + " might be null");
            }
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            processMepinFlow(context, username, authenticatorProperties, authenticatedUser, response, queryParams);
        } catch (MepinException | IOException e) {
            throw new AuthenticationFailedException("Error while processing the authentication flow for the user "
                    + username, e);
        }
    }

    /**
     * Check the mepin mandatory options and process the mepin flow according to the options.
     *
     * @param context                 the authentication context
     * @param username                the user name
     * @param authenticatorProperties the authentication properties
     * @param authenticatedUser       the authenticated user
     * @param response                the HttpServletResponse
     * @throws MepinException
     * @throws IOException
     * @throws AuthenticationFailedException
     */
    private void processMepinFlow(AuthenticationContext context, String username,
                                  Map<String, String> authenticatorProperties,
                                  AuthenticatedUser authenticatedUser, HttpServletResponse response,
                                  String queryParams)
            throws MepinException, IOException, AuthenticationFailedException {
        boolean isMepinDisabledUser = isMepinDisableForUser(username, context);
        if (log.isDebugEnabled()) {
            log.debug("Mepin authentication is enabled by user: " + isMepinDisabledUser);
        }
        boolean isMepinEnabledByAdmin = isMepinMandatory(context);
        if (log.isDebugEnabled()) {
            log.debug("Mepin authentication is enabled by admin: " + isMepinEnabledByAdmin);
        }
        if (isMepinDisabledUser && isMepinEnabledByAdmin) {
        /*If the parameter MepinMandatory is true, the parameter MepinEnableByUserClaim is true
        and the user disables the Mepin authenticator using the claim, the authentication is failed .*/
            redirectToErrorPage(response, context, queryParams, MepinConstants.ERROR_MEPIN_DISABLE);
        } else if (isMepinDisabledUser) {
        /*If the parameter MepinMandatory is false and the parameter MepinEnableByUserClaim is true
        and the user disables the Mepin authenticator using the claim, the authentication flow happens
        with first step authentication.*/
            processFirstStepOnly(authenticatedUser, context);
        } else {
        /* In other cases, the authentication flow happens with Mepin two factor authentication.*/
            proceedWithMepin(response, authenticatorProperties, context, username);
        }
    }

    /**
     * Ge the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return the url
     */
    private String getURL(String baseURI, String queryParams) {
        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + MepinConstants.NAME_OF_AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + MepinConstants.NAME_OF_AUTHENTICATORS + getName();
        }
        return url;
    }

    /**
     * Redirect to an error page.
     *
     * @param response    the HttpServletResponse
     * @param queryParams the query parameter
     * @param retryParam  the retry parameter
     * @throws AuthenticationFailedException
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams,
                                     String retryParam)
            throws AuthenticationFailedException {
        // that Enable the Mepin in user's Profile. Cannot proceed further without Mepin authentication.
        String errorPage = getErrorPage(context);
        String url = getURL(errorPage, queryParams);
        if (log.isDebugEnabled()) {
            log.debug("Th error page is " + errorPage + " and the url is " + url);
        }
        try {
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to error page " + errorPage +
                    " and the url " + url, e);
        }
    }

    /**
     * In Mepin optional case proceed with first step only.It can be basic or federated.
     *
     * @param authenticatedUser the name of authenticatedUser
     * @param context           the AuthenticationContext
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {
        //the authentication flow happens with basic authentication.
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(MepinConstants.AUTHENTICATION, MepinConstants.BASIC);
        } else {
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(MepinConstants.AUTHENTICATION, MepinConstants.FEDERETOR);
        }
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the errorPage
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {
        String errorPage = getErrorPageFromXMLFile(context);
        String authenticationEndpointURL;
        if (StringUtils.isEmpty(errorPage)) {
            authenticationEndpointURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            errorPage = authenticationEndpointURL.replace(MepinConstants.LOGIN_PAGE, MepinConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("The default authentication endpoint URL " + authenticationEndpointURL +
                        "is replaced by default the mepin error page context " + errorPage);
            }
            if (!errorPage.contains(MepinConstants.ERROR_PAGE)) {
                throw new AuthenticationFailedException("The default authentication page is not replaced by default" +
                        " error page");
            }
        }
        return errorPage;
    }

    /**
     * Proceed the Mepin request flow.
     *
     * @param response the HttpServletResponse
     * @param context  the AuthenticationContext
     * @throws AuthenticationFailedException
     */
    private void proceedWithMepin(HttpServletResponse response, Map<String, String> authenticatorProperties,
                                  AuthenticationContext context, String userName) throws AuthenticationFailedException {
        boolean isSecondStep = false;
        boolean isLinked = false;
        String mepinID;
        String mepinPage = getMepinPage(context);
        try {
            if (StringUtils.isNotEmpty(userName)) {
                isSecondStep = true;
                mepinID = getMepinIdFromUserClaim(context, userName);
                if (StringUtils.isNotEmpty(mepinID)) {
                    isLinked = true;
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException("Unable to retrieve the associated user.", e);
        }

        try {
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=authentication.fail.message";
            }
            response.sendRedirect(mepinPage + "?authenticators=" + getName()
                    + "&applicationId=" + authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID)
                    + "&callbackUrl=" + authenticatorProperties.get(MepinConstants.MEPIN_CALLBACK_URL)
                    + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" + context.getContextIdentifier()
                    + "&isSecondStep=" + isSecondStep + "&isLinked=" + isLinked + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting the MePIN", e);
        }
    }

    /**
     * Get the mepin page from authentication.xml file or use the mepin page from constant file.
     *
     * @param context the AuthenticationContext
     * @return the loginPage
     * @throws AuthenticationFailedException
     */
    private String getMepinPage(AuthenticationContext context) throws AuthenticationFailedException {
        String mepinPage = getMepinPageFromXMLFile(context);
        if (log.isDebugEnabled()) {
            log.debug("The mepin page url is " + mepinPage);
        }
        if (StringUtils.isEmpty(mepinPage)) {
            String authenticationEndpointURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            mepinPage = authenticationEndpointURL.replace(MepinConstants.LOGIN_PAGE, MepinConstants.MEPIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("The default authentication endpoint URL " + authenticationEndpointURL +
                        "is replaced by default mepin mepin page context " + mepinPage);
            }
            if (!mepinPage.contains(MepinConstants.MEPIN_PAGE)) {
                throw new AuthenticationFailedException("The default authentication page is not replaced by default" +
                        " mepin page");
            }
        }

        return mepinPage;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return MepinConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return MepinConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property applicationId = new Property();
        applicationId.setName(MepinConstants.MEPIN_APPICATION_ID);
        applicationId.setDisplayName("Application Id");
        applicationId.setRequired(true);
        applicationId.setDescription("Enter MePIN application id value");
        applicationId.setDisplayOrder(1);
        configProperties.add(applicationId);

        Property username = new Property();
        username.setName(MepinConstants.MEPIN_USERNAME);
        username.setDisplayName("Username");
        username.setRequired(true);
        username.setDescription("Enter username");
        username.setDisplayOrder(2);
        configProperties.add(username);

        Property password = new Property();
        password.setName(MepinConstants.MEPIN_PASSWORD);
        password.setDisplayName("Password");
        password.setRequired(true);
        password.setConfidential(true);
        password.setDescription("Enter password");
        password.setDisplayOrder(3);
        configProperties.add(password);

        Property callbackUrl = new Property();
        callbackUrl.setName(MepinConstants.MEPIN_CALLBACK_URL);
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter value corresponding to callback url");
        callbackUrl.setDisplayOrder(4);
        configProperties.add(callbackUrl);

        Property clientId = new Property();
        clientId.setName(MepinConstants.MEPIN_CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Client Id");
        clientId.setDisplayOrder(5);
        configProperties.add(clientId);

        Property confirmationPolicy = new Property();
        confirmationPolicy.setName(MepinConstants.MEPIN_CONFIRMATION_POLICY);
        confirmationPolicy.setDisplayName("Confirmation Policy");
        confirmationPolicy.setRequired(true);
        confirmationPolicy.setDescription("Enter Confirmation Policy (tap, pin, swipe, fp)");
        confirmationPolicy.setDisplayOrder(6);
        configProperties.add(confirmationPolicy);

        Property expiryTime = new Property();
        expiryTime.setName(MepinConstants.MEPIN_EXPIRY_TIME);
        expiryTime.setDisplayName("Expiry Time");
        expiryTime.setRequired(true);
        expiryTime.setDescription("Enter Expiry Time (in seconds)");
        expiryTime.setDisplayOrder(7);
        configProperties.add(expiryTime);

        Property header = new Property();
        header.setName(MepinConstants.MEPIN_HEADER);
        header.setDisplayName("Header");
        header.setRequired(true);
        header.setDescription("Enter Header");
        header.setDisplayOrder(8);
        configProperties.add(header);

        Property message = new Property();
        message.setName(MepinConstants.MEPIN_MESSAGE);
        message.setDisplayName("Message");
        message.setRequired(true);
        message.setDescription("Enter Message");
        message.setDisplayOrder(9);
        configProperties.add(message);

        Property shortMessage = new Property();
        shortMessage.setName(MepinConstants.MEPIN_SHORT_MESSAGE);
        shortMessage.setDisplayName("Short Message");
        shortMessage.setRequired(true);
        shortMessage.setDescription("Enter Short Message");
        shortMessage.setDisplayOrder(10);
        configProperties.add(shortMessage);

        return configProperties;
    }

    /**
     * Process the Mepin association flow.
     *
     * @param authenticatorProperties the authentication properties
     * @param request                 the Http Servlet Request
     * @param context                 the authentication context
     * @param username                the user name
     * @throws AuthenticationFailedException
     */
    protected void processAssociationFlow(HttpServletRequest request, Map<String, String> authenticatorProperties,
                                          AuthenticationContext context, String username)
            throws AuthenticationFailedException {
        try {
            String accessToken = request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN);
            String responseString = new MepinTransactions().getUserInformation(
                    authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                    authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD),
                    authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID),
                    accessToken);
            if (!responseString.equals(MepinConstants.FAILED)) {
                JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                String mepinId = responseJson.getAsJsonPrimitive(MepinConstants.MEPIN_ID).getAsString();
                String authenticatedLocalUsername = String.valueOf(context.getProperty(MepinConstants.USER_NAME));
                String associatedMepinID = getMepinIdFromUserClaim(context, authenticatedLocalUsername);
                if (StringUtils.isEmpty(associatedMepinID)) {
                    addMepinIdToUserClaim(username, mepinId, context);
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                } else {
                    log.error("Trying to hack the mepinId " + mepinId + " of the " + username
                            + " User with the mepinId " + associatedMepinID);
                    return;
                }
            } else {
                throw new AuthenticationFailedException("Unable to get the MePIN ID.");
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException("Unable to associate the user", e);
        }
    }

    /**
     * Get the authentication status whether authenticated or not in Mepin retrying flow.
     *
     * @param authenticatorProperties the authentication properties
     * @param transactionId           the transaction id
     * @return the
     * @throws AuthenticationFailedException
     */
    protected boolean processMepinRetry(Map<String, String> authenticatorProperties, String transactionId)
            throws AuthenticationFailedException {
        Boolean isAuthenticated = false;
        try {
            String allowStatus;
            int retry = 0;
            int retryInterval = 1;
            int retryCount = Integer.parseInt(authenticatorProperties.get(
                    MepinConstants.MEPIN_EXPIRY_TIME)) / retryInterval;
            while (retry < retryCount) {
                String responseString = new MepinTransactions().getTransaction(
                        MepinConstants.MEPIN_ENDPOINT, transactionId,
                        authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID),
                        authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                        authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD));
                if (!responseString.equals(MepinConstants.FAILED)) {
                    JsonObject transactionStatusResponse = new JsonParser().parse(
                            responseString).getAsJsonObject();
                    String transactionStatus = transactionStatusResponse.getAsJsonPrimitive(
                            MepinConstants.MEPIN_TRANSACTION_STATUS).getAsString();
                    JsonPrimitive allowObject = transactionStatusResponse.getAsJsonPrimitive(
                            MepinConstants.MEPIN_ALLOW);
                    if (log.isDebugEnabled()) {
                        log.debug("Transaction status :" + transactionStatus);
                    }
                    if (transactionStatus.equals(MepinConstants.MEPIN_COMPLETED)) {
                        allowStatus = allowObject.getAsString();
                        if (Boolean.parseBoolean(allowStatus)) {
                            isAuthenticated = true;
                            break;
                        }
                    } else if (transactionStatus.equals(MepinConstants.MEPIN_CANCELED)
                            || transactionStatus.equals(MepinConstants.MEPIN_EXPIRED)
                            || transactionStatus.equals(MepinConstants.MEPIN_ERROR)) {
                        break;
                    }
                }
                Thread.sleep(1000);
                retry++;
            }
        } catch (InterruptedException e) {
            throw new AuthenticationFailedException("Interruption occurred while getting the MePIN transaction status", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while geetting the response string from transaction", e);
        }
        return isAuthenticated;
    }

    /**
     * Process Mepin login flow.
     *
     * @param context  the authentication context
     * @param username the user name
     * @throws AuthenticationFailedException
     */
    protected void processLoginWithMepin(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                         String username) throws AuthenticationFailedException {
        try {
            String mePinId;
            mePinId = getMepinIdFromUserClaim(context, username);
            if (StringUtils.isEmpty(mePinId)) {
                log.error("First, You need to Link with Mepin");
                return;
            }
            Boolean isAuthenticated;
            String transactionResponseString = new MepinTransactions()
                    .createTransaction(mePinId, MepinConstants.MEPIN_ENDPOINT,
                            authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                            authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD),
                            authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID),
                            authenticatorProperties.get(MepinConstants.MEPIN_HEADER),
                            authenticatorProperties.get(MepinConstants.MEPIN_MESSAGE),
                            authenticatorProperties.get(MepinConstants.MEPIN_SHORT_MESSAGE),
                            authenticatorProperties.get(MepinConstants.MEPIN_CONFIRMATION_POLICY),
                            authenticatorProperties.get(MepinConstants.MEPIN_CALLBACK_URL),
                            authenticatorProperties.get(MepinConstants.MEPIN_EXPIRY_TIME));
            if (!transactionResponseString.equals(MepinConstants.FAILED)) {
                JsonObject transactionResponseJson = new JsonParser().parse(
                        transactionResponseString).getAsJsonObject();
                String transactionId = transactionResponseJson.getAsJsonPrimitive(
                        MepinConstants.MEPIN_TRANSACTION_ID).getAsString();
                String status = transactionResponseJson.getAsJsonPrimitive(
                        MepinConstants.MEPIN_STATUS).getAsString();
                if (status.equalsIgnoreCase(MepinConstants.MEPIN_OK)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully created the MePIN transaction");
                    }
                    isAuthenticated = processMepinRetry(authenticatorProperties, transactionId);
                    if (isAuthenticated) {
                        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                    } else {
                        throw new AuthenticationFailedException("Unable to confirm the MePIN transaction");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while creating the MePIN transaction");
                    }
                    throw new AuthenticationFailedException("Error while creating the MePIN transaction");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while creating the MePIN transaction");
                }
                throw new AuthenticationFailedException("Error while creating the MePIN transaction");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Unable to create the MePIN transaction ", e);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException("Unable to get the associated user ", e);
        }
    }

    /**
     * Process the response of the MePIN end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if ((!StringUtils.isEmpty(request.getParameter(MepinConstants.IS_SECOND_STEP))
                && !StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)))) {
            if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
                username = String.valueOf(context.getProperty(MepinConstants.USER_NAME));
            }
            processAssociationFlow(request, authenticatorProperties, context, username);
        } else if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
            username = String.valueOf(context.getProperty(MepinConstants.USER_NAME));
            processLoginWithMepin(context, authenticatorProperties, username);
        }
    }

    /**
     * Add Mepin id to mepinid claim for the association the mepin id with user name.
     *
     * @param userName the user name
     * @param context  the authentication context
     */
    private void addMepinIdToUserClaim(String userName, String mepinId, AuthenticationContext context)
            throws org.wso2.carbon.user.core.UserStoreException, AuthenticationFailedException {
        String tenantAwareUsername;
        Map<String, String> claimMap = new HashMap<String, String>();
        tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        claimMap.put(MepinConstants.MEPIN_ID_CLAIM, mepinId);
        UserStoreManager userStoreManager = getUserStoreManager(context.getTenantDomain());
        userStoreManager.setUserClaimValues(tenantAwareUsername, claimMap, null);
        if (log.isDebugEnabled()) {
            log.debug("The claim uri" + MepinConstants.MEPIN_ID_CLAIM + "of " + tenantAwareUsername
                    + " updated with the mepin id " + mepinId);
        }
    }

    /**
     * Get Mepin id from the mepinid claim of the user.
     *
     * @param userName the user name
     * @param context  the authentication context
     */
    private String getMepinIdFromUserClaim(AuthenticationContext context, String userName)
            throws org.wso2.carbon.user.core.UserStoreException, AuthenticationFailedException {
        String tenantAwareUsername, mepinId = null;
        UserStoreManager userStoreManager;

        // find the authenticated user.
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(MepinConstants.AUTHENTICATED_USER);
        if (authenticatedUser == null) {
            throw new AuthenticationFailedException
                    ("Authentication failed!. Cannot proceed further without identifying the user");
        }
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
            userStoreManager = getUserStoreManager(context.getTenantDomain());
            Claim[] userClaimValues = userStoreManager.getUserClaimValues(tenantAwareUsername, null);
            for (Claim userClaimValue : userClaimValues) {
                if (MepinConstants.MEPIN_ID_CLAIM.equals(userClaimValue.getClaimUri())) {
                    mepinId = userClaimValue.getValue();
                    break;
                }
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user claim - "
                    + MepinConstants.MEPIN_ID_CLAIM, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("The claim uri " + MepinConstants.MEPIN_ID_CLAIM + " of " + userName + " updated with mepin id "
                    + mepinId);
        }
        return mepinId;
    }

    /**
     * Get the user store manager from user realm service.
     *
     * @param tenantDomain the tenant domain
     * @return the user store manager
     * @throws AuthenticationFailedException
     */
    private UserStoreManager getUserStoreManager(String tenantDomain)
            throws AuthenticationFailedException {
        int tenantId;
        UserStoreManager userStoreManager;
        tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm" +
                    "for tenant domain " + tenantDomain, e);
        }
        return userStoreManager;
    }

    /**
     * Check whether Mepin is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     * @throws MepinException
     */
    private boolean isMepinDisableForUser(String username, AuthenticationContext context)
            throws MepinException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnableORDisableLocalUserClaim = isMepinDisableByUser(context);
            if (userRealm != null) {
                if (isEnableORDisableLocalUserClaim) {
                    String isMepinEnabledByUser = userRealm.getUserStoreManager().getUserClaimValue(username,
                            MepinConstants.USER_MEPIN_DISABLED_CLAIM_URI, null);
                    return Boolean.parseBoolean(isMepinEnabledByUser);
                }
            } else {
                throw new MepinException("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new MepinException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

    /**
     * Check whether Mepin is mandatory or not.
     *
     * @param context the authentication context
     * @return status of user's mepin authentication
     */
    private boolean isMepinMandatory(AuthenticationContext context) {
        boolean isMepinMandatory = false;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.IS_MEPIN_MANDATORY)) {
            isMepinMandatory = Boolean.parseBoolean(getMepinParameters().get
                    (MepinConstants.IS_MEPIN_MANDATORY));
        } else if ((context.getProperty(MepinConstants.IS_MEPIN_MANDATORY)) != null) {
            isMepinMandatory = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(MepinConstants.IS_MEPIN_MANDATORY)));
        }
        if (log.isDebugEnabled()) {
            log.debug("The mepin authentication is mandatory : " + isMepinMandatory);
        }
        return isMepinMandatory;
    }

    /**
     * Check whether user enable the second factor or not.
     *
     * @param context the authentication context
     * @return status of user's mepin authentication
     */
    private boolean isMepinDisableByUser(AuthenticationContext context) {
        boolean isMepinDisableByUser = false;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.IS_MEPIN_ENABLE_BY_USER)) {
            isMepinDisableByUser = Boolean.parseBoolean(getMepinParameters().get
                    (MepinConstants.IS_MEPIN_ENABLE_BY_USER));
        } else if ((context.getProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER)) != null) {
            isMepinDisableByUser = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER)));
        }
        if (log.isDebugEnabled()) {
            log.debug("The mepin authentication is disabled by user : " + isMepinDisableByUser);
        }
        return isMepinDisableByUser;
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context the authentication context
     * @return the error page
     */
    private String getErrorPageFromXMLFile(AuthenticationContext context) {
        String errorPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = getMepinParameters().get(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String.valueOf
                    (context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL));
        }
        if (log.isDebugEnabled()) {
            log.debug("The error page is " + errorPage);
        }
        return errorPage;
    }

    /**
     * Get the mepin page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return mepin page
     */
    private String getMepinPageFromXMLFile(AuthenticationContext context) {
        String mepinPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL)) {
            mepinPage = getMepinParameters().get(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL)) != null) {
            mepinPage = String.valueOf
                    (context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL));
        }
        if (log.isDebugEnabled()) {
            log.debug("The mepin page is " + mepinPage);
        }
        return mepinPage;
    }
}