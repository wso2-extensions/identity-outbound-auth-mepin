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
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.mepin.exception.MepinException;
import org.wso2.carbon.identity.authenticator.mepin.internal.MepinAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of MePIN
 */
public class MepinAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8948601002969608129L;
    private static Log log = LogFactory.getLog(MepinAuthenticator.class);

    /**
     * Get the domain name.
     *
     * @param username the user name
     * @return the domain name
     */
    private static String getDomainName(String username) {
        int index = username.indexOf("/");
        return index < 0 ? MepinConstants.PRIMARY : username.substring(0, index);
    }

    /**
     * Get the user name without user name.
     *
     * @param username the user name
     * @return the user name without domain
     */
    private static String getUsernameWithoutDomain(String username) {
        int index = username.indexOf("/");
        return index < 0 ? username : username.substring(index + 1, username.length());
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
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
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
        try {
            String username;
            AuthenticatedUser authenticatedUser;
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String tenantDomain = context.getTenantDomain();
            context.setProperty(MepinConstants.AUTHENTICATION, MepinConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            }
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            username = String.valueOf(context.getProperty(MepinConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty(MepinConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: Could not find the authenticated user. ");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed: Cannot proceed further without identifying the user. ");
            }
            boolean isMepinMandatory = MepinUtils.isMepinMandatory(context, getName());
            boolean isUserExists = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            String errorPage = getErrorPage(context);
            // Mepin authentication is mandatory and user doesn't disable Mepin claim in user's profile.
            if (isMepinMandatory) {
                processMepinMandatoryCase(context, authenticatorProperties, response, queryParams, username,
                        isUserExists);
            } else if (isUserExists && !MepinUtils.isMepinDisableForLocalUser(username, context, getName())) {
                if (!context.isRetrying()) {
                    proceedWithMepin(response, authenticatorProperties, context);
                }
            } else {
                processFirstStepOnly(authenticatedUser, context);
            }
        } catch (MepinException e) {
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml fie. ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from User Store. ", e);
        }
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
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
     * Check with Mepin mandatory case with Mepin flow.
     *
     * @param context                  the AuthenticationContext
     * @param authenticationProperties the authentication properties
     * @param response                 the HttpServletResponse
     * @param queryParams              the queryParams
     * @param username                 the Username
     * @param isUserExists             check whether user exist or not
     * @throws AuthenticationFailedException
     * @throws MepinException
     */
    private void processMepinMandatoryCase(AuthenticationContext context, Map<String, String> authenticationProperties,
                                           HttpServletResponse response, String queryParams, String username,
                                           boolean isUserExists) throws AuthenticationFailedException, MepinException {
        //the authentication flow happens with mepin authentication.
        if (!context.isRetrying()) {
            processMepinFlow(context, authenticationProperties, response, isUserExists, username, queryParams);
        }
    }

    /**
     * Check with Mepin flow with user existence.
     *
     * @param context                  the AuthenticationContext
     * @param authenticationProperties the authentication properties
     * @param response                 the HttpServletResponse
     * @param isUserExists             check whether user exist or not
     * @param username                 the UserName
     * @param queryParams              the queryParams
     * @throws AuthenticationFailedException
     * @throws org.wso2.carbon.identity.authenticator.mepin.exception.MepinException
     */
    private void processMepinFlow(AuthenticationContext context, Map<String, String> authenticationProperties,
                                  HttpServletResponse response, boolean isUserExists, String username,
                                  String queryParams)
            throws AuthenticationFailedException, MepinException {
        if (isUserExists) {
            boolean isMepinDisabledByUser = MepinUtils.isMepinDisableForLocalUser(username, context, getName());
            if (isMepinDisabledByUser) {
                // that Enable the Mepin in user's Profile. Cannot proceed further without Mepin authentication.
                redirectToErrorPage(response, context, queryParams, MepinConstants.ERROR_MEPIN_DISABLE);
            } else {
                proceedWithMepin(response, authenticationProperties, context);
            }
        }
    }

    /**
     * Redirect to an error page.
     *
     * @param response    the HttpServletResponse
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    protected void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context, String queryParams,
                                       String retryParam)
            throws AuthenticationFailedException {
        // that Enable the Mepin in user's Profile. Cannot proceed further without Mepin authentication.
        try {
            String errorPage = getErrorPage(context);
            String url = getURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Exception occurred while redirecting to errorPage. ", e);
        }
    }

    /**
     * In Mepin optional case proceed with first step only.It can be basic or federated.
     *
     * @param authenticatedUser the name of authenticatedUser
     * @param context           the AuthenticationContext
     */
    protected void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {
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
     * @throws AuthenticationFailedException
     */
    private String getErrorPage(AuthenticationContext context) throws AuthenticationFailedException {
        String errorPage = MepinUtils.getErrorPageFromXMLFile(context, getName());
        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(MepinConstants.LOGIN_PAGE, MepinConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used");
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
    protected void proceedWithMepin(HttpServletResponse response, Map<String, String> authenticatorProperties,
                                    AuthenticationContext context) throws AuthenticationFailedException {
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace(
                MepinConstants.LOGIN_PAGE, MepinConstants.MEPIN_PAGE);
        boolean isSecondStep = false;
        boolean isLinked = false;
        String mepinID;
        try {
            String idpName = context.getExternalIdP().getIdPName();
            String authenticatedLocalUsername = getLocalAuthenticatedUser(context).getUserName();
            if (StringUtils.isNotEmpty(authenticatedLocalUsername)) {
                isSecondStep = true;
                mepinID = getMepinIdAssociatedWithUsername(idpName, authenticatedLocalUsername, context);
                if (StringUtils.isNotEmpty(mepinID)) {
                    isLinked = true;
                }
            }
        } catch (UserProfileException e) {
            throw new AuthenticationFailedException("Unable to retrieve the associated user.", e);
        }

        try {
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=authentication.fail.message";
            }
            response.sendRedirect(loginPage + "?authenticators=" + getName()
                    + "&applicationId=" + authenticatorProperties.get(MepinConstants.MEPIN_APPICATION_ID)
                    + "&callbackUrl=" + authenticatorProperties.get(MepinConstants.MEPIN_CALLBACK_URL)
                    + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" + context.getContextIdentifier()
                    + "&isSecondStep=" + isSecondStep + "&isLinked=" + isLinked + retryParam);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while redirecting");
            }
            throw new AuthenticationFailedException("Error while redirecting the MePIN", e);
        }
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
     * Check whether authenticated user or not.
     *
     * @param request the Http Servlet Request
     * @return Authenticated User or not
     * @throws AuthenticationFailedException
     */
    protected boolean isAuthenticatedUser(HttpServletRequest request) throws AuthenticationFailedException {
        String authHeader = request.getParameter(MepinConstants.AUTH_HEADER);
        String username;
        String password;
        UserStoreManager userStoreManager;
        authHeader = new String(Base64.decodeBase64(authHeader.getBytes()));
        int index = authHeader.indexOf(":");
        username = authHeader.substring(0, index);
        password = authHeader.substring(index + 1, authHeader.length());
        int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
        boolean isAuthenticated;
        try {
            userStoreManager = (UserStoreManager) MepinAuthenticatorServiceComponent.
                    getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            isAuthenticated = userStoreManager.authenticate(
                    MultitenantUtils.getTenantAwareUsername(username), password);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Unable to get the user store manager", e);
        }
        return isAuthenticated;
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
                    accessToken);
            if (!responseString.equals(MepinConstants.FAILED)) {
                JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                String mepinId = responseJson.getAsJsonPrimitive(MepinConstants.MEPIN_ID).getAsString();
                String idpName = context.getExternalIdP().getIdPName();
                String authenticatedLocalUsername = getLocalAuthenticatedUser(context).getUserName();
                String associatedMepinID = getMepinIdAssociatedWithUsername(idpName, authenticatedLocalUsername, context);
                if (StringUtils.isEmpty(associatedMepinID)) {
                    associateFederatedIdToLocalUsername(username, context,
                            getFederateAuthenticatedUser(mepinId));
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                } else {
                    log.error("Trying to hack the mepinId " + mepinId + " of the " + username
                            + " User with the mepinId " + associatedMepinID);
                    return;
                }
            } else {
                throw new AuthenticationFailedException("Unable to get the MePIN ID.");
            }
        } catch (ApplicationAuthenticatorException e) {
            throw new AuthenticationFailedException("Unable to set the subject", e);
        } catch (UserProfileException e) {
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
                        MepinConstants.MEPIN_GET_TRANSACTION_URL, transactionId,
                        authenticatorProperties.get(MepinConstants.MEPIN_CLIENT_ID),
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
     * Process mepin login flow.
     *
     * @param context  the authentication context
     * @param username the user name
     * @throws AuthenticationFailedException
     */
    protected void processLoginWithMepin(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                         String username) throws AuthenticationFailedException {
        try {
            String idpName = context.getExternalIdP().getIdPName();
            String mePinId;
            mePinId = getMepinIdAssociatedWithUsername(idpName, username, context);
            if (StringUtils.isEmpty(mePinId)) {
                log.error("First, You need to Link with Mepin");
                return;
            }
            Boolean isAuthenticated = false;
            String transactionResponseString = new MepinTransactions().createTransaction(
                    mePinId, context.getContextIdentifier(),
                    MepinConstants.MEPIN_CREATE_TRANSACTION_URL,
                    authenticatorProperties.get(MepinConstants.MEPIN_USERNAME),
                    authenticatorProperties.get(MepinConstants.MEPIN_PASSWORD),
                    authenticatorProperties.get(MepinConstants.MEPIN_CLIENT_ID),
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
        } catch (UserProfileException e) {
            throw new AuthenticationFailedException("Unable to get the associated user ", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Unable to create the MePIN transaction ", e);
        }
    }

    /**
     * Process the response of the MePIN end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        String password;
        boolean isAuthenticated;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if ((!StringUtils.isEmpty(request.getParameter(MepinConstants.IS_SECOND_STEP))
                && !StringUtils.isEmpty(request.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)))) {
            if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
                username = getLocalAuthenticatedUser(context).getUserName();
            } else {
                isAuthenticated = isAuthenticatedUser(request);
                if (!isAuthenticated) {
                    throw new AuthenticationFailedException("Authentication Failed: Invalid username or password");
                }
            }
            processAssociationFlow(request, authenticatorProperties, context, username);
        } else {
            if (request.getParameter(MepinConstants.IS_SECOND_STEP).equals(MepinConstants.TRUE)) {
                username = getLocalAuthenticatedUser(context).getUserName();
            } else {
                username = request.getParameter(MepinConstants.USERNAME);
                password = request.getParameter(MepinConstants.PASSWORD);
                boolean isBasicAuthenticated;
                UserStoreManager userStoreManager;
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                try {
                    userStoreManager = (UserStoreManager) MepinAuthenticatorServiceComponent.
                            getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
                    isBasicAuthenticated = userStoreManager.authenticate(
                            MultitenantUtils.getTenantAwareUsername(username), password);
                    if (!isBasicAuthenticated) {
                        throw new AuthenticationFailedException("Authentication Failed: Invalid username or password");
                    }
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Unable to get the user store manager ", e);
                }
            }
            processLoginWithMepin(context, authenticatorProperties, username);
        }
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
     * Get local authenticated user.
     *
     * @param context the authentication context
     * @return the authenticated user
     */
    private AuthenticatedUser getLocalAuthenticatedUser(AuthenticationContext context) {
        //Getting the last authenticated local user
        AuthenticatedUser authenticatedUser = null;
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser();
                break;
            }
        }

        return authenticatedUser;
    }

    /**
     * Get federated authenticator user.
     *
     * @param authenticatedUserId the authenticated user id
     * @return the authenticator user
     * @throws ApplicationAuthenticatorException
     */
    private AuthenticatedUser getFederateAuthenticatedUser(String authenticatedUserId)
            throws ApplicationAuthenticatorException {
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        if (authenticatedUser.getUserStoreDomain() == null) {
            authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
        }
        authenticatedUser.setUserName(authenticatedUserId);
        if (log.isDebugEnabled()) {
            log.debug("The authenticated subject identifier :" + authenticatedUser.getAuthenticatedSubjectIdentifier());
        }
        return authenticatedUser;
    }

    /**
     * Associate Federated Id with local user name.
     *
     * @param authenticatedLocalUsername the authenticated local user name
     * @param context                    the authentication context
     * @param authenticatedUser          the name of authenticatedUser
     * @throws UserProfileException
     */
    private void associateFederatedIdToLocalUsername(String authenticatedLocalUsername,
                                                     AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser)
            throws UserProfileException {
        StepConfig stepConfig;

        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            stepConfig = context.getSequenceConfig().getStepMap().get(i);
            for (int j = 0; j < stepConfig.getAuthenticatorList().size(); j++) {
                if (stepConfig.getAuthenticatorList().get(j).getName().equals(getName())) {
                    try {
                        String idpName;
                        String originalExternalIdpSubjectValueForThisStep =
                                authenticatedUser.getAuthenticatedSubjectIdentifier();
                        idpName = context.getExternalIdP().getIdPName();
                        stepConfig.setAuthenticatedIdP(idpName);
                        associateID(idpName,
                                originalExternalIdpSubjectValueForThisStep, authenticatedLocalUsername, context);
                        stepConfig.setAuthenticatedUser(authenticatedUser);
                        context.getSequenceConfig().getStepMap().put(i, stepConfig);
                    } catch (UserProfileException e) {
                        throw new UserProfileException("Unable to continue with the federated ID ("
                                + authenticatedUser.getAuthenticatedSubjectIdentifier() + "): ", e);
                    }
                    break;
                }
            }
        }
    }

    /**
     * Associate Mepin id with user name.
     *
     * @param idpID        the idp id
     * @param associatedID the associated id
     * @param userName     the user name
     * @param context      the authentication context
     * @throws UserProfileException
     */
    private void associateID(String idpID, String associatedID, String userName, AuthenticationContext context)
            throws UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql;
        String tenantDomain = context.getTenantDomain();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        String domainName = getDomainName(tenantAwareUsername);
        tenantAwareUsername = getUsernameWithoutDomain(tenantAwareUsername);
        try {
            sql = "INSERT INTO IDN_ASSOCIATED_ID (TENANT_ID, IDP_ID, IDP_USER_ID, DOMAIN_NAME, " +
                    "USER_NAME) VALUES " +
                    "(? , (SELECT ID FROM IDP WHERE NAME = ? AND TENANT_ID = ? ), ? , ?, ?)";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, associatedID);
            prepStmt.setString(5, domainName);
            prepStmt.setString(6, tenantAwareUsername);
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            throw new UserProfileException("Error occurred while persisting the federated user ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, (ResultSet) null, prepStmt);
        }
    }

    /**
     * Get Mepin Id associated user name.
     *
     * @param idpID    the idp id
     * @param username the user name
     * @param context  the authenticationContext
     * @return mepin id
     * @throws UserProfileException
     */
    public String getMepinIdAssociatedWithUsername(String idpID, String username, AuthenticationContext context)
            throws UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql;
        String mepinId;
        String tenantDomain = context.getTenantDomain();
        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            sql = "SELECT IDP_USER_ID  FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? AND IDP_ID = (SELECT ID " +
                    "FROM IDP WHERE NAME = ? AND TENANT_ID = ?) AND USER_NAME = ?";

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, username);

            resultSet = prepStmt.executeQuery();
            connection.commit();

            if (resultSet.next()) {
                mepinId = resultSet.getString(1);
                return mepinId;
            }
        } catch (SQLException e) {
            throw new UserProfileException("Error occurred while getting the associated MePIN ID", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return null;
    }
}