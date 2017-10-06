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
package org.wso2.carbon.identity.application.authenticator.mepin;

import com.sun.org.apache.xerces.internal.jaxp.SAXParserImpl;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.mepin.MepinAuthenticator;
import org.wso2.carbon.identity.authenticator.mepin.MepinConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.powermock.api.support.membermodification.MemberMatcher.constructor;

@PrepareForTest({FileBasedConfigurationBuilder.class, FederatedAuthenticatorUtil.class, FrameworkUtils.class,
        IdentityTenantUtil.class, MultitenantUtils.class, ConfigurationFacade.class})
public class MepinAuthenticatorTest {
    private MepinAuthenticator mepinAuthenticator;
    @Mock private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    @Mock private HttpServletRequest httpServletRequest;
    @Mock private HttpServletResponse httpServletResponse;
    @Mock private AuthenticationContext context;
    @Mock private MepinAuthenticator mockedMepinAuthenticator;
    @Mock private RealmService realmService;
    @Mock private UserRealm userRealm;
    @Mock private UserStoreManager userStoreManager;
    @Mock private UserStoreManager storeManager;
    @Mock private ConfigurationFacade configurationFacade;

    @Mock
    private SequenceConfig sequenceConfig;

    @Mock
    private Map<Integer, StepConfig> mockedMap;

    @Mock
    private StepConfig stepConfig;

    @Mock
    private AuthenticatorConfig authenticatorConfig;

    @Mock
    private ApplicationAuthenticator applicationAuthenticator;

    @Spy
    private AuthenticationContext mockedContext;

    @BeforeMethod
    public void setUp() {
        mepinAuthenticator = new MepinAuthenticator();
        initMocks(this);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(FrameworkUtils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(ConfigurationFacade.class);
    }

    /**
     * Test case for getMepinParameters() method.
     */
    @Test
    public void testGetMepinParameters() {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL, "mepinauthenticationendpoint/custom/mepin.jsp");
        mockGetMepinParametersMethod(authenticatorConfig);

        //test with empty parameters map.
        Assert.assertNull(MepinAuthenticator.getMepinParameters());

        //test with non-empty parameters map.
        authenticatorConfig.setParameterMap(parameters);
        Assert.assertEquals(MepinAuthenticator.getMepinParameters(), parameters);
    }

    /**
     * Method to mock the required methods of getMepinParameters().
     */
    private void mockGetMepinParametersMethod(AuthenticatorConfig authenticatorConfig) {
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(MepinConstants.AUTHENTICATOR_NAME))
                .thenReturn(authenticatorConfig);
    }

    /**
     * Test case for canHandle method for can handle case.
     */
    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandle() throws Exception {
        when(httpServletRequest.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)).thenReturn("213432");
        when(httpServletRequest.getParameter(MepinConstants.MEPIN_LOGIN)).thenReturn("true");
        Assert.assertEquals(mepinAuthenticator.canHandle(httpServletRequest), true);
    }

    /**
     * Test case for canHandle method for can not handle case.
     */
    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() throws Exception {
        when(httpServletRequest.getParameter(MepinConstants.MEPIN_ACCESSTOKEN)).thenReturn(null);
        when(httpServletRequest.getParameter(MepinConstants.MEPIN_LOGIN)).thenReturn(null);
        Assert.assertEquals(mepinAuthenticator.canHandle(httpServletRequest), false);
    }

    /**
     * Test case for getContextIdentifier() method.
     */
    @Test(description = "Test case for getContextIdentifier() method.")
    public void testGetContextIdentifier(){
        when(httpServletRequest.getParameter(FrameworkConstants.SESSION_DATA_KEY)).thenReturn("234567890");
        Assert.assertEquals(mepinAuthenticator.getContextIdentifier(httpServletRequest), "234567890");

        when(httpServletRequest.getParameter(anyString())).thenReturn(null);
        Assert.assertNull(mepinAuthenticator.getContextIdentifier(httpServletRequest));
    }

    /**
     * Test case for getFriendlyName() method.
     */
    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {
        Assert.assertEquals(mepinAuthenticator.getFriendlyName(),
                MepinConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    /**
     * Test case for getName() method.
     */
    @Test(description = "Test case for getName() method.")
    public void testGetName() {
        Assert.assertEquals(mepinAuthenticator.getName(), MepinConstants.AUTHENTICATOR_NAME);
    }

    /**
     * Test case for retryAuthenticationEnabled() method.
     */
    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() throws Exception {
        Assert.assertEquals(Whitebox.invokeMethod(mepinAuthenticator, "retryAuthenticationEnabled"), true);
    }

    /**
     * Test case for process() method with logout request.
     */
    @Test(description = "Test case for successful logout request.")
    public void testProcessLogoutRequest() throws Exception {
        when(context.isLogoutRequest()).thenReturn(true);
        doReturn(true).when(mockedMepinAuthenticator).canHandle(httpServletRequest);
        AuthenticatorFlowStatus status = mepinAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    /**
     * Test case for process() method when authenticatedUser is null.
     */
    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcess() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        doReturn(true).when(mockedMepinAuthenticator).canHandle(httpServletRequest);
        authenticationContext.setTenantDomain(MepinConstants.SUPER_TENANT);
        authenticationContext.setProperty("username", MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty("authenticatedUser", null);
        doNothing().when(FederatedAuthenticatorUtil.class);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(authenticationContext);
        AuthenticatorFlowStatus status = mepinAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
    }

    /**
     * Test case for process() method when authenticatedUser is not null.
     */
    @Test
    public void testProcessWithAuthenticatedUser() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL, "mepinauthenticationendpoint/custom/mepin.jsp");
        authenticatorConfig.setParameterMap(parameters);
        doReturn(true).when(mockedMepinAuthenticator).canHandle(httpServletRequest);
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setTenantDomain(MepinConstants.SUPER_TENANT);
        authenticationContext.setProperty(MepinConstants.USER_NAME, MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty(MepinConstants.AUTHENTICATED_USER, authenticatedUser);
        doNothing().when(FederatedAuthenticatorUtil.class);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(authenticationContext);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(),anyString()))
                .thenReturn(null);
        mockUserRealm();
        mockGetMepinParametersMethod(authenticatorConfig);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValue(MepinAuenticatorTestConstants.USER_NAME,
                MepinConstants.MEPIN_ID_CLAIM, null)).thenReturn(MepinAuenticatorTestConstants.MEPIN_ID);
        AuthenticatorFlowStatus status = mepinAuthenticator.process(httpServletRequest, httpServletResponse,
                authenticationContext);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    private void mockUserRealm() throws UserStoreException {
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MepinAuenticatorTestConstants.TENANT_ID);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn(MepinConstants.SUPER_TENANT);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
    }

    /**
     * Test for getMepinPageFromXMLFile() method for tenant user.
     */
    @Test
    public void testGetMepinPageFromXMLFileForTenant() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL, "mepinpauthenticationendpoint/custom/mepin.jsp");
        authenticatorConfig.setParameterMap(parameters);
        authenticationContext.setTenantDomain(MepinAuenticatorTestConstants.TENANT_DOMAIN);
        authenticationContext.setProperty(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL, MepinConstants.MEPIN_PAGE);
        mockGetMepinParametersMethod(authenticatorConfig);
        Assert.assertEquals(Whitebox.invokeMethod(mepinAuthenticator, "getMepinPageFromXMLFile",
                authenticationContext), MepinConstants.MEPIN_PAGE);
    }

    /**
     * Test for getURL() method.
     */
    @Test
    public void testGetURL() throws Exception {
        //with empty queryParams
        String queryParams = "";
        String baseURI = MepinConstants.MEPIN_PAGE;
        Assert.assertEquals(Whitebox.invokeMethod(mepinAuthenticator, "getURL", baseURI, queryParams),
                baseURI + "?" + MepinConstants.NAME_OF_AUTHENTICATORS + MepinConstants.AUTHENTICATOR_NAME);

        //with queryParams
        queryParams = "send=true";
        Assert.assertEquals(Whitebox.invokeMethod(mepinAuthenticator, "getURL", baseURI, queryParams),
                baseURI + "?" + queryParams + "&" + MepinConstants.NAME_OF_AUTHENTICATORS
                        + MepinConstants.AUTHENTICATOR_NAME);
    }


    /**
     * Test for redirectToErrorPage() method.
     */
    @Test
    public void testRedirectToErrorPage() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL, MepinConstants.ERROR_PAGE);
        authenticatorConfig.setParameterMap(parameters);
        authenticationContext.setTenantDomain(MepinConstants.SUPER_TENANT);
        //with empty queryParams
        String queryParams = "";
        String retryParam = null;
        String baseURI = MepinConstants.ERROR_PAGE;
        mockGetMepinParametersMethod(authenticatorConfig);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(mepinAuthenticator, "redirectToErrorPage",
                httpServletResponse, authenticationContext, queryParams, MepinConstants.ERROR_MEPIN_DISABLE);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(MepinConstants.AUTHENTICATOR_NAME));
    }

    /**
     * Test case for processMepinFlow() method when Mepin authentication enabled by admin and disabled by user.
     */
    @Test
    public void testProcessMepinFlow() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        mockUserRealm();
        authenticationContext.setTenantDomain(MepinAuenticatorTestConstants.TENANT_DOMAIN);
        authenticationContext.setProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER, "true");
        authenticationContext.setProperty(MepinConstants.IS_MEPIN_MANDATORY, "true");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(MepinConstants.LOGIN_PAGE);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MepinAuenticatorTestConstants.TENANT_ID);
        when(userRealm.getUserStoreManager()).thenReturn(storeManager);
        when(storeManager.getUserClaimValue("admin",
                MepinConstants.USER_MEPIN_DISABLED_CLAIM_URI, null)).thenReturn("true");
        when(MultitenantUtils.getTenantAwareUsername(MepinAuenticatorTestConstants.USER_NAME))
                .thenReturn(MepinAuenticatorTestConstants.USER_NAME);
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty(MepinConstants.USER_NAME, MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty(MepinConstants.AUTHENTICATED_USER, authenticatedUser);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(mepinAuthenticator, "processMepinFlow", authenticationContext,
                "admin", new HashMap<>(), authenticatedUser, httpServletResponse, "send=true");
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(MepinConstants.AUTHENTICATOR_NAME));
    }

    /**
     * Test case for processFirstStepOnly() method.
     */
    @Test
    public void testProcessFirstStepOnly() throws Exception {
        when(mockedContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(MepinAuenticatorTestConstants.USER_NAME);
        mockedContext.setProperty(MepinConstants.USER_NAME, MepinAuenticatorTestConstants.USER_NAME);
        mockedContext.setProperty(MepinConstants.AUTHENTICATED_USER, authenticatedUser);
        Whitebox.invokeMethod(mepinAuthenticator, "processFirstStepOnly", authenticatedUser,
                mockedContext);
        Assert.assertEquals(mockedContext.getProperty(MepinConstants.AUTHENTICATION),
                MepinConstants.FEDERETOR);
    }

    /**
     * Test case for processMepinFlow() method when Mepin authentication enabled by admin and disabled by user.
     */
    @Test
    public void testProcessMepinFlowFlow() throws Exception {
        AuthenticationContext authenticationContext = new AuthenticationContext();
        mockUserRealm();
        authenticationContext.setTenantDomain(MepinAuenticatorTestConstants.TENANT_DOMAIN);
        authenticationContext.setProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER, "true");
        authenticationContext.setProperty(MepinConstants.IS_MEPIN_MANDATORY, "true");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(MepinConstants.LOGIN_PAGE);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MepinAuenticatorTestConstants.TENANT_ID);
        when(userRealm.getUserStoreManager()).thenReturn(storeManager);
        when(storeManager.getUserClaimValue("admin",
                MepinConstants.USER_MEPIN_DISABLED_CLAIM_URI, null)).thenReturn("true");
        when(MultitenantUtils.getTenantAwareUsername(MepinAuenticatorTestConstants.USER_NAME))
                .thenReturn(MepinAuenticatorTestConstants.USER_NAME);
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createLocalAuthenticatedUserFromSubjectIdentifier(MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty(MepinConstants.USER_NAME, MepinAuenticatorTestConstants.USER_NAME);
        authenticationContext.setProperty(MepinConstants.AUTHENTICATED_USER, authenticatedUser);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(mepinAuthenticator, "processMepinFlow", authenticationContext,
                "admin", new HashMap<>(), authenticatedUser, httpServletResponse, "send=true");
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(MepinConstants.AUTHENTICATOR_NAME));
    }

    @Test
    public void testIsMepinDisableForUser() throws Exception {
        mockUserRealm();
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(MepinAuenticatorTestConstants.TENANT_DOMAIN);
        authenticationContext.setProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER, "true");
        when(userRealm.getUserStoreManager()).thenReturn(storeManager);
        when(storeManager.getUserClaimValue("admin",
                MepinConstants.USER_MEPIN_DISABLED_CLAIM_URI, null)).thenReturn("false");
        when(MultitenantUtils.getTenantAwareUsername(MepinAuenticatorTestConstants.USER_NAME))
                .thenReturn(MepinAuenticatorTestConstants.USER_NAME);
        Assert.assertEquals(Whitebox.invokeMethod(mepinAuthenticator, "isMepinDisableForUser",
                "admin", authenticationContext), false);
    }

    @Test
    public void testGetConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
        Property applicationId = new Property();
        configProperties.add(applicationId);
        Property username = new Property();
        configProperties.add(username);
        Property password = new Property();
        configProperties.add(password);
        Property callbackUrl = new Property();
        configProperties.add(callbackUrl);
        Property clientId = new Property();
        configProperties.add(clientId);
        Property confirmationPolicy = new Property();
        configProperties.add(confirmationPolicy);
        Property expiryTime = new Property();
        configProperties.add(expiryTime);
        Property header = new Property();
        configProperties.add(header);
        Property message = new Property();
        configProperties.add(message);
        Property shortMessage = new Property();
        configProperties.add(shortMessage);
        Assert.assertEquals(configProperties.size(), mepinAuthenticator.getConfigurationProperties().size());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

}
