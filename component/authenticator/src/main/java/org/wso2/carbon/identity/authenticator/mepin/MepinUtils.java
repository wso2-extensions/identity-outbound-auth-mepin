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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.authenticator.mepin.exception.MepinException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

/**
 * Mepin Authenticator Utils.
 */
public class MepinUtils {

    private static Log log = LogFactory.getLog(MepinUtils.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getMepinParameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(MepinConstants.AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }

    /**
     * Check whether Mepin is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     * @throws MepinException
     */
    public static boolean isMepinDisableForLocalUser(String username, AuthenticationContext context,
                                                     String authenticatorName) throws MepinException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            boolean isEnableORDisableLocalUserClaim = isMepinEnableOrDisableByUser(context, authenticatorName);
            if (userRealm != null) {
                if (isEnableORDisableLocalUserClaim) {
                    String isMepinEnabledByUser = userRealm.getUserStoreManager().getUserClaimValue(username,
                            MepinConstants.USER_MEPIN_DISABLED_CLAIM_URI, null);
                    return Boolean.parseBoolean(isMepinEnabledByUser);
                }
            } else {
                throw new MepinException("Cannot find the user realm for the given tenant domain : " + CarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new MepinException("Failed while trying to access userRealm of the user : " + username, e);
        }
        return false;
    }

    /**
     * Check whether Mepin is mandatory or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     */
    public static boolean isMepinMandatory(AuthenticationContext context, String authenticatorName) {
        Object propertiesFromLocal = null;
        boolean isMepinMandatory = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.IS_MEPIN_MANDATORY)) {
            isMepinMandatory = Boolean.parseBoolean(getMepinParameters().get(MepinConstants.IS_MEPIN_MANDATORY));
        } else if ((context.getProperty(MepinConstants.IS_MEPIN_MANDATORY)) != null) {
            isMepinMandatory = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(MepinConstants.IS_MEPIN_MANDATORY)));
        }
        return isMepinMandatory;
    }

    /**
     * Check whether user enable the second factor or not.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return true or false
     */
    public static boolean isMepinEnableOrDisableByUser(AuthenticationContext context, String authenticatorName) {
        Object propertiesFromLocal = null;
        boolean isMepinEnableByUser = false;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.IS_MEPIN_ENABLE_BY_USER)) {
            isMepinEnableByUser = Boolean.parseBoolean(getMepinParameters().get(MepinConstants.IS_MEPIN_ENABLE_BY_USER));
        } else if ((context.getProperty(MepinConstants.IS_MEPIN_ENABLE_BY_USER)) != null) {
            isMepinEnableByUser = Boolean.parseBoolean(String.valueOf(context.getProperty
                    (MepinConstants.IS_MEPIN_ENABLE_BY_USER)));
        }
        return isMepinEnableByUser;
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context           the AuthenticationContext
     * @param authenticatorName the name of the authenticator
     * @return errorPage
     */
    public static String getErrorPageFromXMLFile(AuthenticationContext context, String authenticatorName) {
        Object propertiesFromLocal = null;
        String errorPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = getMepinParameters().get(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String.valueOf(context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ERROR_PAGE_URL));
        }
        return errorPage;
    }

    /**
     * Get the login page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return loginPage
     */
    public static String getLoginPageFromXMLFile(AuthenticationContext context) {
        Object propertiesFromLocal = null;
        String loginPage = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(MepinConstants.SUPER_TENANT)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || tenantDomain.equals(MepinConstants.SUPER_TENANT)) &&
                getMepinParameters().containsKey(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = getMepinParameters().get(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String.valueOf(context.getProperty(MepinConstants.MEPIN_AUTHENTICATION_ENDPOINT_URL));
        }
        return loginPage;
    }
}