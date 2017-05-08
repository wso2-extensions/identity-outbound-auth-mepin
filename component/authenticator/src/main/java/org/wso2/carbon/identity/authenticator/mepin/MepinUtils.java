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
    public static boolean isMepinDisableForLocalUser(String username, AuthenticationContext context)
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
    public static boolean isMepinMandatory(AuthenticationContext context) {
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
    public static boolean isMepinDisableByUser(AuthenticationContext context) {
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
    public static String getErrorPageFromXMLFile(AuthenticationContext context) {
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
    public static String getMepinPageFromXMLFile(AuthenticationContext context) {
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