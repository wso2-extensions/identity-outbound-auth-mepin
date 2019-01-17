/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.mepin.model;

import java.io.Serializable;

/**
 * MePin transaction data object to populate the MePin transaction request payload.
 */
public class MepinTransaction implements Serializable {
    //Mandatory fields
    private String action;
    private String app_id;
    private String identifier;
    private String mepin_id;
    private String short_message;
    private String header;
    private String message;
    private String confirmation_policy;
    //Optional fields
    private String callback_url;
    private String u2f_user_id;
    private String oath_user_id;
    private String logo_url;
    private String sp_name;
    private String bg_image_url;
    private String sp_icon;
    private String expiry_time;
    //get transaction fields
    private String transaction_id;

    /**
     * Returns the action string related to transactions.
     *
     * @return
     */
    public String getAction() {
        return action;
    }

    /**
     * Sets the action string related to transactions (i.e : transactions/create).
     *
     * @param action
     */
    public void setAction(String action ) {
        this.action = action;
    }

    /**
     * Returns service provider's pre-shared Application specific identifier.
     *
     * @return app identifier
     */
    public String getApp_id() {
        return app_id;
    }

    /**
     * Sets service provider's pre-shared Application specific identifier
     *
     * @param app_id mepin app id
     */
    public void setApp_id(String app_id) {
        this.app_id = app_id;
    }

    /**
     * Returns Service Provider's identifier for the transaction.
     *
     * @return sp identifier
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Sets service provider identifier
     *
     * @param identifier sp identifier
     */
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns End user's pseudonym identifier
     *
     * @return mepin identifier
     */
    public String getMepin_id() {
        return mepin_id;
    }

    /**
     * Sets End user's pseudonym identifier
     *
     * @param mepin_id mepin identifier
     */
    public void setMepin_id(String mepin_id) {
        this.mepin_id = mepin_id;
    }

    /**
     * Returns message to be shown as push notification
     *
     * @return
     */
    public String getShort_message() {
        return short_message;
    }

    /**
     * Sets message to be shown as push notification
     *
     * @param short_message
     */
    public void setShort_message(String short_message) {
        this.short_message = short_message;
    }

    /**
     * Returns caption of the transaction
     *
     * @return
     */
    public String getHeader() {
        return header;
    }

    /**
     * Sets caption of the transaction
     *
     * @param header
     */
    public void setHeader(String header) {
        this.header = header;
    }

    /**
     * Returns description of the transaction
     *
     * @return
     */
    public String getMessage() {
        return message;
    }

    /**
     * Sets the description of the transaction
     *
     * @param message
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Returns the required method for transaction confirmation
     *
     * @return
     */
    public String getConfirmation_policy() {
        return confirmation_policy;
    }

    /**
     * Sets Required method for transaction confirmation
     * ( i.e : mepin/mepin_totp/mepin_tap/mepin_swipe/mepin_pin/mepin_fp/u2f/uaf/otp/sms/oath_ocra)
     *
     * @param confirmation_policy
     */
    public void setConfirmation_policy(String confirmation_policy) {
        this.confirmation_policy = confirmation_policy;
    }

    public String getCallback_url() {
        return callback_url;
    }

    public void setCallback_url(String callback_url) {
        this.callback_url = callback_url;
    }

    public String getU2f_user_id() {
        return u2f_user_id;
    }

    public void setU2f_user_id(String u2f_user_id) {
        this.u2f_user_id = u2f_user_id;
    }

    public String getOath_user_id() {
        return oath_user_id;
    }

    public void setOath_user_id(String oath_user_id) {
        this.oath_user_id = oath_user_id;
    }

    public String getLogo_url() {
        return logo_url;
    }

    public void setLogo_url(String logo_url) {
        this.logo_url = logo_url;
    }

    public String getSp_name() {
        return sp_name;
    }

    public void setSp_name(String sp_name) {
        this.sp_name = sp_name;
    }

    public String getBg_image_url() {
        return bg_image_url;
    }

    public void setBg_image_url(String bg_image_url) {
        this.bg_image_url = bg_image_url;
    }

    public String getSp_icon() {
        return sp_icon;
    }

    public void setSp_icon(String sp_icon) {
        this.sp_icon = sp_icon;
    }

    public String getExpiry_time() {
        return expiry_time;
    }

    public void setExpiry_time(String expiry_time) {
        this.expiry_time = expiry_time;
    }

    public String getTransaction_id() {
        return transaction_id;
    }

    public void setTransaction_id(String transaction_id) {
        this.transaction_id = transaction_id;
    }
}
