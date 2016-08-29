/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

$(document).ready(function() {
    $('#link').click(function() {
    var authHeader = btoa(document.getElementById("username").value+":"+document.getElementById("password").value);
    var applicationId = document.getElementById("applicationId").value;
    var callbackUrl = document.getElementById("callbackUrl").value;
    var sessionDataKey = document.getElementById("sessionDataKey").value;
    var isSecondStep = document.getElementById("isSecondStep").value;
        if(username!="" && password!="") {
            $('#errorDiv').empty();
            $('#enrollmentTable').hide();
            $('#loginTable').html('<span style="font-family: Times New Roman, Times, serif; font-size: 20px; color: #006666;">To link with MePIN click </span><span class="mepin-link" data-theme="light" data-layout="standard" data-applicationid="'+applicationId+'" data-cburl="'+callbackUrl+'?sessionDataKey='+sessionDataKey+'&authHeader='+authHeader+'&isSecondStep='+isSecondStep+'"></span>');
        } else {
            $('#errorDiv').html('<div class="alert alert-danger" id="error-msg">Invalid username or password</div>');
        }
    });
});