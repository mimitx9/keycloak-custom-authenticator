<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=social.displayInfo; section>
    <#if section = "title">
        ${msg("loginTitle",(realm.displayName!''))}
    <#elseif section = "header">
        <div class="custom-header">
            <h2>Đăng nhập</h2>
        </div>
    <#elseif section = "form">
        <#if realm.password>
            <form id="kc-form-login" class="custom-form" action="${url.loginAction}" method="post">
                <div class="form-group">
                    <label for="username">${msg("username")}</label>
                    <input id="username" class="form-control" name="username" value="${(login.username!'')}" type="text" autofocus autocomplete="off" />
                </div>

                <div class="form-group">
                    <label for="password">${msg("password")}</label>
                    <input id="password" class="form-control" name="password" type="password" autocomplete="off" />
                </div>

                <div class="form-options">
                    <#if realm.rememberMe && !usernameEditDisabled??>
                        <div class="checkbox">
                            <label>
                                <#if login.rememberMe??>
                                    <input id="rememberMe" name="rememberMe" type="checkbox" checked> ${msg("rememberMe")}
                                <#else>
                                    <input id="rememberMe" name="rememberMe" type="checkbox"> ${msg("rememberMe")}
                                </#if>
                            </label>
                        </div>
                    </#if>
                    <#if realm.resetPasswordAllowed>
                        <div class="forgot-password">
                            <a href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
                        </div>
                    </#if>
                </div>

                <div class="form-buttons">
                    <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                    <input class="btn btn-primary" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                </div>
            </form>
        </#if>
    <#elseif section = "info">
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div class="register-link">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>