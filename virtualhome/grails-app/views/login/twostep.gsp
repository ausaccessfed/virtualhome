<!doctype html>
<html>
  <head>
    <meta name="layout" content="login" />
  </head>
  <body>

      <div class="row">
        <div class="span12">
          <div class="well well-small">
            <g:form action="twosteplogin" id="${managedSubjectInstance.id}" method="post" class="form form-login form-validating">
              <h2><g:message code="templates.aaf.vhr.loginform.twostep.title"/></h2>

              <g:if test="${loginError}">
                <div class="alert alert-block alert-error login-error">
                  <g:message code="templates.aaf.vhr.loginform.twostep.alert"/>
                </div>
              </g:if>

              <p>Please enter the current 2-Step verification code for your account. This is available from the device which you have previously set up.</p>

              <fieldset>
                <div class="control-group">
                  <label class="control-label" for="totp"><g:message code="label.2stepcode"/></label>
                  <div class="controls">
                    <input id="totp" name="totp" type="text" autofocus="autofocus" class="required" autocomplete="off"/>
                  </div>
                </div>

                <button type="submit" value="Login" class="btn btn-large btn-info"><g:message code="label.login"/></button>
              </fieldset>
            </g:form>
          </div>
        </div>
      </div>
  </body>
</html>
