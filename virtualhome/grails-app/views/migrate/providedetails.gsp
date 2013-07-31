<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
    <r:require modules="pwmask" />
  </head>
  <body>
    <h2>Initial password setup for <g:fieldValue bean="${managedSubjectInstance}" field="cn"/> <small>Please provide the information requested below</small></h2>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <g:form useToken="true" action="validate" class="form-horizontal myaccount form-validating" name="accountform">
      <div class="control-group">
        <label class="control-label" for="login">Username</label>
        <div class="controls">
          <div class="span5">
            <input class="required span5" name="login" id="login" type="text" autofocus="autofocus" autocomplete="off" value="${managedSubjectInstance.login}" disabled="true">
          </div>
        </div>
      </div>

      <div class="control-group">
        <label class="control-label" for="currentPassword">Current Password</label>
        <div class="controls">
          <div class="span5">
            <input class="span5 required" name="currentPassword" id="currentPassword" type="password" autocomplete="off">
          </div>
          <div class="span4">
            <span class="help-block">Please provide the password you're currently using with the AAF Virtual Home so we can validate your previous account details.</span>
          </div>
        </div>
      </div>

      <g:if test="${requiresChallenge}">
        <div class="control-group">
          <label class="control-label" for="password">Challenge Response</label>
          <div class="controls">
            <div class="span5">
              <recaptcha:ifEnabled>
                <recaptcha:recaptcha theme="white" class="required"/>
              </recaptcha:ifEnabled>
            </div>
            <div class="span4">
              <p>
                Due to repeated errors please provide the above
                challenge response answers <strong>in addition to your username and password</strong>.
              </p>
            </div>
          </div>
        </div>
      </g:if>
      
      <hr>

      <g:render template="/templates/passwordinput" model="[newPasswordRequired: true]"/>

      <div class="control-group">
          <label class="control-label" for="plainPasswordConfirmation">Mobile Number</label>
          <div class="controls">
            <div class="span5">
              <input class="span5" name="mobileNumber" type="text" autocomplete="off" value="${managedSubjectInstance.mobileNumber}">
            </div>
            <div class="span4">
              <div class="help-block">
                <p>Please provide your mobile number.</p>
                <p>We <strong>only use</strong> your mobile number to assist in ensuring security if you forget your password and need to reset it.</p>
                <p>International numbers are supported. If you're located outside Australia please be sure to add your <a href="http://en.wikipedia.org/wiki/List_of_mobile_phone_number_series_by_country" target="_blank">international prefix</a> to the start of your number.
                <p>An example of an internationally formatted mobile number is <strong>+1 555 555 5555</strong> which is valid for numbers in the United States. All international numbers are in the format <em>+[code] [number]</em>.</p>
                <p>If you elect not to supply your mobile number and forget your password you'll need to contact administrators directly which may take some time to complete preventing your access to AAF connected services in the interim.</p>
              </div>
            </div>
          </div>
        </div>

      <div class="form-actions">
        <button type="submit" class="btn btn-success btn-large">Set Password</button>
        <g:link controller="dashboard" action="welcome" class="btn btn-large"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>

  </body>
</html>
