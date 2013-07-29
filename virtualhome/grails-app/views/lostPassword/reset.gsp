<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
    <r:require modules="pwmask" />
  </head>
  <body>
    <h2>Password reset for <g:fieldValue bean="${managedSubjectInstance}" field="cn"/></h2>

    <div class="row">
      <div class="span12">
        <g:if test="${allowResend}">
          <p>
            <g:message code="views.aaf.vhr.lostpassword.reset.resend.info"/>
            <g:link action="resend"><g:message code="views.aaf.vhr.lostpassword.reset.resend.link" encodeAs="HTML"/></g:link>
          </p>
        </g:if>
      </div>
    </div>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <hr>

    <g:form action="validatereset" class="form-horizontal myaccount" name="accountform" id="accountform">

        <div class="control-group">
          <label class="control-label" for="resetCode">Email Code</label>
          <div class="controls">
            <div class="span5">
              <input class="required" name="resetCode" id="resetCode" type="text" autofocus="autofocus" autocomplete="off">
            </div>
            <div class="span4">
              <span class="help-block">
                <p>This code was just sent to your email address <strong><g:fieldValue bean="${managedSubjectInstance}" field="email"/>.</strong></p>
                <p>It is case sensitive.</p>
              </span>
            </div>
          </div>
        </div>
        <g:if test="${grailsApplication.config.aaf.vhr.passwordreset.second_factor_required}">
          <hr>
          <g:if test="${managedSubjectInstance.mobileNumber}">
            <div class="control-group">
              <label class="control-label" for="resetCodeExternal">SMS Code</label>
              <div class="controls">
                <div class="span5">
                  <input class="required" name="resetCodeExternal" id="resetCodeExternal" type="text" autocomplete="off">
                </div>
                <div class="span4">
                  <span class="help-block">
                    <p>This code was sent to your mobile number ending in <strong>${managedSubjectInstance?.mobileNumber.drop(managedSubjectInstance?.mobileNumber.size() - 3)}.</strong></p>
                    <p>Please check your phone and input the supplied code. It is case sensitive.</p>
                    <p>Can't access your phone? <a href="#admincontacts" role="button" data-toggle="modal">Contact your account administrators to provide it for you.</a></p>
                  </span>
                </div>
              </div>
            </div>
          </g:if>
          <g:else>
            <div class="control-group">
              <label class="control-label" for="resetCodeExternal">Administrator Code</label>
              <div class="controls">
                <div class="span5">
                  <input class="required" name="resetCodeExternal" id="resetCodeExternal" type="text" autofocus="autofocus" autocomplete="off">
                </div>
                <div class="span4">
                  <span class="help-block">
                    <p>As your account doesn't have a mobile phone number associated with it you'll need to <a href="#admincontacts" role="button" data-toggle="modal">contact your account administrator <strong>as shown here</strong></a> and <strong>ask for a unique code</strong> to continue this process.</p>
                    <p>You might like to provide your mobile number to automate this process in the future. We <strong>only use</strong> your mobile number to assist in ensuring security if you forget your password and need to reset it.</p>
                    <p>Your account administrator can update your mobile number for you.</p>
                  </span>
                </div>
              </div>
            </div>
          </g:else>
        </g:if>
      <hr>

      <g:render template="/templates/passwordinput"/>

      <div class="form-actions">
        <button type="submit" class="btn btn-success btn-large">Reset Password</button>
        <g:link controller="dashboard" action="welcome" class="btn btn-large"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>

    <div id="admincontacts" class="modal hide" tabindex="-1" role="dialog" aria-hidden="true">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h4 id="myModalLabel">Account Administrators for <g:fieldValue bean="${managedSubjectInstance}" field="cn"/></h4>
      </div>
      <div class="modal-body">
        <g:render template="/templates/accountadministrators"/>
      </div>
      <div class="modal-footer">
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
      </div>
    </div>



  </body>
</html>
