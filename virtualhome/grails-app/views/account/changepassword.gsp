<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
    <r:require modules="pwmask" />
  </head>
  <body>

    <h2><g:message code='views.aaf.vhr.account.changepassword.hello' args="${[managedSubjectInstance.cn.encodeAsHTML()]}"/></h2>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <g:form action="completepasswordchange" class="form-horizontal myaccount form-validating" name="accountform">
      <div class="control-group">
        <label class="control-label" for="login"><g:message code="label.username"/></label>
        <div class="controls">
          <div class="span5">
            <input class="required span5" name="login" id="login" type="text" autofocus="autofocus" autocomplete="off" value="${managedSubjectInstance.login}" disabled="true">
          </div>
        </div>
      </div>

      <hr>

      <div class="control-group">
        <label class="control-label" for="currentPassword"><g:message code="label.currentpassword"/></label>
        <div class="controls">
          <div class="span5">
            <input class="span5 required" id="currentPassword" name="currentPassword" type="password" autocomplete="off">
          </div>
          <div class="span4">
            <span class="help-block">
              <p><g:message code="views.aaf.vhr.account.changepassword.currentpassword.help"/></p>
            </span>
          </div>
        </div>
      </div>

      <hr>

      <g:render template="/templates/passwordinput"/>

      <div class="form-actions">
        <p class="text-muted"><i class="icon-info-sign"></i> <g:message code="views.aaf.vhr.account.changepassword.crypto"/></p>
        <button type="submit" class="btn btn-success btn-large"><g:message code="label.changepassword"/></button>
        <g:link action="show" class="btn btn-large"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>

  </body>
</html>
