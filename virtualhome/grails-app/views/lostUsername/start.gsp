<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount"/>
  </head>
  <body>
    <h2>Hello! <small>To retrieve your username, please provide your email address below</small></h2>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>

    <hr>

    <g:form action="send" class="form-horizontal form-validating myaccount">
      <div class="control-group">
        <label class="control-label" for="email">Email</label>
        <div class="controls">
          <div class="span5">
            <input class="required email span4" name="email" id="email" type="text" autofocus="autofocus" autocomplete="off" value="${email}"/>
          </div>
          <div class="span4">
            <span class="help-block">
              <p>Please enter the email address associated with your AAF Virtual Home account.</p>
            </span>
          </div>
        </div>
      </div>

      <div class="control-group">
        <div class="controls">
          <div class="span5">
            <recaptcha:ifEnabled>
              <recaptcha:recaptcha theme="white"/>
            </recaptcha:ifEnabled>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button type="submit" class="btn btn-info btn-large">Retrieve</button>
        <g:link controller="dashboard" action="welcome" class="btn btn-large"><g:message encodeAs="HTML" code="label.cancel"/></g:link>
      </div>
    </g:form>
  </body>
</html>
