<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <h2>Hello! <small>To reset your forgotten password please provide your username and challenge answer below</small></h2>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>

    <g:form action="obtainsubject" class="form-horizontal form-validating myaccount">
      <div class="control-group">
        <label class="control-label" for="login">Username</label>
        <div class="controls">
          <div class="span5">
            <input class="required span4" name="login" id="login" type="text" autofocus="autofocus" autocomplete="off" value="${login}">
          </div>
          <div class="span4">
            <span class="help-block">
              <p>Please enter the username you selected when setting up your account.</p>
            </span>
          </div>
        </div>
      </div>

      <hr>

      <div class="control-group">
        <label class="control-label" for="plainPassword">Challenge Question</label><br>
        <div class="controls">
          <div class="span5">
            <recaptcha:ifEnabled>
              <recaptcha:recaptcha theme="white"/>
            </recaptcha:ifEnabled>
          </div>
          <div class="span4">
            <span class="help-block">
              <p>Please enter the two words shown at the left so we can ensure you're a real person and not an automated bot.</p>
            </span>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <g:if test="${params.restartprocess}">
          <g:checkBox name="resetcodes" value="${true}" /> Please <strong>reset my security codes</strong> as I've lost them <br/><br/>
        </g:if>
        <button type="submit" class="btn btn-info btn-large">Next</button>
        <g:link controller="dashboard" action="welcome" class="btn btn-large"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>

  </body>
</html>
