<div class="well well-small">            
  <g:form action="login" method="post" class="form form-login form-validating">
    <h2><g:message code="templates.aaf.vhr.loginform.title"/></h2>

    <g:if test="${loginError}">
      <div class="alert alert-block alert-error login-error">
        <g:message code="templates.aaf.vhr.loginform.alert"/>
      </div>
    </g:if>

    <g:if test="${loginWarning}">
      <div class="alert alert-block alert-warning login-warning">
        <g:message code="templates.aaf.vhr.loginform.captcha-warning"/>
      </div>
    </g:if>

    <fieldset>
      <div class="control-group">
        <label class="control-label" for="username"><g:message code="label.username"/></label>
        <div class="controls">
          <input id="username" name="username" type="text" autofocus="autofocus" class="required"/>
        </div>
      </div>

      <div class="control-group">
        <label class="control-label" for="password"><g:message code="label.password"/></label>
        <div class="controls">
          <input id="password" name="password" type="password" class="required"/>
        </div>
      </div>
      
      <g:if test="${requiresChallenge}">
        <div class="control-group">
          <div class="controls">
            <recaptcha:ifEnabled>
              <recaptcha:recaptcha theme="white" class="required"/>
            </recaptcha:ifEnabled>
          </div>
        </div>
        <br>
      </g:if>

      <button type="submit" value="Login" class="btn btn-large btn-info"><g:message code="label.login"/></button>
    
    </fieldset>
  </g:form>

  <h4 class="muted"><g:message code="templates.aaf.vhr.loginform.help.howelse"/></h4>
  <ul class="muted">
    <li><g:message code="templates.aaf.vhr.loginform.help.myaccount"/></li>
    <li><g:link controller="lostPassword" action="start"><g:message code="templates.aaf.vhr.loginform.help.lostpwd"/></g:link></li> 
    <li><g:link controller="lostUsername" action="start"><g:message code="templates.aaf.vhr.loginform.help.lostusername"/></g:link></li>
    <li><g:message code="templates.aaf.vhr.loginform.help.guide"/></li>
    <li><a href="http://support.aaf.edu.au/entries/22539753-I-m-collaborating-with-an-Institution-how-do-I-get-access-to-an-AAF-VH-account-"><g:message code="templates.aaf.vhr.loginform.help.account"/></a></li>
  </ul>
</div>

<r:script type="text/javascript">
  $(function () {
    extend_media_queries();
    $("#username").focus();
  });

  $(window).resize(function() {
    extend_media_queries();
  });

  // IE[6|7|8] sucks, this helps us with responsive content cross browser
  // Also effectively turns off fluid grid for tablets
  function extend_media_queries() {
    if ($(window).width() > 980) {
      $("#loginform").removeClass('span12');
      $("#loginform").addClass('span5 offset1');
      $("#description").show();
    } else {
      $("#loginform").removeClass('span5 offset1');
      $("#description").hide();
      $("#loginform").addClass('span12');
    }
  };
</r:script>
