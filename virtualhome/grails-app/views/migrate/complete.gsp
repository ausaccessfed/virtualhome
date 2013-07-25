<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <h2>Your password has been successfully changed</h2>
    <br>
    <div class="row">
      <div class="span3">
        <r:img dir="images" file="research.png" width="225px" height="247px" class="img-rounded"/>
      </div>
      <div class="span9">
        <p>
          From now on when you're logging into the AAF Virtual Home you'll need to <strong>use your new password</strong>.
        </p>
        <p>
          Thanks for undertaking this process for us. We won't need to bother you with it again.
        </p>

        <p>
          <g:if test="${session.getAttribute('aaf.vhr.LoginController.SSO_URL') != null}">
            <br><br>
            <g:link controller="login" action="index" class="btn btn-large btn-info"><i class="icon-white icon-globe"></i> Great! - Take me to my service</g:link>
            <br><small>You'll need to login first, <strong>be sure to use your new password!</strong>.</small>
          </g:if>
          <g:else>
            You can now access all your favourite services, thanks!.
          </g:else>
        </p>
      </div>
    </div>

  </body>
</html>
