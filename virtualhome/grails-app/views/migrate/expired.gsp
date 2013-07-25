<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <h2>Your password has been changed, but we've found a problem</h2>
    <br>
    <div class="row">
      <div class="span3">
        <r:img dir="images" file="research.png" width="225px" height="247px" class="img-rounded"/>
      </div>
      <div class="span9">
        <p>
          From now on when you're logging into the AAF Virtual Home you'll need to <strong>use your new password</strong>.
        </p>
        <div class="alert alert-error">
          <p>Unfortunately though we've found your <strong>account is expired</strong>.</p>
          <p>You'll need to get in touch with one of your account administrators shown below to re-enable your acount before you can use any services.</p>
        </div>
        <g:render template="/templates/accountadministrators"/>
      </div>
    </div>
      
  </body>
</html>
