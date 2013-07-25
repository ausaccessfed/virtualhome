<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <div class="alert alert-error">
      <h1>Account locked</h1>
      <p>The account for <strong>${managedSubjectInstance.login}</strong> has been locked due to abuse or by administrator action.</p>
    </div>

    <h3>Unlocking your account</h3>
    <p>The following administrators will be able to assist in unlocking your account, please contact them directly.</p>
    <p><g:render template="/templates/accountadministrators"/></p>

  </body>
</html>
