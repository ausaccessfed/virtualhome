<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <div class="row">
      <div class="span12">
        <h2>Hello <g:fieldValue bean="${managedSubjectInstance}" field="cn"/></h2>
        <h3 class="muted">There is an important change required for your account</h3>
      </div>
    </div>

    <div class="row">
      <div class="span12">
        <p>The Virtual Home now supports 2-Step verification and the <strong>administrators of your account</strong> have made it mandatory for you to secure your account using this process before you can continue to access AAF connected services.</p>

        <g:render template="appdetails" />

        <p><g:link action="completesetuptwostep" id="${managedSubjectInstance.id}" class="btn btn-large btn-warning">Enable two-step login</g:link></p>
      </div>
    </div>

    <hr>

    <h3 class="muted">Getting Help</h3>
    <p>If you have any queries about this change to your account please contact one of the administrators shown below.</p>
    <g:render template="/templates/accountadministrators"/>

  </body>
</html>
