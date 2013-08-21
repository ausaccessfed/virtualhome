<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <div class="alert alert-error">
      <h1><g:message code="views.aaf.vhr.lostpassword.support.alert.heading" encodeAs="HTML"/></h1>
      <g:message code="views.aaf.vhr.lostpassword.support.alert.message" args="${[managedSubjectInstance.login.encodeAsHTML()]}"/>
    </div>

    <h3><g:message code="views.aaf.vhr.lostpassword.support.action.heading" encodeAs="HTML"/></h3>
    <p><g:message code="views.aaf.vhr.lostpassword.support.action.message" encodeAs="HTML"/></p>
    <p><g:render template="/templates/accountadministrators"/></p>

  </body>
</html>
