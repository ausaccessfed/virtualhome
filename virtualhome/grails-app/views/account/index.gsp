<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
    <r:require modules="pwmask" />
  </head>
  <body>

    <div class="row">
      <div id="description" class="span6">
        <h2 class="muted"><g:message code="views.aaf.vhr.account.index.title"/></h2>
        <g:message code="views.aaf.vhr.account.index.details"/>
        
      </div>

      <div id="loginform" class="span5 offset1">
        <g:render template="/loginform" />
      </div>
    </div>

  </body>
</html>
