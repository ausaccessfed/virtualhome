<div class="container">  
  <div class="row">
    <div class="span12">
      <r:img dir='images' file='logo.jpg' plugin="aafApplicationBase" alt="${message(code:'branding.application.name')}" width="102" height="50" />
      <h1><g:message encodeAs='HTML' code='branding.application.name' /></h1> 
      <g:if test="${grailsApplication.config.aaf.base.deployment_environment == 'test'}">
        <h2><g:message encodeAs='HTML' code="branding.application.testfederation.name"/></h2>
      </g:if>
      <g:if test="${grailsApplication.config.aaf.base.deployment_environment == 'development'}">
        <h2><g:message encodeAs='HTML' code="branding.application.development.name"/></h2>
      </g:if>
    </div>
  </div>
</div>
