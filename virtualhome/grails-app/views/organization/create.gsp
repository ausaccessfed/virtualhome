<html>
  <head>
    <meta name="layout" content="internal" />
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="list"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.organization"/></g:link> <span class="divider">/</span></li>
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.organization.create"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':organizationInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.organization.create.heading" /></h2>

    <div class="alert alert-block alert-info">
      <h4><g:message encodeAs='HTML' code="label.warning"/>!</h4>
      <p><g:message encodeAs='HTML' code="views.aaf.vhr.organization.create.warning"/></p>
    </div>
    
    <g:form action="save" class="form-validating form-horizontal">
      <g:render template="form"/>
      <div class="form-actions">
        <button type="submit" class="btn btn-success"/><g:message encodeAs='HTML' code="label.create" /></button>
        <g:link class="btn" action="list"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>
    
  </body>
</html>

