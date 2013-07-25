<html>
  <head>
    <meta name="layout" content="internal" />
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${groupInstance.organization.id}"><g:fieldValue bean="${groupInstance.organization}" field="displayName"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" id="${groupInstance?.id}"><g:fieldValue bean="${groupInstance}" field="name"/></g:link> <span class="divider">/</span></li>
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.group.edit"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':groupInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.group.edit.heading" args="${[groupInstance.name]}"/></h2>
    
    <g:form action="update" class="form-validating form-horizontal">
      <g:hiddenField name="id" value="${groupInstance?.id}" />
      <g:hiddenField name="version" value="${groupInstance?.version}" />
      <g:render template="form"/>
      <div class="form-actions">
        <button type="submit" class="btn btn-success"/><g:message encodeAs='HTML' code="label.update" /></button>
        <g:link class="btn" action="show" id="${groupInstance?.id}"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>
    
  </body>
</html>

