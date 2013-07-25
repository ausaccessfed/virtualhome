<html>
  <head>
    <meta name="layout" content="internal" />
    <r:require modules="bootstrap-multiselect"/>
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${organizationInstance.id}"><g:fieldValue bean="${organizationInstance}" field="displayName"/></g:link> <span class="divider">/</span></li> 
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.managedsubject.create"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.organization.managedsubject.create.heading" args="${[organizationInstance.displayName]}"/></h2>
    
    <g:form controller="managedSubject" action="save" class="form-validating form-horizontal">
      <g:render template="form_account"/>
      <div class="form-actions">
        <button type="submit" class="btn btn-success"/><g:message encodeAs='HTML' code="label.create" /></button>
        <g:link class="btn" action="list"><g:message encodeAs='HTML' code="label.cancel"/></g:link>
      </div>
    </g:form>
    
  </body>
</html>

