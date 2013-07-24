
<html>
  <head>  
    <meta name="layout" content="internal" />
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.organization"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.organization.list.heading" /></h2>
    
      <table class="table table-borderless table-sortable">
        <thead>
          <tr>
            <th><g:message encodeAs='HTML' code="label.displayname" /></th> 
            <th><g:message encodeAs='HTML' code="label.description" /></th> 
            <th><g:message encodeAs='HTML' code="label.active" /></th> 
            <th><g:message encodeAs='HTML' code="label.archived" /></th> 
            <th/>
          </tr>
        </thead>
        <tbody>
        <g:each in="${organizationInstanceList.sort{it.displayName}}" status="i" var="organizationInstance">
          <tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
            <td>${fieldValue(bean: organizationInstance, field: "displayName")}</td>
            <td>${fieldValue(bean: organizationInstance, field: "description")}</td>
            <td><g:formatBoolean boolean="${organizationInstance.active}" /></td>
            <td><g:formatBoolean boolean="${organizationInstance.archived}" /></td>
            <td><g:link action="show" id="${organizationInstance.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view"/></g:link></td>
          </tr>
        </g:each>
        </tbody>
      </table>
  </body>
</html>
