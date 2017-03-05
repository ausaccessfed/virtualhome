
<html>
  <head>  
    <meta name="layout" content="internal" />
  </head>
  <body>
    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.managedsubject"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.list.heading" /></h2>
    
      <table class="table table-borderless table-sortable">
        <thead>
          <tr>
            <th><g:message encodeAs='HTML' code="label.login" /></th> 
            <th><g:message encodeAs='HTML' code="label.cn" /></th> 
            <th><g:message encodeAs='HTML' code="label.email" /></th>
            <aaf:hasPermission target="app:administrator">
              <th><g:message encodeAs='HTML' code="label.sharedtoken" /></th>
            </aaf:hasPermission>
            <th><g:message encodeAs='HTML' code="label.functioning" /></th> 
            <th><g:message encodeAs='HTML' code="label.organization" /></th> 
            <th><g:message encodeAs='HTML' code="label.group" /></th> 
            <th/>
          </tr>
        </thead>
        <tbody>
        <g:each in="${managedSubjectInstanceList}" status="i" var="managedSubjectInstance">
          <tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
            <td>${fieldValue(bean: managedSubjectInstance, field: "login")}</td>
            <td>${fieldValue(bean: managedSubjectInstance, field: "cn")}</td>
            <td>${fieldValue(bean: managedSubjectInstance, field: "email")}</td>  
            <aaf:hasPermission target="app:administrator">
              <td>${fieldValue(bean: managedSubjectInstance, field: "sharedToken")}</td>
            </aaf:hasPermission>
            <td><g:formatBoolean boolean="${managedSubjectInstance.functioning()}"/></td>
            <td><g:link action="show" controller="organization" id="${managedSubjectInstance.organization.id}">${fieldValue(bean: managedSubjectInstance, field: "organization.displayName")}</g:link></td>
            <td><g:link action="show" controller="group" id="${managedSubjectInstance.group.id}">${fieldValue(bean: managedSubjectInstance, field: "group.name")}</g:link></td>
            <td><g:link action="show" id="${managedSubjectInstance.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view"/></g:link></td>
          </tr>
        </g:each>
        </tbody>
      </table>
  </body>
</html>
