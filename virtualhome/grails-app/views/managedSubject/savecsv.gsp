<html>
  <head>
    <meta name="layout" content="internal" />
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${groupInstance.organization.id}"><g:fieldValue bean="${groupInstance.organization}" field="displayName"/></g:link> <span class="divider">/</span></li> 
      <li><g:link action="show" controller="group" id="${groupInstance.id}"><g:fieldValue bean="${groupInstance}" field="name"/></g:link> <span class="divider">/</span></li> 
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.managedsubject.savecsv"/></li>
    </ul>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.savecsv.heading"/></h2>
    
    <p>
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.savecsv.details" args="${[linecount, groupInstance.name]}"/>
    </p>

    <h4><g:message encodeAs='HTML' code="label.accounts"/></h4>
    <table class="table table-borderless">
      <thead>
        <tr>
          <th><g:message encodeAs='HTML' code="label.cn"/></th>
          <th><g:message encodeAs='HTML' code="label.email"/></th>
          <th><g:message encodeAs='HTML' code="label.view"/></th>
        </tr>
      </thead>
      <tbody>
        <g:each in="${managedSubjectInstances}" var="managedSubjectInstance">
          <tr>
            <td><g:fieldValue bean="${managedSubjectInstance}" field="cn"/></td>
            <td><g:fieldValue bean="${managedSubjectInstance}" field="email"/></td>
            <td><g:link controller="managedSubject" action="show" id="${managedSubjectInstance.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view"/></g:link></td>
          </tr>
        </g:each>
      </tbody>
    </table>
    
  </body>
</html>

