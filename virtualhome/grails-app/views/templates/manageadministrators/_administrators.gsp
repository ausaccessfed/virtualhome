<g:if test="${role.subjects}">  
  <table class="table table-borderless">
    <thead>
      <tr>
        <th><g:message encodeAs='HTML' code="label.name" /></th>
        <th><g:message encodeAs='HTML' code="label.email" /></th>
        <aaf:hasPermission target="app:administrator">
          <th><g:message encodeAs='HTML' code="label.sharedtoken" /></th>
        </aaf:hasPermission>
        <th/>
      </tr>
    </thead>
    <tbody>
      <g:each in="${role.subjects.sort{it.id}}" var="subject">
        <tr>
          <td><g:fieldValue bean="${subject}" field="cn"/></td>
          <td><a href="mailto:${subject.email}"><g:fieldValue bean="${subject}" field="email"/></a></td>
          <aaf:hasPermission target="app:administrator">
            <td><g:fieldValue bean="${subject}" field="sharedToken"/></td>
          </aaf:hasPermission>
          <td class="pull-right">         
            <g:form controller="manageAdministrators" action="remove" method="post">
              <aaf:hasPermission target="app:administrator">
                <g:link controller="subject" action="show" id="${subject.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view" /></g:link>
              </aaf:hasPermission>
              <g:hiddenField name="type" value="${type}" />
              <g:hiddenField name="id" value="${instance?.id}" />
              <g:hiddenField name="subjectID" value="${subject.id}" />
              <a class="remove-administrative-member btn btn-small btn-danger"><g:message encodeAs='HTML' code="label.remove"/></a>
            </g:form>
          </td>
        </tr>
      </g:each>
    </tbody>
  </table>
</g:if>
<g:else>
  <g:if test="${type == 'group'}">
    <p class="alert alert-info"><g:message encodeAs='HTML' code="templates.aaf.vhr.manageadministrators.group.role.members.none" args="[createLink(controller:'organization', action:'show', id:instance.organization.id, absolute:true, fragment:'tab-administrators'), instance.organization.displayName]"/></p>
  </g:if>
  <g:else>
    <p class="alert alert-info"><g:message encodeAs='HTML' code="templates.aaf.vhr.manageadministrators.role.members.none"/></p>
  </g:else>
</g:else>

