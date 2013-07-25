<a class="show-add-administrative-members"><g:message encodeAs='HTML' code="label.addadministrator"/></a>
<g:form controller="manageAdministrators" action="search" method="post">
  <g:hiddenField name="id" value="${organizationInstance.id}" />
  <g:hiddenField name="type" value="organization" />
</g:form>
