<a href="#" onclick="$(this).next('form').submit();">
  <g:if test="${organizationInstance.active}">
    <g:message encodeAs='HTML' code="views.aaf.vhr.organization.show.deactivate"/>
  </g:if>
  <g:else>
    <g:message encodeAs='HTML' code="views.aaf.vhr.organization.show.activate"/>
  </g:else>
</a>
<g:form action="toggleActive" method="post">
  <g:hiddenField name="version" value="${organizationInstance?.version}" />
  <g:hiddenField name="id" value="${organizationInstance.id}" />
</g:form>
