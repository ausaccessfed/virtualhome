<a href="#" onclick="$(this).next('form').submit();">
<g:if test="${groupInstance.active}">
  <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.deactivate"/>
</g:if>
<g:else>
  <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.activate"/>
</g:else>
</a>
<g:form action="toggleActive" method="post">
  <g:hiddenField name="version" value="${groupInstance?.version}" />
  <g:hiddenField name="id" value="${groupInstance.id}" />
</g:form>
