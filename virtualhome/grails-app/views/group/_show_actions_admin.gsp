<g:if test="${!groupInstance.enforceTwoStepLogin()}">
  <a href="#" onclick="$(this).next('form').submit();"><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.twostep.enforce"/></a>
  <g:form action="enforcetwosteplogin" method="post">
    <g:hiddenField name="id" value="${groupInstance.id}" />
    <g:hiddenField name="enforce" value="true" />
  </g:form>
</g:if>
<g:else>
  <a href="#" onclick="$(this).next('form').submit();"><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.twostep.unenforce"/></a>
  <g:form action="enforcetwosteplogin" method="post">
    <g:hiddenField name="id" value="${groupInstance.id}" />
    <g:hiddenField name="enforce" value="false" />
  </g:form>
</g:else>

<li class="divider"></li>

<a class="show-add-administrative-members"><g:message encodeAs='HTML' code="label.addadministrator"/></a>
<g:form controller="manageAdministrators" action="search" method="post">
  <g:hiddenField name="id" value="${groupInstance.id}" />
  <g:hiddenField name="type" value="group" />
</g:form>
