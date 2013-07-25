<g:if test="${managedSubjectInstance.login != null}">
  <li>
    <a href="#" onclick="$(this).next('form').submit();">
      <g:if test="${managedSubjectInstance.active}">
        <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.deactivate"/>
      </g:if>
      <g:else>
        <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.activate"/>
      </g:else>
    </a>
    <g:form action="toggleActive" method="post">
      <g:hiddenField name="version" value="${managedSubjectInstance?.version}" />
      <g:hiddenField name="id" value="${managedSubjectInstance.id}" />
    </g:form>
  <li>
</g:if>

<li>
  <a href="#" onclick="$(this).next('form').submit();">
    <g:if test="${managedSubjectInstance.locked}">
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.admin.unlock"/>
    </g:if>
    <g:else>
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.admin.lock"/>
    </g:else>
  </a>
  <g:form action="toggleLock" method="post">
    <g:hiddenField name="version" value="${managedSubjectInstance?.version}" />
    <g:hiddenField name="id" value="${managedSubjectInstance.id}" />
  </g:form>
</li>

<li>
  <a href="#" class="archive-ensure" data-confirm="${message(code:'views.aaf.vhr.managedsubject.confirm.archive')}">
    <g:if test="${managedSubjectInstance.archived}">
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unarchive"/>
    </g:if>
    <g:else>
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.archive"/>
    </g:else>
  </a>
  <g:form action="toggleArchive" method="post">
    <g:hiddenField name="version" value="${managedSubjectInstance?.version}" />
    <g:hiddenField name="id" value="${managedSubjectInstance.id}" />
  </g:form>
<li>
