<ul class="dropdown-menu">

  <aaf:hasPermission target="app:administrator">
    <li>
      <g:link action="create" controller="managedSubject" params='['group.id':"${groupInstance.id}"]'><g:message encodeAs='HTML' code="label.createmanagedsubject"/></g:link>
    </li>
    <li>
      <g:link action="createcsv" controller="managedSubject" params='['group.id':"${groupInstance.id}"]'><g:message encodeAs='HTML' code="label.createmultiplemanagedsubject"/></g:link>
    </li>

    <li class="divider"></li>
    
    <li>
      <g:render template="show_actions_admin"/>
    </li>

    <li class="divider"></li>

    <li>
      <g:link action="edit" id="${groupInstance.id}"><g:message encodeAs='HTML' code="label.editgroup"/></g:link>
    </li>
    <li>
      <g:render template="show_actions_toggle"/>
    </li>

    <li class="divider"></li>
    <li>
      <a href="#" onclick="$(this).next('form').submit();">
      <g:if test="${groupInstance.archived}">
        <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.unarchive"/>
      </g:if>
      <g:else>
        <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.archive"/>
      </g:else>
      </a>
      <g:form action="toggleArchived" method="post">
        <g:hiddenField name="version" value="${groupInstance?.version}" />
        <g:hiddenField name="id" value="${groupInstance.id}" />
      </g:form>
    </li>

    <li>
      <a href="#" onclick="$(this).next('form').submit();">
      <g:if test="${groupInstance.blocked}">
        <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.unblock"/>
      </g:if>
      <g:else>
        <g:message encodeAs='HTML' code="views.aaf.vhr.group.show.block"/>
      </g:else>
      </a>
      <g:form action="toggleBlocked" method="post">
        <g:hiddenField name="version" value="${groupInstance?.version}" />
        <g:hiddenField name="id" value="${groupInstance.id}" />
      </g:form>
    </li>
    <li>
      <a href="#" class="delete-ensure" data-confirm="${message(code:'views.aaf.vhr.group.confirm.remove')}"><g:message encodeAs='HTML' code="label.deletegroup"/></a>
      <g:form action="delete" method="delete">
        <g:hiddenField name="id" value="${groupInstance.id}" />
      </g:form>
    </li>
  </aaf:hasPermission>

  <aaf:lacksPermission target="aaf:administrator">
    <g:if test="${groupInstance.canMutate()}">
      <li>
        <g:link action="create" controller="managedSubject" params='['group.id':"${groupInstance.id}"]'><g:message encodeAs='HTML' code="label.createmanagedsubject"/></g:link>
      </li>
      <li>
        <g:link action="createcsv" controller="managedSubject" params='['group.id':"${groupInstance.id}"]'><g:message encodeAs='HTML' code="label.createmultiplemanagedsubject"/></g:link>
      </li>
      <li class="divider"></li>
      <li>
        <g:render template="show_actions_admin"/>
      </li>
      <li class="divider"></li>
      <li>
        <g:link action="edit" id="${groupInstance.id}"><g:message encodeAs='HTML' code="label.editgroup"/></g:link>
      </li>
      <li>
        <g:render template="show_actions_toggle"/>
      </li>
    </g:if>
    <g:else>
      <li><span class="label label-important" style="margin:6px;"><g:message encodeAs='HTML' code="label.noactions"/></span></li>
    </g:else>
  </aaf:lacksPermission>

</ul>
