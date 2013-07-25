<ul class="dropdown-menu">
  <aaf:hasPermission target="app:administrator">
    <g:render template="show_actions_resend"/>

    <li>
      <g:link action="edit" id="${managedSubjectInstance.id}"><g:message encodeAs='HTML' code="label.editmanagedsubject"/></g:link>
    </li>
    <li>
      <g:link action="admincode" id="${managedSubjectInstance.id}"><g:message encodeAs='HTML' code="label.generatepasswordresetcode"/></g:link>
    </li>
    <li class="divider"></li>
    <g:render template="show_actions_toggle"/>
    <li class="divider"></li>
    <li>
      <a href="#" onclick="$(this).next('form').submit();">
        <g:if test="${managedSubjectInstance.blocked}">
          <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.admin.unblock"/>
        </g:if>
        <g:else>
          <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.admin.block"/>
        </g:else>
      </a>
      <g:form action="toggleBlock" method="post">
        <g:hiddenField name="version" value="${managedSubjectInstance?.version}" />
        <g:hiddenField name="id" value="${managedSubjectInstance.id}" />
      </g:form>
    </li>

    <li>
      <a href="#" class="delete-ensure" data-confirm="${message(code:'views.aaf.vhr.managedsubject.confirm.remove')}"><g:message encodeAs='HTML' code="label.deletemanagedsubject"/></a>
      <g:form action="delete" method="delete">
        <g:hiddenField name="id" value="${managedSubjectInstance.id}" />
      </g:form>
    </li>
  </aaf:hasPermission>

  <aaf:lacksPermission target="aaf:administrator">
    <g:if test="${managedSubjectInstance.canMutate()}">
      <g:render template="show_actions_resend"/>
      <li>
        <g:link action="edit" id="${managedSubjectInstance.id}"><g:message encodeAs='HTML' code="label.editmanagedsubject"/></g:link>
      </li>
      <g:if test="${managedSubjectInstance.functioning()}">
        <li>
          <g:link action="admincode" id="${managedSubjectInstance.id}"><g:message encodeAs='HTML' code="label.generatepasswordresetcode"/></g:link>
        </li>
      </g:if>
      <li class="divider"></li>
      <g:render template="show_actions_toggle"/>
    </g:if>
    <g:else>
      <li><span class="label label-important" style="margin:6px;"><g:message encodeAs='HTML' code="label.noactions"/></span></li>
    </g:else>
  </aaf:lacksPermission>
</ul>
