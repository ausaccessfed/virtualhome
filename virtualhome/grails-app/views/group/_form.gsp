

<fieldset>

  <g:hiddenField name="organization.id" value="${groupInstance?.organization?.id}" />

  <div class="control-group ${hasErrors(bean: groupInstance, field: 'name', 'error')}">
    <label class="control-label" for="name"><g:message encodeAs='HTML' code="label.name"/></label>
    <div class="controls">
      <g:textField name="name" required="" value="${groupInstance?.name}"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.group.name')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: groupInstance, field: 'description', 'error')}">
    <label class="control-label" for="description"><g:message encodeAs='HTML' code="label.description"/></label>
    <div class="controls">
      <g:textField name="description" required="" value="${groupInstance?.description}"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.group.description')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <g:if test="${groupInstance?.organization?.orgScope}">
    <div class="control-group ${hasErrors(bean: groupInstance, field: 'groupScope', 'error')}">
      <label class="control-label" for="groupScope"><g:message encodeAs='HTML' code="label.scope"/></label>
      <div class="controls">
        <g:textField name="groupScope" value="${groupInstance?.groupScope}"/>
        <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.group.scope')}"><i class="icon icon-question-sign"></i></a>
      </div>
    </div>
  </g:if>

  <div class="control-group ${hasErrors(bean: groupInstance, field: 'welcomeMessage', 'error')}">
    <label class="control-label" for="welcomeMessage"><g:message encodeAs='HTML' code="label.welcomemessage"/></label>
    <div class="controls">
      <g:textArea name="welcomeMessage" value="${groupInstance?.welcomeMessage}" rows="20" class="input-xxlarge"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.group.welcomemessage')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

</fieldset>
