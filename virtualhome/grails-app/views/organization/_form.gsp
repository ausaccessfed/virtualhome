

<fieldset>

  <aaf:hasPermission target='app:administration'>
    <g:if test="${actionName != 'create'}">
      <hr>
      <p class="alert alert-info"><g:message encodeAs='HTML' code="views.aaf.vhr.organization.updated.remotely"/></p>
    </g:if>
    <div class="control-group ${hasErrors(bean: organizationInstance, field: 'name', 'error')}">
      <label class="control-label" for="name"><g:message encodeAs='HTML' code="label.name"/></label>
      <div class="controls">
        <g:textField name="name" required="" value="${organizationInstance?.name}"/>
      </div>
    </div>

    <div class="control-group ${hasErrors(bean: organizationInstance, field: 'displayName', 'error')}">
      <label class="control-label" for="displayName"><g:message encodeAs='HTML' code="label.displayname"/></label>
      <div class="controls">
        <g:textField name="displayName" required="" value="${organizationInstance?.displayName}"/>
      </div>
    </div>

    <hr>
  </aaf:hasPermission>

  <div class="control-group ${hasErrors(bean: organizationInstance, field: 'description', 'error')}">
    <label class="control-label" for="description"><g:message encodeAs='HTML' code="label.description"/></label>
    <div class="controls">
      <g:textArea name="description" required="" cols="40" rows="5" maxlength="2000" value="${organizationInstance?.description}"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.organization.description')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: organizationInstance, field: 'orgScope', 'error')}">
    <label class="control-label" for="orgScope"><g:message encodeAs='HTML' code="label.scope"/></label>
    <div class="controls">
      <g:textField name="orgScope" value="${organizationInstance?.orgScope}"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.organization.scope')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <aaf:hasPermission target='app:administration'>
    <hr>
    <g:if test="${actionName == 'create'}">
      <div class="control-group ${hasErrors(bean: organizationInstance, field: 'frID', 'error')}">
        <label class="control-label" for="frID"><g:message encodeAs='HTML' code="label.frid"/></label>
        <div class="controls">
          <g:field name="frID" type="number" value="${organizationInstance.frID}" required=""/>
        </div>
      </div>
    </g:if>

    <div class="control-group ${hasErrors(bean: organizationInstance, field: 'groupLimit', 'error')}">
      <label class="control-label" for="groupLimit"><g:message encodeAs='HTML' code="label.grouplimit"/></label>
      <div class="controls">
        <g:field name="groupLimit" type="number" value="${organizationInstance.groupLimit}" required=""/>
      </div>
    </div>

    <div class="control-group ${hasErrors(bean: organizationInstance, field: 'subjectLimit', 'error')}">
      <label class="control-label" for="subjectLimit"><g:message encodeAs='HTML' code="label.subjectlimit"/></label>
      <div class="controls">
        <g:field name="subjectLimit" type="number" value="${organizationInstance.subjectLimit}" required=""/>
      </div>
    </div>
  </aaf:hasPermission>

</fieldset>
