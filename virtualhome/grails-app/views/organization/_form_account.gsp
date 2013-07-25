
<fieldset>

  <g:hiddenField name="eduPersonAssurance" value='urn:mace:aaf.edu.au:iap:id:1' />

  <h4><g:message encodeAs='HTML' code="label.group"/></h4>
  <div class="control-group">
    <div class="controls">
      <g:select name="group.id"
        from="${groupInstanceList}"
        optionValue="name"
        optionKey="id" />
    </div>
  </div>

  <g:render template="/managedSubject/form_createfields"/>

</fieldset>
