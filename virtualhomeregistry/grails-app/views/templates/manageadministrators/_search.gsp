
<h3>Add via email</h3>

<g:if test="${invited}">
  <div class="alert alert-success">
    <strong>Success</strong><br>
    The invitation was sent successfully via email.
  </div>
</g:if>

<p>Invite a new administrator via email. The addresse will be sent an email containing a unique link which when clicked will give them administrative rights.</p>

<g:form controller="manageAdministrators" action="invite" method="post" class="form" name="invite-administrative-member">
  <div class="control-group">
    <label class="control-label" for="email"><g:message encodeAs='HTML' code="label.email"/></label>
    <div class="controls">
      <g:field type="email" name="email" required=""/>
    </div>
  </div>

  <g:hiddenField name="type" value="${type}" />
  <g:hiddenField name="id" value="${instance?.id}" />

  <button class="btn btn-success" type="submit"><g:message encodeAs='HTML' code="label.invite" /></button>
</g:form>

<hr>

<h3>Add existing account</h3>
<table class="table table-borderless table-sortable">
  <thead>
    <tr>
      <th><g:message encodeAs='HTML' code="label.name" /></th>
      <th><g:message encodeAs='HTML' code="label.email" /></th>
      <aaf:hasPermission target="app:administrator">
        <th><g:message encodeAs='HTML' code="label.sharedtoken" /></th>
      </aaf:hasPermission>
      <th/>
    </tr>
  </thead>
  <tbody>
    <g:each in="${subjects}" var="subject">
      <tr>
        <td><g:fieldValue bean="${subject}" field="cn"/></td>
        <td><g:fieldValue bean="${subject}" field="email"/></td>
        <aaf:hasPermission target="app:administrator">
          <td><g:fieldValue bean="${subject}" field="sharedToken"/></td>
        </aaf:hasPermission>
        <td class="pull-right">
          <g:form controller="manageAdministrators" action="add" method="post">
            <aaf:hasPermission target="app:administrator">
              <a href="#" class="btn btn-small ajax-modal" data-load="${createLink(controller:'subject', action:'showpublic', id:subject.id, absolute:true)}" ><g:message encodeAs='HTML' code="label.quickview" /></a>
              <g:link controller="subject" action="show" id="${subject.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view" /></g:link>
            </aaf:hasPermission>

            <g:hiddenField name="type" value="${type}" />
            <g:hiddenField name="id" value="${instance?.id}" />
            <g:hiddenField name="subjectID" value="${subject?.id}" />
            <a class="add-administrative-member btn btn-small btn-success"><g:message encodeAs='HTML' code="label.add"/></a>
          </g:form>
        </td>
    </g:each>
  </tbody>
</table>

