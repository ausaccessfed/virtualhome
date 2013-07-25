<h5 class="muted">Primary Administrators</h5>
<table class="table table-borderless">
  <thead>
    <tr>
      <th><g:message encodeAs='HTML' code="label.name" /></th>
      <th><g:message encodeAs='HTML' code="label.email" /></th>
    </tr>
  </thead>
  <tbody>
    <g:each in="${groupRole.subjects?.sort{it.cn}}" var="subject">
      <tr>
        <td><g:fieldValue bean="${subject}" field="cn"/></td>
        <td><a href="mailto:${subject.email}"><g:fieldValue bean="${subject}" field="email"/></a></td>
      </tr>
    </g:each>
  </tbody>
</table>

<h5 class="muted">Secondary Administrators</h5>
<table class="table table-borderless">
  <thead>
    <tr>
      <th><g:message encodeAs='HTML' code="label.name" /></th>
      <th><g:message encodeAs='HTML' code="label.email" /></th>
    </tr>
  </thead>
  <tbody>
    <g:each in="${organizationRole.subjects?.sort{it.cn}}" var="subject">
      <tr>
        <td><g:fieldValue bean="${subject}" field="cn"/></td>
        <td><a href="mailto:${subject.email}"><g:fieldValue bean="${subject}" field="email"/></a></td>
      </tr>
    </g:each>
  </tbody>
</table>

<div class="alert alert-info">
  <h5>Can't contact an administrator?</h5>
  <p>If you're unable to contact an account administator as shown above (or if there are no administrators shown) please get in touch with <a href="mailto:support@aaf.edu.au">AAF support at support@aaf.edu.au</a>. Please provide your username and details of who you've attempted to contact above as part of the email so we can assist you further.</p>
</div>
