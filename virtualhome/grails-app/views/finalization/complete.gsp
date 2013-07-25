<!doctype html>
<html>
  <head>
    <meta name="layout" content="internal" />
    <r:require modules="pwmask" />
  </head>
  <body>
    <div class="hero-unit">
      <h1>You're ready to go!</h1>
      <p>To login to services simply select <strong>AAF Virtual Home</strong> from the list of available organisations when asked to nominate your organisation.</p>
      <a href="http://www.aaf.edu.au/servicecatalogue/" class="btn btn-info btn-large pull-right"><i class="icon-globe icon-white"></i> Show me the services!</a>
    </div>

    <h4>Your account details</h4>
    <div class="row">
      <div class="span5">
        <table class="table table-borderless">
        <tbody>

          <tr><td colspan="2"><h4><g:message encodeAs='HTML' code="label.coreattributes"/></h4></tr></td>
          
          <tr>
            <th class="span4"><span id="cn-label"><strong><g:message encodeAs='HTML' code="label.cn" /></strong></span></th>
            <td><span aria-labelledby="cn-label"><g:fieldValue bean="${managedSubjectInstance}" field="cn"/></span></td>
          </tr>
        
          <tr>
            <th class="span4"><span id="email-label"><strong><g:message encodeAs='HTML' code="label.email" /></strong></span></th>
            <td><span aria-labelledby="email-label"><g:fieldValue bean="${managedSubjectInstance}" field="email"/></span></td>
          </tr>
        
          <tr>
            <th class="span4"><span id="edupersonassurance-label"><strong><g:message encodeAs='HTML' code="label.edupersonassurance" /></strong></span></th>
            <td><span aria-labelledby="edupersonassurance-label"><g:fieldValue bean="${managedSubjectInstance}" field="eduPersonAssurance"/></span></td>
          </tr>
        
          <tr>
            <th class="span4"><span id="edupersonaffiliation-label"><strong><g:message encodeAs='HTML' code="label.edupersonaffiliation" /></strong></span></th>
            <td><span aria-labelledby="edupersonaffiliation-label"><g:fieldValue bean="${managedSubjectInstance}" field="eduPersonAffiliation"/></span></td>
          </tr>

          <tr>
            <th class="span4"><span id="displayname-label"><strong><g:message encodeAs='HTML' code="label.displayname" /></strong></span></th>
            <td><span aria-labelledby="displayname-label"><g:fieldValue bean="${managedSubjectInstance}" field="displayName"/></span></td>
          </tr>
        </tbody>
        </table>
      </div>

      <div class="span5 offset2">
        <table class="table table-borderless">
        <tbody>
          <tr><td colspan="2"><h4><g:message encodeAs='HTML' code="label.optionalattributes"/></h4></tr></td>

          <tr>
            <th class="span4"><span id="givenname-label"><strong><g:message encodeAs='HTML' code="label.givenname" /></strong></span></th>
            <td><span aria-labelledby="givenname-label"><g:fieldValue bean="${managedSubjectInstance}" field="givenName"/></span>
          </tr>
        
          <tr>
            <th class="span4"><span id="surname-label"><strong><g:message encodeAs='HTML' code="label.surname" /></strong></span></th>
            <td><span aria-labelledby="surname-label"><g:fieldValue bean="${managedSubjectInstance}" field="surname"/></span>
          </tr>
        
          <tr>
            <th class="span4"><span id="telephonenumber-label"><strong><g:message encodeAs='HTML' code="label.telephonenumber" /></strong></span></th>
            <td><span aria-labelledby="telephonenumber-label"><g:fieldValue bean="${managedSubjectInstance}" field="telephoneNumber"/></span>
          </tr>

          <tr>
            <th class="span4"><span id="mobilenumber-label"><strong><g:message encodeAs='HTML' code="label.mobilenumber" /></strong></span></th>
            <td><span aria-labelledby="mobilenumber-label"><g:fieldValue bean="${managedSubjectInstance}" field="mobileNumber"/></span>
          </tr>
        
          <tr>
            <th class="span4"><span id="postaladdress-label"><strong><g:message encodeAs='HTML' code="label.postaladdress" /></strong></span></th>
            <td><span aria-labelledby="postaladdress-label"><g:fieldValue bean="${managedSubjectInstance}" field="postalAddress"/></span>
          </tr>
        
          <tr>
            <th class="span4"><span id="organizationalunit-label"><strong><g:message encodeAs='HTML' code="label.organizationalunit" /></strong></span></th>
            <td><span aria-labelledby="organizationalunit-label"><g:fieldValue bean="${managedSubjectInstance}" field="organizationalUnit"/></span>
          </tr>

        </tbody>
        </table>
      </div>
    </div>
  </body>
</html>
