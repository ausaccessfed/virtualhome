<!doctype html>
<html>
  <head>
    <meta name="layout" content="myaccount" />
  </head>
  <body>

    <div class="row">
      <div class="span6">
        <h2>Hello <g:fieldValue bean="${managedSubjectInstance}" field="cn"/>!</h2>
      </div>
    </div>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>

    <g:if test="${!managedSubjectInstance.canLogin()}">
      <div class="alert alert-warning">
        <h3>Account unable to access AAF services</h3>
        <p>Your account has been restricted and is currently unable to be used to access AAF services.</p>
        <p>Please contact one of the administrators shown in the table <strong>Assistance with your account</strong> below for help in re-enabling your access.</p>
      </div>
    </g:if>

    <h3 class="muted">Account Details</h3>

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
            <th class="span4"><span id="displayname-label"><strong><g:message encodeAs='HTML' code="label.displayname" /></strong></span></th>
            <td><span aria-labelledby="displayname-label"><g:fieldValue bean="${managedSubjectInstance}" field="displayName"/></span></td>
          </tr>

          <tr>
            <th class="span4"><span id="edupersonassurance-label"><strong><g:message encodeAs='HTML' code="label.edupersonassurance" /></strong></span></th>
            <td><span aria-labelledby="edupersonassurance-label"><g:fieldValue bean="${managedSubjectInstance}" field="eduPersonAssurance"/></span></td>
          </tr>

          <tr>
              <th class="span4"><span id="edupersonaffiliation-label"><strong><g:message encodeAs='HTML' code="label.edupersonaffiliation" /></strong></span></th>
              <td>
                <span aria-labelledby="edupersonaffiliation-label">
                  <ol>
                  <g:each in="${managedSubjectInstance.eduPersonAffiliation?.split(';')}" var='aff'>
                    <li>${aff.encodeAsHTML()}</li>
                  </g:each>
                  </ol>
                </span>
              </td>
            </tr>

          <tr>
            <th class="span4"><span id="edupersonentitlement-label"><strong><g:message encodeAs='HTML' code="label.edupersonentitlement" /></strong></span></th>
            <td>
              <span aria-labelledby="edupersonentitlement-label">
                <ol>
                <g:each in="${managedSubjectInstance.eduPersonEntitlement?.split(';')}" var='ent'>
                  <li>${ent.encodeAsHTML()}</li>
                </g:each>
                </ol>
              </span>
            </td>
          </tr>

          <tr>
            <th class="span4"><span id="organization-label"><strong><g:message encodeAs='HTML' code="label.organization" /></strong></span></th>
            <td><span aria-labelledby="organization-label"><g:fieldValue bean="${managedSubjectInstance}" field="organization.displayName"/></span></td>
          </tr>

          <tr>
            <th class="span4"><span id="group-label"><strong><g:message encodeAs='HTML' code="label.group" /></strong></span></th>
            <td><span aria-labelledby="group-label"><g:fieldValue bean="${managedSubjectInstance}" field="group.name"/></span></td>
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

      <div class="span12">
        <g:link action="changedetails" class="btn">
          <g:message code="views.aaf.vhr.account.show.changedetails" encodeAs="HTML"/>
        </g:link>
      </div>

    </div>

    <hr>

    <h3 class="muted">2-Step verification</h3>
    <g:if test="${managedSubjectInstance.isUsingTwoStepLogin()}">
      <p>This account has been successfully setup to use 2-Step verfication.</p>

      <div class="row"><div class="span12 centered"><br><img src="${totpURL}" width="200" height="200" class="img-polaroid"><br><br></div></div>

      <p>If you haven't already done so please <strong>follow the instructions on your installed app</strong> to scan the above QR code and complete the set up on your phone.<p>
    </g:if>
    <g:else>
      <p>Would you like to enable extra security for your account?.</p>
      <g:render template="appdetails" />
      <p><g:link action="enabletwostep" id="${managedSubjectInstance.id}" class="btn btn-large btn-warning">Enable 2-Step verification</g:link></p>
    </g:else>

    <hr>

    <h3 class="muted">Getting Help</h3>
    <p>You can <g:link action="changedetails">change your password or mobile number</g:link> using this website.</p>
    <p>For all other queries relating to your account please contact one of the administrators shown below.</p>

    <g:render template="/templates/accountadministrators"/>
  </body>
</html>
