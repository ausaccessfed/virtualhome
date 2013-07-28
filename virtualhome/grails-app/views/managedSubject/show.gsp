
<html>
  <head>
    <meta name="layout" content="internal" />
  </head>

  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${managedSubjectInstance.group.organization.id}"><g:fieldValue bean="${managedSubjectInstance.group.organization}" field="displayName"/></g:link> <span class="divider">/</span></li>
      <li><g:link controller="group" action="show" id="${managedSubjectInstance.group.id}"> <g:fieldValue bean="${managedSubjectInstance.group}" field="name"/></g:link> <span class="divider">/</span></li>
      <li class="active"><g:fieldValue bean="${managedSubjectInstance}" field="cn"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.heading" args="${[managedSubjectInstance.cn]}"/></h2>

    <g:if test="${managedSubjectInstance.isExpired()}">
      <div class="alert alert-block">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.expired.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.expired.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${managedSubjectInstance.blocked}">
      <div class="alert alert-block alert-error">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.blocked.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.blocked.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.blocked.correct"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${managedSubjectInstance.archived}">
      <div class="alert alert-block">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.archived.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.archived.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${managedSubjectInstance.locked}">
      <div class="alert alert-block">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.locked.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.locked.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.locked.correct"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${!managedSubjectInstance.finalized}">
      <div class="alert alert-block alert-info">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.finalized.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.finalized.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.finalized.correct"/></p>
      </div>
    </g:if>
    <g:if test="${!(managedSubjectInstance.functioning()) && managedSubjectInstance.login != null && !managedSubjectInstance.blocked && !managedSubjectInstance.locked && !managedSubjectInstance.archived && !managedSubjectInstance.isExpired()}">
      <div class="alert alert-block alert-info">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.functioning.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.functioning.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.unable.to.login"/></p>
      </div>
    </g:if>

    <ul class="nav nav-tabs">
      <li class="active"><a href="#tab-overview" data-toggle="tab"><g:message encodeAs='HTML' code="label.overview" /></a></li>
      <li><a href="#tab-eventlog" data-toggle="tab"><g:message encodeAs='HTML' code="label.eventlog" /></a></li>

      <li class="dropdown pull-right">
        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
          <g:message encodeAs='HTML' code="label.actions" />
          <b class="caret"></b>
        </a>
        <g:render template="show_actions"/>
      </li>
    </ul>

    <div class="tab-content">
      <div id="tab-overview" class="tab-pane active">
        <div class="row">
          <div class="span5">
            <table class="table table-borderless">
              <tbody>

                <tr><td colspan="2"><h4><g:message encodeAs='HTML' code="label.coreattributes"/></h4></td></tr>
                
                <tr>
                  <th class="span4"><span id="cn-label"><strong><g:message encodeAs='HTML' code="label.cn" /></strong></span></th>
                  <td><span aria-labelledby="cn-label"><g:fieldValue bean="${managedSubjectInstance}" field="cn"/></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="email-label"><strong><g:message encodeAs='HTML' code="label.email" /></strong></span></th>
                  <td><span aria-labelledby="email-label"><g:fieldValue bean="${managedSubjectInstance}" field="email"/></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="sharedtoken-label"><strong><g:message encodeAs='HTML' code="label.sharedtoken" /></strong></span></th>
                  <aaf:hasPermission target="app:administrator">
                    <td><span aria-labelledby="sharedtoken-label"><g:fieldValue bean="${managedSubjectInstance}" field="sharedToken"/></span></td>
                  </aaf:hasPermission>
                  <aaf:lacksPermission target="app:administrator">
                    <td><span aria-labelledby="sharedtoken-label" class="label label-warning"><g:message encodeAs='HTML' code="label.obfuscated"/></span></td>
                  </aaf:lacksPermission>
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
                    </span></td>
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
                    </span></td>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="span5 offset2">
            <table class="table table-borderless">
              <tbody>
                <tr><td colspan="2"><h4><g:message encodeAs='HTML' code="label.optionalattributes"/></h4></td></tr>

                <tr>
                  <th class="span4"><span id="givenname-label"><strong><g:message encodeAs='HTML' code="label.givenname" /></strong></span></th>
                  <td><span aria-labelledby="givenname-label"><g:fieldValue bean="${managedSubjectInstance}" field="givenName"/></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="surname-label"><strong><g:message encodeAs='HTML' code="label.surname" /></strong></span></th>
                  <td><span aria-labelledby="surname-label"><g:fieldValue bean="${managedSubjectInstance}" field="surname"/></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="telephonenumber-label"><strong><g:message encodeAs='HTML' code="label.telephonenumber" /></strong></span></th>
                  <td><span aria-labelledby="telephonenumber-label"><g:fieldValue bean="${managedSubjectInstance}" field="telephoneNumber"/></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="mobilenumber-label"><strong><g:message encodeAs='HTML' code="label.mobilenumber" /></strong></span></th>
                  <td><span aria-labelledby="mobilenumber-label"><g:fieldValue bean="${managedSubjectInstance}" field="mobileNumber"/></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="postaladdress-label"><strong><g:message encodeAs='HTML' code="label.postaladdress" /></strong></span></th>
                  <td><span aria-labelledby="postaladdress-label"><g:fieldValue bean="${managedSubjectInstance}" field="postalAddress"/></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="organizationalunit-label"><strong><g:message encodeAs='HTML' code="label.organizationalunit" /></strong></span></th>
                  <td><span aria-labelledby="organizationalunit-label"><g:fieldValue bean="${managedSubjectInstance}" field="organizationalUnit"/></span></td>
                </tr>

              </tbody>
            </table>
          </div>
        </div>

        <hr>

        <div class="row">
          <div class="span12">

            <table class="table table-borderless">
              <tbody>
                <tr><td colspan="2"><h4><g:message encodeAs='HTML' code="label.internaldata"/></h4></td></tr>

                <tr>
                  <th class="span4"><span id="internalid-label"><strong><g:message encodeAs='HTML' code="label.internalid" /></strong></span></th>
                  <td><span aria-labelledby="internalid-label"><g:fieldValue bean="${managedSubjectInstance}" field="id" /></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="login-label"><strong><g:message encodeAs='HTML' code="label.login" /></strong></span></th>
                  <td><span aria-labelledby="login-label"><g:fieldValue bean="${managedSubjectInstance}" field="login"/></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="accountexpiry-label"><strong><g:message encodeAs='HTML' code="label.accountexpires" /></strong></span></th>
                  <td>
                    <g:if test="${managedSubjectInstance.accountExpires}">
                      <span aria-labelledby="accountexpiry-label"><g:formatDate format="dd-MM-yyyy" date="${managedSubjectInstance.accountExpires}"/></span></td>
                    </g:if>
                    <g:else>
                      <span aria-labelledby="accountexpiry-label"><g:message encodeAs='HTML' code="label.doesnotexpire"/></span></td>
                    </g:else>
                  </td>
                </tr>

                <tr>
                  <th class="span4"><span id="active-label"><strong><g:message encodeAs='HTML' code="label.active" /></strong></span></th>
                  <td><span aria-labelledby="active-label"><g:formatBoolean boolean="${managedSubjectInstance?.active}" /></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="locked-label"><strong><g:message encodeAs='HTML' code="label.locked" /></strong></span></th>
                  <td><span aria-labelledby="locked-label"><g:formatBoolean boolean="${managedSubjectInstance?.locked}" /></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="archived-label"><strong><g:message encodeAs='HTML' code="label.archived" /></strong></span></th>
                  <td><span aria-labelledby="archived-label"><g:formatBoolean boolean="${managedSubjectInstance?.archived}" /></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="blocked-label"><strong><g:message encodeAs='HTML' code="label.blocked" /></strong></span></th>
                  <td><span aria-labelledby="blocked-label"><g:formatBoolean boolean="${managedSubjectInstance?.blocked}" /></span></td>
                </tr>

                <tr>
                  <th class="span4"><span id="organization-label"><strong><g:message encodeAs='HTML' code="label.organization" /></strong></span></th>
                  <td><span aria-labelledby="organization-label"><g:link controller="organization" action="show" id="${managedSubjectInstance?.organization?.id}"><g:fieldValue bean="${managedSubjectInstance.organization}" field="displayName"/></g:link></span></td>
                </tr>
              
                <tr>
                  <th class="span4"><span id="group-label"><strong><g:message encodeAs='HTML' code="label.group" /></strong></span></th>
                  <td><span aria-labelledby="group-label"><g:link controller="group" action="show" id="${managedSubjectInstance?.group?.id}"><g:fieldValue bean="${managedSubjectInstance.group}" field="name"/></g:link></span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div id="tab-eventlog" class="tab-pane">
        <table class="table table-borderless">
          <thead>
            <tr>
              <th><g:message encodeAs='HTML' code="label.datecreated"/></th>
              <th><g:message encodeAs='HTML' code="label.event"/></th>
              <th><g:message encodeAs='HTML' code="label.category"/></th>
              <th><g:message encodeAs='HTML' code="label.reason"/></th>
              <th><g:message encodeAs='HTML' code="label.actioner"/></th>
              <th><g:message encodeAs='HTML' code="label.environment"/></th>
            </tr>
          </thead>
          <tbody>
            <g:each in="${managedSubjectInstance.stateChanges.sort{it.dateCreated}.reverse()}" var="event">
              <tr>
                <td><g:fieldValue bean="${event}" field="dateCreated" /></td>
                <td><g:fieldValue bean="${event}" field="event" /></td>
                <td><g:fieldValue bean="${event}" field="category" /></td>
                <td><g:fieldValue bean="${event}" field="reason" /></td>
                <aaf:hasPermission target="app:administrator">
                  <td><g:link controller="subject" action="show" id="${event?.actionedBy?.id}"><g:fieldValue bean="${event}" field="actionedBy.cn" /></g:link></td>
                </aaf:hasPermission>
                <aaf:lacksPermission target="aaf:administrator">
                  <td><g:fieldValue bean="${event}" field="actionedBy.cn" /></td>
                </aaf:lacksPermission>
                <td>
                  <g:if test="${event.environment}">
                    <pre><g:fieldValue bean="${event}" field="environment" /></pre>
                  </g:if>
                </td>
              </tr>
            </g:each>
          </tbody>
        </table>
      </div>
    </div>

  </body>
</html>
