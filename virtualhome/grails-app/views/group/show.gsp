
<html>
  <head>
    <meta name="layout" content="internal" />
  </head>

  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${groupInstance.organization.id}"><g:fieldValue bean="${groupInstance.organization}" field="displayName"/></g:link> <span class="divider">/</span></li>
      <li><g:fieldValue bean="${groupInstance}" field="name"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':groupInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.heading" args="${[groupInstance.name]}"/></h2>

    <g:if test="${groupInstance.archived}">
      <div class="alert alert-block">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.archived.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.archived.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${groupInstance.blocked}">
      <div class="alert alert-block alert-error">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.blocked.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.blocked.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.unable.to.login"/></p>
      </div>
    </g:if>
    <g:if test="${!groupInstance.functioning() && !groupInstance.blocked && !groupInstance.archived}">
      <div class="alert alert-block alert-info">
        <h4><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.functioning.heading"/></h4>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.functioning.reason"/></p>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.group.show.unable.to.login"/></p>
      </div>
    </g:if>

    <ul class="nav nav-tabs">
      <li class="active"><a href="#tab-overview" data-toggle="tab"><g:message encodeAs='HTML' code="label.overview" /></a></li>

      <aaf:hasPermission target="app:manage:organization:${groupInstance.organization.id}:group:${groupInstance.id}:manage:administrators">
        <li><a href="#tab-accounts" data-toggle="tab"><g:message encodeAs='HTML' code="label.managedsubjects" /></a></li>
      </aaf:hasPermission>

      <li><a href="#tab-administrators" data-toggle="tab"><g:message encodeAs='HTML' code="label.administrators" /></a></li>

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
        <table class="table table-borderless">
          <tbody>
            
            <tr>
              <th class="span4"><span id="name-label"><strong><g:message encodeAs='HTML' code="label.name" /></strong></span></th>
              <td><span aria-labelledby="name-label"><g:fieldValue bean="${groupInstance}" field="name"/></span>
            </tr>
          
            <tr>
              <th class="span4"><span id="description-label"><strong><g:message encodeAs='HTML' code="label.description" /></strong></span></th>
              <td><span aria-labelledby="description-label"><g:fieldValue bean="${groupInstance}" field="description"/></span>
            </tr>

            <tr>
              <th class="span4"><span id="groupscope-label"><strong><g:message encodeAs='HTML' code="label.scope" /></strong></span></th>
              <td><span aria-labelledby="groupscope-label"><g:fieldValue bean="${groupInstance}" field="groupScope"/></span>
            </tr>

            <tr>
              <th class="span4"><span id="organization-label"><strong><g:message encodeAs='HTML' code="label.organization" /></strong></span></th>
              <td><span aria-labelledby="organization-label"><g:link controller="organization" action="show" id="${groupInstance?.organization?.id}"><g:fieldValue bean="${groupInstance.organization}" field="displayName"/></g:link></span>
            </tr>

            <tr>
              <th class="span4"><span id="organization-welcomemessage"><strong><g:message encodeAs='HTML' code="label.welcomemessage" /></strong></span></th>
              <td>
                <g:if test="${groupInstance.welcomeMessage}">
                  <pre><g:fieldValue bean="${groupInstance}" field="welcomeMessage"/></pre>
                </g:if>
              </td>
            </tr>

            <tr><td colspan="2"><hr></tr></td>
            <tr><td colspan="2"><strong><g:message encodeAs='HTML' code="label.internaldata"/></tr></td>

            <tr>
              <th class="span4"><span id="internalid-label"><strong><g:message encodeAs='HTML' code="label.internalid" /></strong></span></th>
              <td><span aria-labelledby="internalid-label"><g:fieldValue bean="${groupInstance}" field="id" /></span>
            </tr>
          
            <tr>
              <th class="span4"><span id="datecreated-label"><strong><g:message encodeAs='HTML' code="label.datecreated" /></strong></span></th>
              <td><span aria-labelledby="datecreated-label"><g:formatDate date="${groupInstance?.dateCreated}" /></span>
            </tr>
          
            <tr>
              <th class="span4"><span id="lastupdated-label"><strong><g:message encodeAs='HTML' code="label.lastupdated" /></strong></span></th>
              <td><span aria-labelledby="lastupdated-label"><g:formatDate date="${groupInstance?.lastUpdated}" /></span>
            </tr>
          
            <tr>
              <th class="span4"><span id="active-label"><strong><g:message encodeAs='HTML' code="label.active" /></strong></span></th>
              <td><span aria-labelledby="active-label"><g:formatBoolean boolean="${groupInstance?.active}" /></span>
            </tr>

            <tr>
              <th class="span4"><span id="archived-label"><strong><g:message encodeAs='HTML' code="label.archived" /></strong></span></th>
              <td><span aria-labelledby="archived-label"><g:formatBoolean boolean="${groupInstance?.archived}" /></span>
            </tr>

            <tr>
              <th class="span4"><span id="blocked-label"><strong><g:message encodeAs='HTML' code="label.blocked" /></strong></span></th>
              <td><span aria-labelledby="blocked-label"><g:formatBoolean boolean="${groupInstance?.blocked}" /></span>
            </tr>
                    
          </tbody>
        </table>
      </div>

      <aaf:hasPermission target="app:manage:organization:${groupInstance.organization.id}:group:${groupInstance.id}:manage:administrators">
        <div id="tab-accounts" class="tab-pane">
          <table class="table table-borderless table-sortable">
            <thead>
              <tr>
                  <th><g:message encodeAs='HTML' code="label.login" /></th> 
                  <th><g:message encodeAs='HTML' code="label.cn" /></th> 
                  <th><g:message encodeAs='HTML' code="label.email" /></th> 
                  <th/>
              </tr>
            </thead>
            <tbody>
            <g:each in="${groupInstance.subjects.findAll{!it.archived}}" status="i" var="managedSubjectInstance">
              <tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
                <td>${fieldValue(bean: managedSubjectInstance, field: "login")}</td>
                <td>${fieldValue(bean: managedSubjectInstance, field: "cn")}</td>
                <td>${fieldValue(bean: managedSubjectInstance, field: "email")}</td>
                <td>
                  <aaf:hasPermission target="app:manage:organization:${managedSubjectInstance.organization.id}:group:${managedSubjectInstance.group.id}:managedsubject:show">
                    <g:link action="show" controller="managedSubject" id="${managedSubjectInstance.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view"/></g:link>
                  </aaf:hasPermission>
                </td>
              </tr>
            </g:each>
            </tbody>
          </table>

          <g:if test="${groupInstance.subjects.findAll{it.archived}?.size() > 0}">
            <hr>
            <h4><g:message encodeAs='HTML' code="label.archived"/></h4>
            <table class="table table-borderless table-sortable">
              <thead>
                <tr>
                    <th><g:message encodeAs='HTML' code="label.login" /></th> 
                    <th><g:message encodeAs='HTML' code="label.cn" /></th> 
                    <th><g:message encodeAs='HTML' code="label.email" /></th> 
                    <th/>
                </tr>
              </thead>
              <tbody>
              <g:each in="${groupInstance.subjects.findAll{it.archived}}" status="i" var="managedSubjectInstance">
                <tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
                  <td>${fieldValue(bean: managedSubjectInstance, field: "login")}</td>
                  <td>${fieldValue(bean: managedSubjectInstance, field: "cn")}</td>
                  <td>${fieldValue(bean: managedSubjectInstance, field: "email")}</td>
                  <td>
                    <aaf:hasPermission target="app:manage:organization:${managedSubjectInstance.organization.id}:group:${managedSubjectInstance.group.id}:managedsubject:show">
                      <g:link action="show" controller="managedSubject" id="${managedSubjectInstance.id}" class="btn btn-small"><g:message encodeAs='HTML' code="label.view"/></g:link>
                    </aaf:hasPermission>
                  </td>
                </tr>
              </g:each>
              </tbody>
            </table>
          </g:if>
        </div>
      </aaf:hasPermission>

      <div id="tab-administrators" class="tab-pane">
        <div id="administrative-members">
          
          <aaf:hasPermission target="app:manage:organization:${groupInstance.organization.id}:group:${groupInstance.id}:manage:administrators">
            <g:render template="/templates/manageadministrators/administrators" model="[instance:groupInstance, type:'group']" />
            <div id="add-administrative-members"></div>
          </aaf:hasPermission>

          <aaf:lacksPermission target="app:manage:organization:${groupInstance.organization.id}:group:${groupInstance.id}:manage:administrators">
            <g:render template="/templates/manageadministrators/showadministrators" />
          </aaf:lacksPermission>
        </div>
      </div>

    </div>

  </body>
</html>
