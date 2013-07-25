<!doctype html>
<html>
  <head>
    <meta name="layout" content="internal" />
    <r:require modules="equalizecols" />
  </head>
  <body>

    <div class="row dashboardrow">
      <div class="span6">
        <div class="well well-small administering">
          <h2><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.myorganizations"/></h2>
          <g:if test="${organizationInstanceList.sort{it.displayName}}">
            <ul class="unstyled">
            <g:each in="${organizationInstanceList.sort{it.displayName}}" var="org">
              <li><g:link controller="organization" action="show" id="${org.id}"><g:fieldValue bean="${org}" field="displayName"/></g:link></li>
            </g:each>
            </ul>
          </g:if>
          <g:else>
            <p><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.noorganizations"/></p>
          </g:else>
          <br>
          <div class="view-all"><g:link controller="organization" action="list" class="btn btn-small btn-info"><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.organizations.view"/></g:link></div>
        </div>
      </div>

      <div class="span6">
        <div class="well well-small administering">
          <h2><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.mygroups"/></h2>
          <g:if test="${groupInstanceList}">
            
            <g:each in="${groupInstanceList.sort{it.key}}" var="entry">
              <strong class="muted">${entry.key}</strong>
              <ul class="unstyled">
                <g:each in="${entry.value.sort{it.name}}" var="group">
                  <li><g:link controller="group" action="show" id="${group.id}"><g:fieldValue bean="${group}" field="name"/></g:link></li>
                </g:each>
              </ul>
            </g:each>
            
          </g:if>
          <g:else>
            <p><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.nogroups"/></p>
          </g:else>
          <aaf:hasPermission target="app:administrator">
            <br>
            <div class="view-all"><g:link controller="group" action="list" class="btn btn-small btn-info"><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.groups.view"/></g:link></div>
          </aaf:hasPermission>
        </div>
      </div>
    </div>

    <hr>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.statistics.heading"/></h2>
    <div class="row">
      <div class="span4">
        <div class="well well-small statistic">
          <h3><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.total.organizations"/></h3>
          <hr>
          <span class="lead">${statistics.organizations}</span>
        </div>
      </div>
      <div class="span4">
        <div class="well well-small statistic">
          <h3><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.total.groups"/></h3>
          <hr>
          <span class="lead">${statistics.groups}</span>
        </div>
      </div>
      <div class="span4">
        <div class="well well-small statistic">
          <h3><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.total.managedsubjects"/></h3>
          <hr>
          <span class="lead">${statistics.managedSubjects}</span>
        </div>
      </div>
    </div>

    <div class="row content-spacer">
      <div class="span12">
        <h3><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.vhr.sessions"/></h3>
        <p><g:message encodeAs='HTML' code="views.aaf.vhr.dashboard.vhr.sessions.detail"/></p>
        <div id="sessionschart">
        </div>    
      </div>
    </div>

    <r:script>
      $('.administering').equalizeCols();
      $('.statistic').equalizeCols();

      $(function() {
        aaf_base.administration_dashboard_sessions_report(${statistics.last12MonthSessions});      
      });
    </r:script>

  </body>
</html>
