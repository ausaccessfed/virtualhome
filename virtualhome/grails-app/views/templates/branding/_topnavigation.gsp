<div class="container">
  <div class="navbar">
    <div class="navbar-inner">

      <a class="btn btn-navbar btn-mini" data-toggle="collapse" data-target=".nav-collapse">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </a>

      <ul class="nav">
        <aaf:isLoggedIn>
          <li>
            <g:link controller="dashboard" action="dashboard"><g:message encodeAs='HTML' code="branding.nav.dashboard" /></g:link>
          </li>
        </aaf:isLoggedIn>
        <aaf:isNotLoggedIn>
          <li>
            <g:link controller="dashboard" action="welcome"><g:message encodeAs='HTML' code="branding.nav.welcome" /></g:link>
          </li>
        </aaf:isNotLoggedIn>
      </ul>
      <ul class="nav pull-right">
        <aaf:isNotLoggedIn>
          <li>
            <g:link controller="auth"><g:message encodeAs='HTML' code="branding.nav.login"/></g:link>
          </li>
        </aaf:isNotLoggedIn>
      </ul>

      <div class="nav-collapse">
        <ul class="nav">

          <aaf:isAdministrator>
            <li>
              <g:link controller="organization" action="list"><g:message encodeAs='HTML' code="branding.nav.organizations" /></g:link>
            </li>
            <li>
              <g:link controller="group" action="list"><g:message encodeAs='HTML' code="branding.nav.groups" /></g:link>
            </li>
            <li>
              <g:link controller="managedSubject" action="list"><g:message encodeAs='HTML' code="branding.nav.accounts" /></g:link>
            </li>
            <li class="dropdown">
              <a class="dropdown-toggle" id="workflow" role="button" data-toggle="dropdown" data-target="#" href="#">
                <g:message encodeAs='HTML' code="branding.nav.workflow" />
              </a>
              <ul class="dropdown-menu" role="menu" aria-labelledby="workflow">
                <li><g:link controller="workflowApproval" action="list"><g:message encodeAs='HTML' code="branding.nav.workflow.approval" /></g:link></li>
                <aaf:isAdministrator>
                  <li><g:link controller="workflowApproval" action="administrative"><g:message encodeAs='HTML' code="branding.nav.workflow.administration.approval" /></g:link></li>
                </aaf:isAdministrator>
              </ul>
            </li>

            <li class="dropdown">
              <a class="dropdown-toggle" id="administration" role="button" data-toggle="dropdown" data-target="#" href="#">
                <g:message encodeAs='HTML' code="branding.nav.admin" />
              </a>
              <ul class="dropdown-menu" role="menu" aria-labelledby="administration">
                <li><g:link controller="adminDashboard" action="index"><g:message encodeAs='HTML' code="branding.nav.admin.dashboard" /></g:link></li>
                <li><g:link controller="subject"><g:message encodeAs='HTML' code="branding.nav.admin.subjects" /></g:link></li>
                <li><g:link controller="role"><g:message encodeAs='HTML' code="branding.nav.admin.roles" /></g:link></li>
                <li><g:link controller="emailTemplate" action="list"><g:message encodeAs='HTML' code="branding.nav.admin.emailtemplate" /></g:link></li>
                <li class="dropdown-submenu">
                  <a tabindex="-1" href="#"><g:message encodeAs='HTML' code="branding.nav.admin.workflow" /> <i class="icon-chevron-right icon-white"></i></a>
                  <ul class="dropdown-menu">
                    <li><g:link controller="workflowProcess" action="list"><g:message encodeAs='HTML' code="branding.nav.admin.workflow.process" /></g:link></li>
                    <li><g:link controller="workflowScript" action="list"><g:message encodeAs='HTML' code="branding.nav.admin.workflow.script" /></g:link></li>
                  </ul>
                <li><g:link controller="console" action="index" target="_blank"><g:message encodeAs='HTML' code="branding.nav.admin.console" /></g:link></li>
                <li><g:link controller="adminDashboard" action="environment"><g:message encodeAs='HTML' code="branding.nav.admin.environment" /></g:link></li>
              </ul>
            </li>
          </aaf:isAdministrator>

          <li><a href="http://support.aaf.edu.au" target="_blank"><g:message encodeAs='HTML' code="branding.nav.support" /></a></li>
        </ul>

        <ul class="nav pull-right">
          <aaf:isLoggedIn>
            <li>
              <g:link controller="auth" action="logout"><g:message encodeAs='HTML' code="branding.nav.logout" /></g:link>
            </li>
          </aaf:isLoggedIn>
        </ul>
      </div>

    </div>
  </div>
</div>
