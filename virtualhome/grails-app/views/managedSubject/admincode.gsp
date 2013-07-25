
<html>
  <head>
    <meta name="layout" content="internal" />
  </head>

  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${managedSubjectInstance.group.organization.id}"><g:fieldValue bean="${managedSubjectInstance.group.organization}" field="displayName"/></g:link> <span class="divider">/</span></li>
      <li><g:link controller="group" action="show" id="${managedSubjectInstance.group.id}"> <g:fieldValue bean="${managedSubjectInstance.group}" field="name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" id="${managedSubjectInstance.id}"><g:fieldValue bean="${managedSubjectInstance}" field="cn"/></g:link></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.show.heading" args="${[managedSubjectInstance.cn]}"/></h2>

    <div class="hero-unit">
      <h2>Password reset code </h2>

      <div class="alert"><center><h3>${managedSubjectInstance.resetCodeExternal}</h3></center></div>

      <p>Please provide this code to <strong>${managedSubjectInstance.cn}</strong> via any communications means you have available to allow them to use the VHR lost password reset service at <g:link controller="lostPassword" action="start">${createLink(controller:'lostPassword', action:'start', absolute:true)}</g:link>.</p>
      <p>We recommend all accounts provide a mobile phone number to automate and further secure the lost password reset process. You may like to also request this information and update the account accordingly.</p>
      <p>This code can only be used once.</p>
    </div>

  </body>
</html>
