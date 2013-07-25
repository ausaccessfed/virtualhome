<html>
  <head>
    <meta name="layout" content="internal" />
  </head>
  <body>

    <ul class="breadcrumb">
      <li><g:link controller="dashboard"><g:message encodeAs='HTML' code="branding.application.name"/></g:link> <span class="divider">/</span></li>
      <li><g:link action="show" controller="organization" id="${groupInstance.organization.id}"><g:fieldValue bean="${groupInstance.organization}" field="displayName"/></g:link> <span class="divider">/</span></li> 
      <li><g:link action="show" controller="group" id="${groupInstance.id}"><g:fieldValue bean="${groupInstance}" field="name"/></g:link> <span class="divider">/</span></li> 
      <li class="active"><g:message encodeAs='HTML' code="branding.nav.breadcrumb.managedsubject.createcsv"/></li>
    </ul>

    <g:render template="/templates/flash" plugin="aafApplicationBase"/>
    <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

    <g:if test="${errors && !status}">
      <h3 class="muted"><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.errors.csv.heading"/></h3>
      <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.errors.csv.detail"/></p>

      <div class='alert alert-error'>
        <ul>
          <g:each in="${errors}" var="error">
            <li>${error}</li>
          </g:each>
        </ul>
      </div>
    </g:if>

    <g:if test="${managedSubjectInstances && !status}">
      <h3 class="muted"><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.errors.account.heading"/></h3>
      <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.errors.account.detail"/></p>
      <p><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.errors.account.nocreation"/></p>

      <div class='alert alert-error'>
        <ol>
          <g:each in="${managedSubjectInstances}" var="managedSubjectInstance">
            <g:eachError bean="${managedSubjectInstance}" var="error">
              <li><g:message encodeAs='HTML' error="${error}"/></li>
            </g:eachError>
          </g:each>
        </ol>
      </div>
    </g:if>

    <h2><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.heading" args="${[groupInstance.name]}"/></h2>
    <g:render template="reminder"/>
    <p>
      <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.description"/>
    </p>
    <p>
      <strong><g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.format"/></strong>
    </p>
    <ul>
      <li>[cn] - <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.format.cn"/></li>
      <li>[email] - <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.format.email"/></li>
      <li>[eduPersonAffiliation] - <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.format.aff"/></li>
      <li>[expiry-in-months] - <g:message encodeAs='HTML' code="views.aaf.vhr.managedsubject.createcsv.format.expiry"/></li>
    </ul>

    <br>

    <h4 class="muted">Example CSV file contents</h4>
    <pre>Jim Jones,jim@uni.edu.au,staff,0
Lisa Jones,lisa@uni.edu.au,student,24
Петров,petrov@uni.edu.ru,affiliate,6</pre>

    <br><br><br>

    <g:uploadForm action="savecsv" class="form form-horizontal">
      <fieldset>
        <g:hiddenField name="group.id" value="${groupInstance.id}"/>

        <div class="control-group">
          <label class="control-label" for="csvdata"><g:message encodeAs='HTML' code="label.file"/></label>
          <div class="controls">
            <input type="file" name="csvdata" class="input-large"/>
          </div>
        </div>
        <div class="form-actions">
          <input type="submit" class="btn btn-success"/>
        </div>
      </fieldset>
    </g:uploadForm>
    
  </body>
</html>

