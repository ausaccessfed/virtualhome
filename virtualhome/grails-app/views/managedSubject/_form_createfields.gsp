<g:if test="${actionName == 'edit' || actionName == 'update'}">
  <h4><g:message encodeAs='HTML' code="label.coreattributes"/></h4>
  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'login', 'error')}">
    <label class="control-label" for="login"><g:message encodeAs='HTML' code="label.username"/></label>
    <div class="controls">
      <g:textField name="login" required="" value="${managedSubjectInstance?.login}"/>
      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.login')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>
</g:if>

<div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'cn', 'error')}">
  <label class="control-label" for="cn"><g:message encodeAs='HTML' code="label.cn"/></label>
  <div class="controls">
    <g:textField name="cn" required="" value="${managedSubjectInstance?.cn}"/>
    <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.cn')}"><i class="icon icon-question-sign"></i></a>
  </div>
</div>

<div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'email', 'error')}">
  <label class="control-label" for="email"><g:message encodeAs='HTML' code="label.email"/></label>
  <div class="controls">
    <g:field type="email" name="email" required="" value="${managedSubjectInstance?.email}"/>

    <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.email')}"><i class="icon icon-question-sign"></i></a>
  </div>
</div>

<aaf:hasPermission target="app:administrator">
  <g:if test="${actionName != 'create'}">
    <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'sharedToken', 'error')}">
      <label class="control-label" for="sharedToken"><g:message encodeAs='HTML' code="label.sharedtoken"/></label>
      <div class="controls">
        <g:textField name="sharedToken" value="${managedSubjectInstance?.sharedToken}" placeholder="automatically created if blank"/>

        <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.sharedtoken')}"><i class="icon icon-question-sign"></i></a>
      </div>
    </div>
  </g:if>
</aaf:hasPermission>

<div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'eduPersonAffiliation', 'error')}">
  <label class="control-label" for="eduPersonAffiliation"><g:message encodeAs='HTML' code="label.edupersonaffiliation"/></label>
  <div class="controls">
    <g:select name="eduPersonAffiliation" from="${managedSubjectInstance.affiliations}" 
    value="${managedSubjectInstance?.eduPersonAffiliation ?managedSubjectInstance?.eduPersonAffiliation.split(';') as List : 'member'}" 
    valueMessagePrefix="managedSubject.eduPersonAffiliation" multiple="multiple" id="edupersonaffiliation" required="required"/>

    <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.edupersonaffiliation')}"><i class="icon icon-question-sign"></i></a>
  </div>
</div>

<div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'eduPersonEntitlement', 'error')}">
  <label class="control-label" for="eduPersonEntitlement"><g:message encodeAs='HTML' code="label.edupersonentitlement"/></label>
  <div class="controls">
    <g:textArea name="eduPersonEntitlement" value="${managedSubjectInstance?.eduPersonEntitlement?.replace(';', '\n')}"
    class="input-xxlarge" rows="10" placeholder="urn:mace:aaf.edu.au:domain.edu.au:registered:delegation"/>

    <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.edupersonentitlement')}"><i class="icon icon-question-sign"></i></a>
  </div>
</div>



<div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'accountExpires', 'error')}">
  <label class="control-label" for="accountExpires"><g:message encodeAs='HTML' code="label.accountexpires"/></label>
  <div class="controls">
    <g:checkBox id="wantexpirydate" name="wantexpirydate" value="${managedSubjectInstance.accountExpires ? true:false}" /> <small><strong>set expiry date</strong> (active forever unless expiry date set</small>
    <br><br>

    <div id="expiryselection">
      <g:datePicker disabled="disabled" id="accountExpires" name="accountExpires" value="${managedSubjectInstance.accountExpires}" precision="day" noSelection="['':'-Choose-']" relativeYears="[-2..3]"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.accountexpires')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>
</div>

<g:if test="${actionName == 'edit' || actionName == 'update'}">
  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'displayName', 'error')}">
    <label class="control-label" for="displayName"><g:message encodeAs='HTML' code="label.displayname"/></label>
    <div class="controls">
      <g:textField name="displayName" value="${managedSubjectInstance?.displayName}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.displayname')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <hr>

  <h4><g:message encodeAs='HTML' code="label.optionalattributes"/></h4>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'givenName', 'error')}">
    <label class="control-label" for="givenName"><g:message encodeAs='HTML' code="label.givenname"/></label>
    <div class="controls">
      <g:textField name="givenName" value="${managedSubjectInstance?.givenName}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.givenname')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'surname', 'error')}">
    <label class="control-label" for="surname"><g:message encodeAs='HTML' code="label.surname"/></label>
    <div class="controls">
      <g:textField name="surname" value="${managedSubjectInstance?.surname}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.surname')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'telephoneNumber', 'error')}">
    <label class="control-label" for="telephoneNumber"><g:message encodeAs='HTML' code="label.telephonenumber"/></label>
    <div class="controls">
      <g:textField name="telephoneNumber" value="${managedSubjectInstance?.telephoneNumber}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.telephonenumber')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'mobileNumber', 'error')}">
    <label class="control-label" for="mobileNumber"><g:message encodeAs='HTML' code="label.mobilenumber"/></label>
    <div class="controls">
      <g:textField name="mobileNumber" value="${managedSubjectInstance?.mobileNumber}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.mobilenumber')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'postalAddress', 'error')}">
    <label class="control-label" for="postalAddress"><g:message encodeAs='HTML' code="label.postaladdress"/></label>
    <div class="controls">
      <g:textField name="postalAddress" value="${managedSubjectInstance?.postalAddress}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.postaladdress')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>

  <div class="control-group ${hasErrors(bean: managedSubjectInstance, field: 'organizationalUnit', 'error')}">
    <label class="control-label" for="organizationalUnit"><g:message encodeAs='HTML' code="label.organizationalunit"/></label>
    <div class="controls">
      <g:textField name="organizationalUnit" value="${managedSubjectInstance?.organizationalUnit}"/>

      <a href="#" rel="tooltip" title="${g.message(encodeAs:'HTML', code:'help.inline.aaf.vhr.managedsubject.organizationalunit')}"><i class="icon icon-question-sign"></i></a>
    </div>
  </div>
</g:if>

<r:script>
  $(document).ready(function() {
    $('#edupersonaffiliation').multiselect();

    <g:if test="${managedSubjectInstance.accountExpires}">
      $('#expiryselection').show();
      $("#accountExpires_day").removeAttr('disabled');
      $("#accountExpires_month").removeAttr('disabled');
      $("#accountExpires_year").removeAttr('disabled');
    </g:if>
    <g:else>
      $('#expiryselection').hide();
    </g:else>
  });

  $('#wantexpirydate').bind('change', function () {
    if($("#wantexpirydate").is(':checked')) {
      $('#expiryselection').show();
      $("#accountExpires_day").removeAttr('disabled');
      $("#accountExpires_month").removeAttr('disabled');
      $("#accountExpires_year").removeAttr('disabled');
    }
    else {
      $('#expiryselection').hide();
      $("#accountExpires_day").attr('disabled','disabled');
      $("#accountExpires_month").attr('disabled','disabled');
      $("#accountExpires_year").attr('disabled','disabled');
    }
  });
</r:script>
