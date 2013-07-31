<!doctype html>
<html>
  <head>
    <meta name="layout" content="internal" />
    <r:require modules="pwmask" />
  </head>
  <body>

    <div class="row">
      <div class="span12">
       <div class="page-header">
        <h1>Welcome <g:fieldValue bean="${managedSubjectInstance}" field="cn"/> <small> Your account is nearly ready....</small></h1>
        <p class="lead">Please choose a username, a <strong>secure</strong> password and provide your mobile phone number below.</p>
      </div>

      <g:render template="/templates/flash" plugin="aafApplicationBase"/>
      <g:render template="/templates/errors_bean" model="['bean':managedSubjectInstance]" plugin="aafApplicationBase"/>

      

      <g:form controller="finalization" action="complete" class="form-horizontal finalize" name="accountform">
        <g:hiddenField name="inviteCode" value="${invitationInstance.inviteCode}"/>

        <div class="control-group">
          <label class="control-label" for="login">Username</label>
          <div class="controls">
            <div class="span5">
              <input class="required span5" name="login" id="login" type="text" autofocus="autofocus" autocomplete="off" value="${managedSubjectInstance.login}">
            </div>
            <div class="span4">
              <span class="help-block">
                <p>You can choose anything you like for your username so long as:
                  <ul>
                    <li>It is memorable for you;</li>
                    <li>It is between 3 and 255 characters in length; and</li>
                    <li>Contains no whitespace.</li>
                  </ul>
                </p>
                <br><br>
              </span>
            </div>
          </div>
        </div>

        <hr>

        <g:render template="/templates/passwordinput" model="[newPasswordRequired: true]"/>

        <hr>

        <div class="control-group">
          <label class="control-label" for="plainPasswordConfirmation">Mobile Number</label>
          <div class="controls">
            <div class="span5">
              <input class="span5" name="mobileNumber" type="text" autocomplete="off" value="${managedSubjectInstance.mobileNumber}">
            </div>
            <div class="span4">
              <div class="help-block">
                <p>Please provide your mobile number.</p>
                <p>We <strong>only use</strong> your mobile number to assist in ensuring security if you forget your password and need to reset it.</p>
                <p>International numbers are supported. If you're located outside Australia please be sure to add your <a href="http://en.wikipedia.org/wiki/List_of_mobile_phone_number_series_by_country" target="_blank">international prefix</a> to the start of your number.
                <p>An example of an internationally formatted mobile number is <strong>+1 555 555 5555</strong> which is valid for numbers in the United States. All international numbers are in the format <em>+[code] [number]</em>.</p>
                <p>If you elect not to supply your mobile number and forget your password you'll need to contact administrators directly which may take some time to complete preventing your access to AAF connected services in the interim.</p>
              </div>
            </div>
          </div>
        </div>


        <div class="form-actions">
          <p class="text-muted"><i class="icon-info-sign"></i> <strong>Intensive cryptography coming up!! Your browser will take a few seconds to talk with the AAF Virtual Home after you click, there is no need to refresh.</strong></p>

          <button type="submit" class="btn btn-info btn-large"><i class="icon-user icon-white"></i> Finalise your account</button>
          
        </div>
      </g:form>

      </div>
    </div>

  </body>
</html>
