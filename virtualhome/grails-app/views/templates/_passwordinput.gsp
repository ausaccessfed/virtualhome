<div class="control-group">
  <label class="control-label" for="plainPassword">
    <g:message code="templates.aaf.vhr.passwordinput.password.label" encodeAs="HTML"/>
  </label>
  <div class="controls">
    <div class="span5">
      <g:if test="${newPasswordRequired}">
        <input class="span5 required" id="plainPassword" name="plainPassword" type="password" autocomplete="off" data-typetoggle="#showpassword">
      </g:if>
      <g:else>
        <input class="span5" id="plainPassword" name="plainPassword" type="password" autocomplete="off" data-typetoggle="#showpassword">
      </g:else>
      <input id="showpassword" type="checkbox" tabindex="-1"/> <span><g:message code="templates.aaf.vhr.passwordinput.password.unmask"/></span>
      <p class="lead" style="margin-top:12px; margin-bottom: 6px;">
        <g:message code="templates.aaf.vhr.passwordinput.password.help" args="${['<strong id="pwlength">0</strong>']}" encodeAs="none"/>
      </p>
    </div>
    <div class="span4">
      <div class="help-block pulse-target">
        <g:message code="templates.aaf.vhr.passwordinput.password.requirements"/>
      </div>
    </div>
  </div>
</div>

<div class="control-group">
  <label class="control-label" for="plainPasswordConfirmation">
    <g:message code="templates.aaf.vhr.passwordinput.passwordconfirmation.label"/>
  </label>
  <div class="controls">
    <div class="span5">
      <g:if test="${required}">
        <input class="span5 required" name="plainPasswordConfirmation" id="plainPasswordConfirmation" type="password" autocomplete="off" data-typetoggle="#showpassword">
      </g:if>
      <g:else>
        <input class="span5" name="plainPasswordConfirmation" id="plainPasswordConfirmation" type="password" autocomplete="off" data-typetoggle="#showpassword">
      </g:else>
    </div>
    <div class="span4">
      <span class="help-block"><g:message code="templates.aaf.vhr.passwordinput.passwordconfirmation.help"/></span>
    </div>
  </div>
</div>

<r:require modules="pulse" />
<r:script>
  $('#plainPassword').showPassword();
  $('#plainPasswordConfirmation').showPassword();

  var examples = ['lol', 'correcthorsebatterystaple', 'ilovedvisitingIcelandin2012', 'I backed Horse 46 in the Melbourne cup!'];

  $('#plainPassword').on("keyup", function() {
    $('#pwlength').html($('#plainPassword').val().length);
  });

  $('#plainPassword').on("focus", function() {
    $('.pulse-target').pulse( {opacity: 0.4}, {duration : 600, pulses : 2});
    $('.pulse-target').addClass('help-block-pulse');
  });

  $('#plainPassword').on("focusout", function() {
    $('.pulse-target').removeClass('help-block-pulse');
  });

  $('button[type=submit]').click(function() {
    if($("#accountform").valid()) {
      aaf_base.set_button($(this));
      $(this).parents('form').submit();
    }
  });

  jQuery.validator.addMethod("notAnExample", function(value, element) {
    if(jQuery.inArray($('#plainPassword').val().trim(),examples) != -1) {
      return false;
    } else {
      return true;
    }
  }, "");

  jQuery.validator.addMethod("noSpace", function(value, element) { 
    return value.indexOf(" ") < 0 && value != ""; 
  }, "Spaces are not permitted.");

  $("#accountform").validate({
    rules: {
      login: {
        required: true,
        minlength: 3,
        noSpace:true,
        remote: { url:"login-available", async:true }
      },
      plainPassword: {
        minlength: 8,
        notAnExample: true
      },
      plainPasswordConfirmation: {
        minlength: 8,
        equalTo: '#plainPassword'
      }
    },
    errorElement: "div",
    wrapper: "div",
    errorPlacement: function(error, element) {
      error.css('margin-bottom', '12px');

      error.addClass('text-error');
      element.parent().append(error);

      if(!$('#loginavailable').hasClass('hidden')) {
        $('#loginavailable').addClass('hidden');
      }
    },
    messages:{
      login: {
        remote: 'Unfortunately <strong>this username is taken</strong>, please choose something unique.'
      },
      plainPassword: {
        notAnExample: '<strong>LOL!!!</strong> not a good idea to use the examples :)'
      },
      plainPasswordConfirmation: {
        equalTo: 'Oops! Your passwords do not quite match.'
      }
    },
    keyup: true,
    focusout: false,
    focusInvalid:true
  });
</r:script>
