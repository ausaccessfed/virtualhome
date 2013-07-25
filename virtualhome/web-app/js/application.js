$(document).on('click', '.show-add-administrative-members', function() {
  var btn = $(this);
  var form = btn.next('form');
  $.ajax({
    type: "POST",
    cache: false,
    url: form.attr('action'),
    data: form.serialize(),
    success: function(res) {
      $('a[href="#tab-administrators"]').tab('show'); // Select tab by name

      var target = $("#add-administrative-members");
      target.html(res);
      aaf_base.applyBehaviourTo(target);
      target.fadeIn();   
    },
    error: function (xhr, ajaxOptions, thrownError) {
      aaf_base.reset_button(btn);
      aaf_base.popuperror();
    }
  });
});

$(document).on('click', '.add-administrative-member', function() {
  aaf_base.set_button($(this));
  var btn = $(this);
  var form = btn.parent();
  $.ajax({
    type: "POST",
    cache: false,
    url: form.attr('action'),
    data: form.serialize(),
    success: function(res) {
      var target = $("#administrative-members");
      target.html(res);
      aaf_base.applyBehaviourTo(target);
      target.fadeIn();
      
      aaf_base.reset_button(btn);    
    },
    error: function (xhr, ajaxOptions, thrownError) {
      aaf_base.reset_button(btn);
      aaf_base.popuperror();
    }
  });
});

$(document).on('submit', '#invite-administrative-member', function() {
  var form = $(this);
  var btn = $(':submit', this);
  aaf_base.set_button(btn);
  $.ajax({
    type: "POST",
    cache: false,
    url: form.attr('action'),
    data: form.serialize(),
    success: function(res) {
      var target = $("#administrative-members");
      target.html(res);
      aaf_base.applyBehaviourTo(target);
      target.fadeIn();
      
      aaf_base.reset_button(btn);    
    },
    error: function (xhr, ajaxOptions, thrownError) {
      aaf_base.reset_button(btn);
      aaf_base.popuperror();
    }
  });

  return false;
});

$(document).on('click', '.remove-administrative-member', function() {
  aaf_base.set_button($(this));
  var btn = $(this);
  var form = btn.parent();
  $.ajax({
    type: "POST",
    cache: false,
    url: form.attr('action'),
    data: form.serialize(),
    success: function(res) {
      var target = $("#administrative-members");
      target.html(res);
      aaf_base.applyBehaviourTo(target);
      target.fadeIn();
      
      aaf_base.reset_button(btn);    
    },
    error: function (xhr, ajaxOptions, thrownError) {
      aaf_base.reset_button(btn);
      aaf_base.popuperror();
    }
  });
});
