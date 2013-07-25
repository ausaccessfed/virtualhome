Hello ${managedSubject.cn.encodeAsHTML()},<br><br>

You have been provided with new account in the AAF Virtual Home that allows you to access the wide range of online services connected to the Australian Access Federation.<br><br>

<g:if test="${managedSubject.group.welcomeMessage}">
  <h5>A message from your account administrator</h5>
  ${managedSubject.group.welcomeMessage}
  <br><br>
</g:if>

<h5>Your action is now required</h5>

To finish setting your account up please <a href="${g.createLink(controller:'finalization', action:'index', params:['inviteCode':invitation.inviteCode], absolute:true)}">access your unique account finalisation page by clicking this link</a> and follow the instructions provided.
