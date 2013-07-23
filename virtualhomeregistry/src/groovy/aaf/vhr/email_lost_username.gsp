<g:if test="${managedSubject}">
  Hello ${managedSubject.cn.encodeAsHTML()},<br><br>
</g:if>
<g:else>
  Hello,<br><br>
</g:else>

We have received a request to provide the username you use for logging in to the AAF Virtual Home.<br><br>

If you did not request your username please contact support@aaf.edu.au immediately, providing your account details and a copy of this notification.<br><br>

<g:if test="${managedSubject}">
  <h5>Your username is:</h5>

  ${managedSubject.login.encodeAsHTML()}<br><br>

  If you have also lost your password, you may initiate a password reset using the <strong>Recover your lost password</strong> link on the AAF Virtual Home login page.
</g:if>
<g:else>
  <h5>Your email address is not associated with an account in AAF Virtual Home.</h5>

  If you believe this message to be in error, please contact your organisation's IT Support.<br><br>

  For further assistance, please contact support@aaf.edu.au.
</g:else>
