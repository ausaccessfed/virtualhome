
# Shibboleth IdP 3.x integration code #

This code was developed by REANNZ (Research and Education Advanced Network New Zealand) for Tuakiri, the New Zealand Access Federation, and contributed back to the AAF virtualhome project.

This code allows running the virtualhome application with a Shibboleth 3.x IdP.

Tuakiri is running this code in production with IdP 3.2.1, with a customized version of the virtualhome application.

To use the full functionality of this code, one would need to use the version of the virtualhome application extended by REANNZ for Tuakiri.  Specifically:
* support for `forceAuthn="true"` requires the virtualhome application to return the timestamp of the authentication on the API exposed to this module.  This was introduced as an extension in the Tuakiri version.
* the module also tries to pass the service name to the login page - but this get only accepted by the Tuakiri version.

This module MAY work with the AAF version of virtualhome (without the two features above), but AAF provides absolutely no support for this module.

## Installation and configuration ##

* build the module with

    gradle build

* use the configuration snippets in the idpv3 directory here:
  * add the contents of `addto-web.xml` to `edit-webapp/WEB-INF/web.xml`
  * add `VHRUsername` (or a different value as configured in `web.xml` above) to the `shibboleth.authn.RemoteUser.checkAttributes` bean in `conf/authn/remoteuser-authn-config.xml` as per `change-in-authn-remoteuser-internal-authn-config.xml`
  * optionally, to support `forceAuthn`, change the `authn/RemoteUser` bean in `conf/authn/general-authn.xml` to declare support for forceAuthn as per the sample in `change-in-authn-general-authn.xml`
  * optionally, to get the service name to pass to the login page, change `shibboleth.authn.RemoteUser.populateUIInfo` in `conf/authn/remoteuser-authn-config.xml` to `TRUE` as per `change-in-authn-remoteuser-authn-config.xml`

## Authors ##

This module was developed by Vlad Mencl <vladimir.mencl@reannz.co.nz>, based on the AAF IdPV2 module.
