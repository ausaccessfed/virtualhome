<!DOCTYPE html>
<html>
  <head>
    <title><g:message encodeAs='HTML' code='branding.application.name'/></title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="shortcut icon" href="${resource(dir:'images', file:'favicon.ico')}" />
    
    <r:require modules="modernizr, bootstrap, bootstrap-responsive-css, validate, datatables, less, app"/>
    <r:layoutResources/>
    <g:layoutHead />

    <style id="antiClickjack">body{display:none !important;}</style>
    <script type="text/javascript">
       if (self === top) {
           var antiClickjack = document.getElementById("antiClickjack");
           antiClickjack.parentNode.removeChild(antiClickjack);

           $("#username").focus();
       } else {
           top.location = self.location;
       }
    </script>
  </head>

  <body>
    
    <header>      
      <g:render template='/templates/branding/header' />
    </header>

    <nav>
      <div class="container">
        <div class="navbar">
          <div class="navbar-inner">

            <ul class="nav">
              <li>
                <g:link controller="dashboard" action="welcome"><g:message encodeAs='HTML' code="branding.nav.welcome" /></g:link>
              </li>
              <li><a href="http://support.aaf.edu.au" target="_blank"><g:message encodeAs='HTML' code="branding.nav.support" /></a></li>
            </ul>

          </div>
        </div>
      </div>
    </nav>

    <section>
      <div class="container">
        <div class='notifications top-right'></div>
        <g:layoutBody/>
      </div>
    </section>
  
    <footer>
      <div class="container"> 
        <div class="row">
          <div class="span12">
            <g:render template='/templates/branding/footer' />
          </div>
        </div>
      </div>
    </footer>

    <r:layoutResources/>
  </body>

</html>
