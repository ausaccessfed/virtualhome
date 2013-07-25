<!DOCTYPE html>
<html>
  <head>
    <title><g:message encodeAs='HTML' code='branding.application.name'/></title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="shortcut icon" href="${resource(dir:'images', file:'favicon.ico')}" />
        
    <r:require modules="modernizr, bootstrap, bootstrap-responsive-css, bootstrap-notify, bootstrap-datepicker, bootbox, less, validate, datatables, formrestrict, highcharts, app"/>
    <r:layoutResources/>
    <g:layoutHead />
  </head>

  <body>

    <header>      
      <g:render template='/templates/branding/header' />
    </header>

    <nav>
      <g:render template='/templates/branding/topnavigation'/>
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

    <g:render plugin="aafApplicationBase" template='/templates/session_check'/>

    <r:layoutResources/>
  </body>

</html>
