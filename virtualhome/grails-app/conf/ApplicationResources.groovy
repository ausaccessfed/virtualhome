modules = { 
  'pwmask' {
    // http://unwrongest.com/projects/show-password/

    dependsOn 'jquery'
    resource url: 'js/jquery.showpassword.1.3.min.js', attrs:[type:'js']
  }
  'pulse' {
    dependsOn 'jquery'
    resource url: 'js/jquery.pulse.min.js', attrs:[type:'js']
  }
  'app' {
    dependsOn 'app_base'
    resource url: 'css/application.css', attrs:[rel:'stylesheet/less', type:'css']
    resource url: 'js/application.js', attrs:[type:'js']
  }
}
