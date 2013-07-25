class SecurityFilters {

  def filters = {
    dashboard_authenticated(uri:"/dashboard/**") {
      before = {
        accessControl { true }
      }
    }
    organization_authenticated(uri:"/organisations/**") {
      before = {
        accessControl { true }
      }
    }
    organization_authenticated(uri:"/groups/**") {
      before = {
        accessControl { true }
      }
    }
    organization_authenticated(uri:"/accounts/**") {
      before = {
        accessControl { true }
      }
    }
    backend_authenticated(uri:"/backend/**") {
      before = {
        accessControl { true }
      }
    }
  }
}
