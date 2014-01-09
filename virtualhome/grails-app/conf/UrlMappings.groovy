class UrlMappings {

  static mappings = {

    "/"(controller:"dashboard", action:"welcome")

    "/login" {
      controller="login"
      action="index"
    }
    "/login/$action?" {
      controller="login"
    }

    "/myaccount/setup/login-available" {
      controller="finalization"
      action="loginAvailable"
    }
    "/myaccount/setup/complete" {
      controller="finalization"
      action="complete"
    }
    "/myaccount/setup/used" {
      controller="finalization"
      action="used"
    }
    "/myaccount/setup/error" {
      controller="finalization"
      action="error"
    }
    "/myaccount/setup/$inviteCode" {
      controller="finalization"
    }
    "/myaccount" {
      controller="account"
      action="index"
    }
    "/myaccount/login" {
      controller="account"
      action="login"
    }
    "/myaccount/twosteplogin" {
      controller="account"
      action="twosteplogin"
    }
    "/myaccount/logout" {
      controller="account"
      action="logout"
    }
    "/myaccount/details" {
      controller="account"
      action="show"
    }
    "/myaccount/changedetails" {
      controller="account"
      action="changedetails"
    }
    "/myaccount/completedetailschange" {
      controller="account"
      action="completedetailschange"
    }
    "/myaccount/enabletwostep" {
      controller="account"
      action="enabletwostep"
    }
    "/myaccount/setuptwostep" {
      controller="account"
      action="setuptwostep"
    }
    "/myaccount/completesetuptwostep" {
      controller = "account"
      action = "completesetuptwostep"
    }

    "/lostpassword/$action" {
      controller="lostPassword"
    }
    "/lostusername/$action" {
      controller="lostUsername"
    }

    "/dashboard"(controller:"dashboard", action:"dashboard")

    "/accounts/list" {
      controller="managedSubject"
      action="list"
    }
    "/groups/list" {
      controller="group"
      action="list"
    }

    "/organisations/groups/accounts/$action/$id?" {
      controller="managedSubject"
    }
    "/organisations/groups/$action/$id?" {
      controller="group"
    }
    "/organisations/$action/$id?" {
      controller="organization"
    }

    "/backend/manageadministrators/$action/$id?" {
      controller="manageAdministrators"
    }

    "/api/v1/login/$action/$sessionID" (controller: "loginApi")
    "/api/v1/organizations/$action/$id?" (controller: "organizationApi")
  }

}
