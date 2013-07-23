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
    "/myaccount/logout" {
      controller="account"
      action="logout"
    }
    "/myaccount/details" {
      controller="account"
      action="show"
    }
    "/myaccount/changepassword" {
      controller="account"
      action="changepassword"
    }
    "/myaccount/completepasswordchange" {
      controller="account"
      action="completepasswordchange"
    }
    "/lostpassword/$action" {
      controller="lostPassword"
    }
    "/lostusername/$action" {
      controller="lostUsername"
    }
    "/migration/$action" {
      controller="migrate"
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
