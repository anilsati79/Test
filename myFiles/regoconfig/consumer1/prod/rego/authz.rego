package authz.policy
import data.identity.roles
import data.roles.permissions
import data.roles.allowedfields
import data.roles.authorization
import data.roles.part
import data.customer.allowedIpRanges
import data.customer.identities
import data.customer.portfolios
import input

default allow = false
default authorize = false
default isIdentityAuthorized = false
default isIpAllowed = false
default isMfaOk = false
default isIpFilteringOk = false
default isUserAuthorized = false

allow {
  isIdentityAuthorized
}

authorize = allowance {
  isIdentityAuthorized
  isIpFilteringOk
  isMfaOk
  isPortfolioOk
} else = denial

isIdentityAuthorized {
    not input.service
    identityRoles := roles[input.identity]
    identityPermisions := permissions[identityRoles[_]]
    identityPermisions[_][_] == input.resource
}

isIdentityAuthorized {
    input.service
    identityRoles := roles[input.identity]
    identityPermisions := permissions[identityRoles[_]]
    identityPermisions[input.service][_] == input.resource
}

serviceRoles[listOfRoles] {
  listOfRoles := roles[input.identity][_]
}

allowedFields[listOfFields] {
  listOfRoles := roles[input.identity]
  listOfFields := allowedfields[listOfRoles[_]][_]
}
authorizations[listOfFields] {
  listOfRoles := roles[input.identity]
  listOfFields := authorization[listOfRoles[_]][_]
}
parts[listOfFields] {
  listOfRoles := roles[input.identity]
  listOfFields := part[listOfRoles[_]][_]
}
isUserAuthorized {
    identityRoles := roles[input.identity]
    identityAuthorizations := authorization[identityRoles[_]]
    identityAuthorizations[_] == input.resource
}

isIpFilteringOk {
  not isIpFilteringEnabled
}

isIpFilteringOk {
  input.params["x-login-method"] == "ip-address"
  isIpAllowed
}

isMfaOk {
  not isMfaRequired
}

isMfaOk {
  input.params["x-login-method"] == "id-porten"
}

isPortfolioOk {
  not isPortfolioCheckRequired
}

isPortfolioCheckRequired {
    # NOTE: As of now we don't have dedicated mechanism to mark required Porfolio check
    # For this reason until more detailed Portfolio requirements will be provided we will support it when
    # service sends specific @AuthParam to OPA Server called `portfolio`
    input.params.portfolio
}

isPortfolioOk {
    identityRoles=roles[input.identity]
    identityAuthorizations=authorization[identityRoles[_]]
    identityAuthorizations[_]=="ALL_RW"
}

isPortfolioOk {
  identityInfo := customerWithIdentity
  identityPortfolios:=portfolios[identityInfo[_]]
  identityPortfolios[_]==input.params.portfolio
}

customerWithIdentity[customerId] {
  ids = identities[id]
  ids[_] == input.identity
  customerId := to_number(id)
}

allowance = {
  "allow" : true
}

denial = {
  "allow": false,
  "errors" : error
}

error[msg] {
  not isIdentityAuthorized
  msg := "Identity is not authorized to perform operation on this resource"
}

error[msg] {
  not isPortfolioOk
  msg := "Identity is not authorized to access customer's portfolio"
}

error[msg] {
  not isIpFilteringOk
  msg := "IP Filtering is enabled yet client IP doesn't match any allowed range"
}

error[msg] {
  not isMfaOk
  msg := "Specific login methods (like ID Porten) is required by customer yet not provided in authorization data"
}
