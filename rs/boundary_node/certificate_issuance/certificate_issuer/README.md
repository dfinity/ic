# Certificate Issuer

The Certificate Issuer is a service that issues certificates for canisters. 

## Checker

It features a checker, which checks whether an asset canister has a 
well-known file that lists the domain name in question. The checker uses
the `ic-agent` to query the asset canister for the `.well-known/custom-domains`
file.

## Changelog

### 0.1.1

* Use `ic-agent` to perform the check for the `.well-known/custom-domains` file
  instead of making a http request to the canister.
