---- MODULE Common ----
EXTENDS Variants

NOT_SPAWNING == Variant("NotSpawning", UNIT)
SPAWNING == Variant("Spawning", UNIT)

\* Initial value used for uninitialized accounts
DUMMY_ACCOUNT == ""

\* @type: (a -> b, Set(a)) => a -> b;
Remove_Arguments(f, S) == [ x \in (DOMAIN f \ S) |-> f[x]]

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
account_balance(account) == Variant("AccountBalance", [account |-> account])
transfer(from, to, amount, fee) == Variant("Transfer", [from |-> from, to |-> to, amount |-> amount, fee |-> fee])

TRANSFER_OK == "Ok"
TRANSFER_FAIL == "Err"

====
