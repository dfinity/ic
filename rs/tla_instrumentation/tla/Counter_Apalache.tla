---- MODULE Counter_Apalache ----

EXTENDS TLC, Sequences, Variants

\* The constants similar to the ones below will be inserted by the code link
\* at the CODE_LINK_INSERT_CONSTANTS marker.
(*
MAX_COUNTER == 2
My_Method_Process_Ids == {"Counter"}
*)

\* CODE_LINK_INSERT_CONSTANTS


(*
@typeAlias: proc = Str;
@typeAlias: methodCall = Target_Method(Int);
@typeAlias: methodResponse = Fail(UNIT) | Ok(Int);
*)
_type_alias_dummy == TRUE

VARIABLES
    \* @type: Int;
    counter,
    \* @type: $proc -> Int;
    my_local,
    \* @type: Seq({caller : $proc, method_and_args: $methodCall });
    mycan_to_othercan,
    \* @type: Set({caller: $proc, response: $methodResponse });
    othercan_to_mycan,
    \* @type: $proc -> Str;
    pc

MOD == INSTANCE Counter

Next == [MOD!Next]_MOD!vars

====