---- MODULE Counter ----
EXTENDS TLC, Naturals, Variants, Sequences

CONSTANTS 
    My_Method_Process_Ids,
    MAX_COUNTER

request(caller, request_args) == [caller |-> caller, method_and_args |-> request_args]
target(value) == Variant("Target_Method", value)

(* --algorithm Counter {

variables 
    counter = 0;
    mycan_to_othercan = <<>>;
    othercan_to_mycan = {};

process ( My_Method \in My_Method_Process_Ids )
    variable my_local = 0;
{
    Start_Label:
        counter := counter + 1;
        my_local := counter;
        mycan_to_othercan := Append(mycan_to_othercan, request(self, target(2)));
    WaitForResponse:
        with(resp \in { r \in othercan_to_mycan: r.caller = self }) {
            othercan_to_mycan := othercan_to_mycan \ {resp};
            counter := counter + 1;
            my_local := counter;
        }
}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "87a0b4ea" /\ chksum(tla) = "d0aa893")
VARIABLES counter, mycan_to_othercan, othercan_to_mycan, pc, my_local

vars == << counter, mycan_to_othercan, othercan_to_mycan, pc, my_local >>

ProcSet == (My_Method_Process_Ids)

Init == (* Global variables *)
        /\ counter = 0
        /\ mycan_to_othercan = <<>>
        /\ othercan_to_mycan = {}
        (* Process My_Method *)
        /\ my_local = [self \in My_Method_Process_Ids |-> 0]
        /\ pc = [self \in ProcSet |-> "Start_Label"]

Start_Label(self) == /\ pc[self] = "Start_Label"
                     /\ counter' = counter + 1
                     /\ my_local' = [my_local EXCEPT ![self] = counter']
                     /\ mycan_to_othercan' = Append(mycan_to_othercan, request(self, target(2)))
                     /\ pc' = [pc EXCEPT ![self] = "WaitForResponse"]
                     /\ UNCHANGED othercan_to_mycan

WaitForResponse(self) == /\ pc[self] = "WaitForResponse"
                         /\ \E resp \in { r \in othercan_to_mycan: r.caller = self }:
                              /\ othercan_to_mycan' = othercan_to_mycan \ {resp}
                              /\ counter' = counter + 1
                              /\ my_local' = [my_local EXCEPT ![self] = counter']
                         /\ pc' = [pc EXCEPT ![self] = "Done"]
                         /\ UNCHANGED mycan_to_othercan

My_Method(self) == Start_Label(self) \/ WaitForResponse(self)

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == (\E self \in My_Method_Process_Ids: My_Method(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

====
