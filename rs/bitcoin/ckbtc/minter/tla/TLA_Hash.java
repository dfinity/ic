// package tlc2.overrides;
import tlc2.value.impl.Value;
import tlc2.value.impl.IntValue;

public final class TLA_Hash {
    // @TLAPlusOperator(identifier = "Hash", module = "TLA_Hash", warn = false)
    public static Value Hash(Value v){
        return IntValue.gen(v.hashCode());
    }
}