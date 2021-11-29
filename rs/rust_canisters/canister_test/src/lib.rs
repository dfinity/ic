/*!
This is a test runner for wasm code. This is based off the replica tests but it is more focused on unit testing the WASM rather than the runtime.

It's pretty tedious dealing with bytes all the time so this is designed to be extensible to any type of serialization and deserialisation format.

As an example let us sketch out how to extend these tests to work with canisters the consume and produce JSON.

```ignore
use canister_test::*;
# trait ToJSON{}
# trait FromJSON{}
# impl FromJSON for String {}
# impl ToJSON for &str {}
# impl ToJSON for () {}

trait JSONCall{
    fn json<Res: FromJSON, Payload: ToJSON>
    (&self, payload: Payload) -> Res;
}
trait JSONInstaller<'a>{
    fn json<Payload: ToJSON>
    (self, payload: Payload) -> Canister<'a>;
}

impl<'a> JSONCall for Query<'a> {
    fn json<Res: FromJSON, Payload: ToJSON>
        (&self, payload: Payload) -> Res {
#        unimplemented!()
    }
}

impl<'a> JSONCall for Update<'a> {
    fn json<Res: FromJSON, Payload: ToJSON>
        (&self, payload: Payload) -> Res {
#        unimplemented!()
    }
}

impl<'a> JSONInstaller<'a> for Install<'a> {
    fn json<Payload: ToJSON>
        (self, payload: Payload) -> Canister<'a> {
#        unimplemented!()
    }
}

fn reverse_test(){
    canister_test(|r|{
        let canister =
            WASM::from_file("canister.wasm")
            .install(&r)
            .json(());

        let res: String =
            canister
            .query("reverse")
            .json("desserts");

        assert_eq!(res, "stressed");
    })
}
```
If you find you're getting linker errors on Linux add

[target.wasm32-unknown-unknown]
rustflags = ["-C", "link-arg="]

to .cargo/config
*/
mod canister;
mod cargo_bin;
pub mod runner;
pub use canister::*;
pub use cargo_bin::*;
pub use ic_replica_tests::LocalTestRuntime;
