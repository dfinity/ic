//! Here we define a number of macros to aid in the creation of composable pots.
//! Recall a composable pot consists in a configuration, a potential setup
//! and a set of steps.

/// Defines a single `crate::inner::pot::FondueTest` either based on its rust
/// name or with an explicit name.
#[macro_export]
macro_rules! comp_step {
    ($a:path) => {
        pot::FondueTest::new(std::stringify!($a), $a)
    };
    ($a:path => $name:expr) => {
        pot::FondueTest::new($name, $a)
    };
}

/// The [steps] macro can be thought of as defining a set of steps. Yet, a
/// subtle but important trick is at play here: we actually generate a closure
/// that receives no arguments and returns a vector with the provided steps.
/// This means that we can call the result of [steps] as many times as we want,
/// generating the same vector of steps but without having to rquire that
/// `crate::pot::FondueTest` is ever cloneable. Essentially, the fondue tests
/// get regenerated. Check [composable_confs_option_setup] for a place where
/// this is necessary.
#[macro_export]
macro_rules! steps {
    { $($steps:path $(=> $name:expr)? ),* } => {
        {
            move || {
                let mut v = Vec::new();
                $(v.push(comp_step!($steps $(=> $name)?));)*
                v
            }
        }
    };
}

/// This is the most general way of creating a composable pot,
/// it needs a path to a configuration, a setup function and
/// a closure that returns a vector of steps, which can be created using the
/// [steps] macro. For example, assume the existence of a type `MyManager :
/// Manager` and of a module:
///
/// ```ignore
/// mod my_composable_tests {
///     pub fn config() -> MyManager::Config { ... }
///     pub fn setup(man: MyManager, ctx: pot::Context<MyManager>) { ... }
///     pub fn test1(man: MyManager::Handle, ctx: pot::Context<MyManager>) { ... }
///     pub fn test2(man: MyManager::Handle, ctx: pot::Context<MyManager>) { ... }
///     pub fn test3(man: MyManager::Handle, ctx: pot::Context<MyManager>) { ... }
/// }
/// ```
///
/// The following call to [composable_option_setup] will create a composable
/// test that will initialize the manager according to `my_composable_tests::
/// config()`, execute the `setup` phase then run `test1`, `test2` and `test3`
/// in no particular order. It will use the fully qualified name unless
/// specified otherwise and will apply the user provided suffix to all of the
/// names. In the example below, it uses the fully qualified
/// names for `test1` and `test2`, but renames `test3` to `"new_test3_name";
///
/// ```ignore
/// fn my_pot() -> pot::Pot<MyManager> {
///     composable_option_setup!(
///         my_composable_tests::config(),
///         Some(my_composable_tests::setup()),
///         steps!{
///             my_composable_tests::test1,
///             my_composable_tests::test2,
///             my_composable_tests::test3 => "new_test3_name"
///         }
///     )
/// }
/// ```
#[macro_export]
macro_rules! composable {
    ($name:literal, $config:expr, $steps:expr) => {
        pot::from_composable_setup($name, &$config, None, $steps().into_iter(), false)
    };
}

#[macro_export]
macro_rules! composable_experimental {
    ($name:literal, $config:expr, $steps:expr) => {
        pot::from_composable_setup($name, &$config, None, $steps().into_iter(), true)
    };
}

/// Similar to [composable], but requires the presence of a setup function.
#[macro_export]
macro_rules! composable_setup {
    ($name:literal, $config:expr, $setup:expr, $steps:expr) => {
        pot::from_composable_setup($name, &$config, Some($setup), $steps().into_iter(), false)
    };
}

/// Similarly to [composable_option_setup], but generates a vector of pots.
/// One for each specified configuration. Say we want the two tests `test_A` and
/// `test_B`, but against three possible configurations: we create three
/// separate pots with the same steps, which is exactly what
/// [composable_confs_option_setup] does.
///
/// Without [composable_confs_option_setup], we could do something like:
///
/// ```ignore
/// fn my_pots() -> pot::Pot<MyManager> {
///     vec![
///         composable_option_setup!(
///             config_1(),
///             Some(my_composable_tests::setup()),
///             steps!{
///                 test_A => "test_A_cfg1",
///                 test_B => "test_B_cfg1",
///             }
///         ),
///         composable_option_setup!(
///             config_2(),
///             Some(my_composable_tests::setup()),
///             steps!{
///                 test_A => "test_A_cfg2",
///                 test_B => "test_B_cfg2",
///             }
///         ),
///         composable_option_setup!(
///             config_3(),
///             Some(my_composable_tests::setup()),
///             steps!{
///                 test_A => "test_A_cfg3",
///                 test_B => "test_B_cfg3",
///             }
///         ),
///    ]
/// }
/// ```
///
/// Which is equivalent to:
///
/// ```ignore
/// fn my_pots() -> pot::Pot<MyManager> {
///     composable_confs_option_setup!(
///         [(config_1(), "_cfg1"), (config_2(), "_cfg2"), (config_3(), "_cfg3")],
///         Some(my_composable_tests::setup()),
///         steps!{
///             test_A,
///             test_B,
///         }
///     ),
/// }
/// ```
///
/// Note that if `steps!` returned a vector instead of a closure, we would have
/// to clone said vector for each config we are instantiating the pot with.
#[macro_export]
macro_rules! composable_confs_option_setup {
   ($pot_name:literal, [ $(($config:expr, $name:expr)),+ ] , $setup:expr, $steps:expr) => {
       {
           let mut v = vec![];
           $(
               let p = pot::from_composable_setup(
                   $pot_name,
                   &$config,
                   $setup,
                   $steps().into_iter().map(|s| s.suffix_name($name)),
                   false
               );
               v.push(p);
           )+
           v
       }
   };
}

/// Creates an isolated test from a module that contains a `config` and `test`
/// functions appropriately typed. For example, assume the existence of
/// a type `MyManager : Manager` and of a module:
///
/// ```ignore
/// mod test_number_one {
///     pub fn config() -> MyManager::Config { ... }
///     pub fn test(man: MyManager, ctx: pot::Context<MyManager>) { ... }
/// }
/// ```
///
/// Then, the following two code blocks are equivalent:
///
/// ```ignore
/// fn my_pot() -> pot::Pot<MyManager> {
///     isolated_test!(test_number_one)
/// }
/// ```
///
/// ```ignore
/// fn my_pot() -> pot::Pot<MyManager> {
///     pot::from_isolated("test_number_one", test_number_one::config(), test_number_one::test)
/// }
/// ```
#[macro_export]
macro_rules! isolated_test {
    ($mod:ident) => {
        pot::from_isolated(std::stringify!($mod), &$mod::config(), $mod::test)
    };
}
