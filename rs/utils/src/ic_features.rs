features! {
    // Following are the feature toggles for copy on write state management.
    // Each flag controls whether each subcomponent's implementation for cow
    // state management is enabled or not. By default all the feature toggle
    // are disabled. They can be explicitly enabled during tests. For more
    // information please refer to features crates documentation.
    pub mod cow_state_feature {
        const cow_state = 0b0000_0001
    }

}

features! {
    // Sandboxed Execution
    pub mod sandboxed_execution_feature {
        const sandboxed_execution = 0b0000_0001
    }
}
