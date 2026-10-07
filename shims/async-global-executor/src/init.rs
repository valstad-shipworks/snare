/// Init the global executor, spawning as many threads as specified or
/// the value specified by the specified environment variable.
///
/// # Examples
///
/// ```
/// async_global_executor::init_with_config(
///     async_global_executor::GlobalExecutorConfig::default()
///         .with_env_var("NUMBER_OF_THREADS")
///         .with_min_threads(4)
///         .with_max_threads(6)
///         .with_thread_name_fn(Box::new(|| "worker".to_string()))
/// );
/// ```
pub fn init_with_config(config: crate::config::GlobalExecutorConfig) {
    let _ = crate::config::GLOBAL_EXECUTOR_CONFIG.set(config.seal());
    init();
}

/// Init the global executor, spawning as many threads as the number or cpus or
/// the value specified by the `ASYNC_GLOBAL_EXECUTOR_THREADS` environment variable
/// if specified.
///
/// # Examples
///
/// ```
/// async_global_executor::init();
/// ```
pub fn init() {
    let pool = crate::executor::Pool::get();
    if pool.start() {
        let config =
            crate::config::GLOBAL_EXECUTOR_CONFIG.get_or_init(crate::config::Config::default);
        crate::reactor::block_on(async {
            crate::threading::spawn_more_threads_in(pool, config.min_threads)
                .await
                .expect("cannot spawn executor threads");
        });
    }
}
