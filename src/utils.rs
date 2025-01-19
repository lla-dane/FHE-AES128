#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        println!(
            "[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            format!($($arg)*)
        );
    };
}
