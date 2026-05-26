/// Trace-level logging (gated on `test` or `debug` feature).
#[macro_export]
macro_rules! trace {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::trace!($($tts)*)
    }
}

/// Debug-level logging (gated on `test` or `debug` feature).
#[macro_export]
macro_rules! debug {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::debug!($($tts)*)
    }
}

/// Warning-level logging.
#[macro_export]
macro_rules! warn {
    ($($tts:tt)*) => {
        tracing::warn!($($tts)*)
    }
}

/// Info-level logging.
#[macro_export]
macro_rules! info {
    ($($tts:tt)*) => {
        tracing::info!($($tts)*)
    }
}

/// Error-level logging.
#[macro_export]
macro_rules! error {
    ($($tts:tt)*) => {
        tracing::error!($($tts)*)
    }
}

/// Trace-level span (gated on `test` or `debug` feature).
#[macro_export]
macro_rules! trace_span {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::trace_span!($($tts)*)
    }
}

/// Debug-level span (gated on `test` or `debug` feature).
#[macro_export]
macro_rules! debug_span {
    ($($tts:tt)*) => {
        #[cfg(any(test, feature="debug"))]
        tracing::debug_span!($($tts)*)
    }
}

/// Warning-level span.
#[macro_export]
macro_rules! warn_span {
    ($($tts:tt)*) => {
        tracing::warn_span!($($tts)*)
    }
}

/// Info-level span.
#[macro_export]
macro_rules! info_span {
    ($($tts:tt)*) => {
        tracing::info_span!($($tts)*)
    }
}

/// Error-level span.
#[macro_export]
macro_rules! error_span {
    ($($tts:tt)*) => {
        tracing::error_span!($($tts)*)
    }
}
