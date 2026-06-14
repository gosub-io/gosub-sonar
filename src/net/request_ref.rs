//! Correlation tags for tracking fetch requests without coupling to application internals.

use std::fmt::Display;

/// Request references tag a fetch with an application-defined correlation ID,
/// without the net layer needing to know about higher-level concepts like tabs
/// or navigation stacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum RequestReference {
    /// A numbered background or prefetch task
    Background(u64),
    /// An application-defined opaque task group ID
    Tagged(u64),
}

impl Default for RequestReference {
    fn default() -> Self {
        RequestReference::Background(0)
    }
}

impl Display for RequestReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestReference::Background(id) => write!(f, "BG({})", id),
            RequestReference::Tagged(id) => write!(f, "Tagged({})", id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_background() {
        assert_eq!(format!("{}", RequestReference::Background(42)), "BG(42)");
    }

    #[test]
    fn display_tagged() {
        assert_eq!(format!("{}", RequestReference::Tagged(7)), "Tagged(7)");
    }
}
