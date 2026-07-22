//! Pure navigation core shared by ordinary and deadline-bounded confirmations.
//!
//! Rendering, inactivity, the forced absolute deadline, and physical input
//! stay in `confirm.rs`.  This state machine owns only ordered page navigation,
//! scroll-to-end, cancel, and the FI-hardened affirmative sentinel.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NavigationInput {
    LeftShort,
    RightShort,
    LeftLong,
    RightLong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NavigationDecision {
    Continue,
    Cancelled,
    Confirmed(u32),
}

pub(crate) struct NavigationCore {
    page_index: usize,
    page_count: usize,
    seen_last: crate::fih::FihBool,
}

impl NavigationCore {
    pub(crate) fn new(page_count: usize) -> Option<Self> {
        if page_count == 0 {
            return None;
        }
        Some(Self {
            page_index: 0,
            page_count,
            seen_last: crate::fih::FihBool::new_false(),
        })
    }

    #[must_use]
    pub(crate) fn page_index(&self) -> usize {
        self.page_index
    }

    /// Call only after the current page was painted.  The last-page gate is
    /// therefore evidence of display, not merely an index assignment.
    pub(crate) fn mark_current_page_rendered(&mut self) {
        if self.page_index + 1 >= self.page_count {
            self.seen_last.set_true();
        }
    }

    pub(crate) fn handle(&mut self, input: NavigationInput) -> NavigationDecision {
        match input {
            NavigationInput::RightShort => {
                self.advance();
                NavigationDecision::Continue
            }
            NavigationInput::LeftShort => {
                if self.page_index > 0 {
                    self.page_index -= 1;
                }
                NavigationDecision::Continue
            }
            NavigationInput::RightLong => {
                let gate = self.seen_last.check_sentinel();
                if gate == crate::fi::OK_SENTINEL {
                    NavigationDecision::Confirmed(gate)
                } else {
                    self.advance();
                    NavigationDecision::Continue
                }
            }
            NavigationInput::LeftLong => NavigationDecision::Cancelled,
        }
    }

    fn advance(&mut self) {
        if self.page_index + 1 < self.page_count {
            self.page_index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_navigation_is_rejected() {
        assert!(NavigationCore::new(0).is_none());
    }

    #[test]
    fn long_right_cannot_skip_scroll_order() {
        let mut nav = NavigationCore::new(3).unwrap();
        nav.mark_current_page_rendered();
        assert_eq!(
            nav.handle(NavigationInput::RightLong),
            NavigationDecision::Continue
        );
        assert_eq!(nav.page_index(), 1);
        nav.mark_current_page_rendered();
        assert_eq!(
            nav.handle(NavigationInput::RightLong),
            NavigationDecision::Continue
        );
        assert_eq!(nav.page_index(), 2);
        nav.mark_current_page_rendered();
        assert_eq!(
            nav.handle(NavigationInput::RightLong),
            NavigationDecision::Confirmed(crate::fi::OK_SENTINEL)
        );
    }

    #[test]
    fn cancel_is_immediate_from_every_page() {
        let mut nav = NavigationCore::new(29).unwrap();
        nav.mark_current_page_rendered();
        nav.handle(NavigationInput::RightShort);
        assert_eq!(
            nav.handle(NavigationInput::LeftLong),
            NavigationDecision::Cancelled
        );
    }

    #[test]
    fn back_navigation_does_not_clear_seen_last() {
        let mut nav = NavigationCore::new(2).unwrap();
        nav.mark_current_page_rendered();
        nav.handle(NavigationInput::RightShort);
        nav.mark_current_page_rendered();
        nav.handle(NavigationInput::LeftShort);
        assert_eq!(nav.page_index(), 0);
        assert_eq!(
            nav.handle(NavigationInput::RightLong),
            NavigationDecision::Confirmed(crate::fi::OK_SENTINEL)
        );
    }
}
