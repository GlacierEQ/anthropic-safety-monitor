pub struct ActionBoundaryChecker {
    pub max_file_mutations: usize,
    pub active_mutations: usize,
}

impl ActionBoundaryChecker {
    pub fn new(max_mutations: usize) -> Self {
        ActionBoundaryChecker {
            max_file_mutations: max_mutations,
            active_mutations: 0,
        }
    }

    pub fn validate_action(&mut self, action_name: &str) -> bool {
        if action_name == "delete_root" || action_name == "hard_reset" {
            return false;
        }
        self.active_mutations += 1;
        self.active_mutations <= self.max_file_mutations
    }
}
