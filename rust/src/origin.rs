//! Provenance for effective invocation policy values.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Default,
    Cli,
    Global,
    Profile(String),
    Preset(String),
    Project,
    Derived,
    App,
}

impl Origin {
    pub fn tag(&self) -> String {
        match self {
            Self::Default => "[default]".to_string(),
            Self::Cli => "[cli]".to_string(),
            Self::Global => "[global]".to_string(),
            Self::Profile(id) => format!("[profile:{}]", terminal_safe(id)),
            Self::Preset(name) => format!("[preset:{}]", terminal_safe(name)),
            Self::Project => "[project]".to_string(),
            Self::Derived => "[derived]".to_string(),
            Self::App => "[app]".to_string(),
        }
    }
}

pub fn terminal_safe(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            result.extend(character.escape_default());
        } else {
            result.push(character);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_tags_escape_terminal_controls() {
        assert_eq!(
            Origin::Preset("safe\n\u{1b}[2J".into()).tag(),
            "[preset:safe\\n\\u{1b}[2J]"
        );
        assert_eq!(
            Origin::Profile("safe\n\u{1b}[2J".into()).tag(),
            "[profile:safe\\n\\u{1b}[2J]"
        );
    }
}
