//! Allow-list à l'**émission** des events : économise CPU + disque + bande
//! passante par rapport à un filtrage côté serveur (events refusés ne sont
//! ni sérialisés, ni spoolés, ni envoyés).
//!
//! Configuré dans la section `filter` de `agent.json`. Source de vérité
//! côté serveur (`wazabi-filter.toml`), poussée au bootstrap via
//! `GET /api/v1/bootstrap/agent.json`. L'admin peut aussi l'éditer
//! directement sur l'endpoint (restart nécessaire — pas de hot-reload).
//!
//! ```json
//! {
//!   "filter": {
//!     "modules":     ["kernel_callback", "plugin"],
//!     "event_types": ["process_create", "process_terminate"]
//!   }
//! }
//! ```
//!
//! Une liste vide / absente signifie "tout passe pour ce critère". Section
//! `filter` complètement absente = pas de filtre du tout (comportement par
//! défaut, identique à la version pré-filtre).
//!
//! La granularité s'arrête au couple `(module, event_type)`. Pour les
//! events plugin, tous ont `event_type = "plugin_event"` et `module =
//! "plugin"` — donc l'allow-list contrôle le canal entier (on/off), pas
//! le `kind` interne du plugin. Filtrer par `kind` viendra avec les
//! règles Waza côté agent.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Deserialize, Debug, Default, Clone)]
pub struct FilterSection {
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
}

#[derive(Debug)]
pub struct Filter {
    modules: HashSet<String>,
    event_types: HashSet<String>,
}

static GLOBAL: OnceLock<Filter> = OnceLock::new();

impl Filter {
    fn from_section(section: FilterSection) -> Self {
        Self {
            modules: section.modules.into_iter().collect(),
            event_types: section.event_types.into_iter().collect(),
        }
    }

    /// Returns `true` if the event should be kept, `false` if dropped.
    /// An empty allow-set on a given dimension means "no restriction" —
    /// matches the server-side semantics so admins can reason about both.
    pub fn allows(&self, module: &str, event_type: &str) -> bool {
        if !self.modules.is_empty() && !self.modules.contains(module) {
            return false;
        }
        if !self.event_types.is_empty() && !self.event_types.contains(event_type) {
            return false;
        }
        true
    }

    fn is_active(&self) -> bool {
        !self.modules.is_empty() || !self.event_types.is_empty()
    }
}

/// Initialise le filtre global au boot. Idempotent : un deuxième appel
/// ne remplace pas la valeur (le `OnceLock` la conserve).
pub fn init(section: Option<FilterSection>) {
    let filter = Filter::from_section(section.unwrap_or_default());
    let active = filter.is_active();
    let _ = GLOBAL.set(filter);
    if active {
        let f = GLOBAL.get().expect("set above");
        eprintln!(
            "[agent] event filter active — modules={:?} event_types={:?}",
            f.modules, f.event_types
        );
    }
}

/// Check d'un event. Si le filtre n'a pas été initialisé (init pas appelé,
/// cas de test), on laisse passer — fail-open est volontaire ici : un
/// EDR avec un filtre cassé doit continuer à voir les events, pas
/// silencieusement en perdre.
#[inline]
pub fn allows(module: &str, event_type: &str) -> bool {
    GLOBAL.get().map_or(true, |f| f.allows(module, event_type))
}
