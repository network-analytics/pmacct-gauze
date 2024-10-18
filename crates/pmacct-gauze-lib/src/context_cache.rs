use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone)]
pub struct ContextCache<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> Default for ContextCache<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

impl<K, V> Deref for ContextCache<K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<K, V> DerefMut for ContextCache<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}
