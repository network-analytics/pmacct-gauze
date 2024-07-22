use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;

use crate::capi::features::prefix_tree::{NodeType, Prefix};
use crate::capi::features::prefix_tree::classic::PrefixTree;

pub trait Rib<Pfx, Value> {
    fn insert(&mut self, prefix: Pfx, value: Value);
    fn delete(&mut self, prefix: &Pfx) -> Option<Value>;
    fn lookup_mut(&mut self, prefix: &Pfx) -> Option<&mut Value>;
    fn lookup(&self, prefix: &Pfx) -> Option<&Value>;
    fn longest_prefix_match_mut(&mut self, prefix: &Pfx) -> Option<(Pfx, &mut Value)>;
    fn longest_prefix_match(&self, prefix: &Pfx) -> Option<(Pfx, &Value)>;

    fn walk(&self, f: impl FnMut(&Pfx, &Value));
}

#[derive(Default)]
pub struct RibPrefixTree<Pfx, Value>
where
    Pfx: Prefix + Hash,
{
    tree: PrefixTree<Pfx>,
    map: HashMap<Pfx, Value>,
}

impl<Pfx: Prefix + Hash, Value: Debug> Debug for RibPrefixTree<Pfx, Value> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("RibPrefixTree");
        debug.field("map", &self.map);
        debug.finish()
    }
}

impl<Pfx, Value> Rib<Pfx, Value> for RibPrefixTree<Pfx, Value>
where
    Pfx: Clone + Prefix + Hash,
{
    fn insert(&mut self, prefix: Pfx, value: Value) {
        self.tree.insert(prefix.clone());
        self.map.insert(prefix, value);
    }

    fn delete(&mut self, prefix: &Pfx) -> Option<Value> {
        self.tree.delete(prefix);
        self.map.remove(prefix)
    }

    fn lookup(&self, prefix: &Pfx) -> Option<&Value> {
        self.map.get(prefix)
    }

    fn lookup_mut(&mut self, prefix: &Pfx) -> Option<&mut Value> {
        self.map.get_mut(prefix)
    }

    fn longest_prefix_match_mut(&mut self, prefix: &Pfx) -> Option<(Pfx, &mut Value)> {
        let node = self.tree.longest_prefix_match(prefix)?;

        let prefix = node.borrow().prefix.clone();
        let value = self.map.get_mut(&prefix).unwrap();
        Some((prefix, value))
    }

    fn longest_prefix_match(&self, prefix: &Pfx) -> Option<(Pfx, &Value)> {
        let node = self.tree.longest_prefix_match(prefix)?;

        let prefix = node.borrow().prefix.clone();
        let value = self.map.get(&prefix).unwrap();
        Some((prefix, value))
    }

    fn walk(&self, mut f: impl FnMut(&Pfx, &Value)) {
        self.tree.walk(|node_ref| {
            match node_ref.borrow().node_type {
                NodeType::Entry => {
                    let prefix = &node_ref.borrow().prefix;
                    let value = self.map.get(prefix).unwrap();
                    f(prefix, value);
                }
                NodeType::Structural => {}
            };
        });
    }
}