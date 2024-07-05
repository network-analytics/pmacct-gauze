use std::cell::RefCell;
use std::cmp::{Ordering, PartialEq};
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use ipnet::Ipv4Net;

#[derive(Default, Clone)]
pub struct PrefixTree {
    top: Option<NodeRef>,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct NodeRef(Rc<RefCell<Node>>);


// UNUSED ATM
// TODO use and mark removed nodes and "common_node" results as Structural so they can be pruned
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum NodeType {
    Real,
    Structural,
}

#[derive(Clone)]
pub struct Node {
    prefix: Ipv4Net,
    left: Option<NodeRef>,
    right: Option<NodeRef>,
    parent: Option<NodeRef>,
}

impl Debug for PrefixTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut nodes = BTreeSet::<Node>::new();

        let mut node = self.top.clone();
        while let Some(noderef) = node.clone() {
            nodes.insert(noderef.borrow().clone());

            if let Some(left) = &noderef.borrow().left && !nodes.contains(&left.borrow().clone()) {
                node = Some(left.clone());
            } else if let Some(right) = &noderef.borrow().right && !nodes.contains(&right.borrow().clone()) {
                node = Some(right.clone());
            } else if noderef.borrow().parent != node {
                node = noderef.borrow().parent.clone()
            } else {
                break;
            }
        }

        let mut debug = f.debug_struct("PrefixTree");
        debug.field("top", &self.top);
        debug.field("nodes", &nodes);
        debug.finish()
    }
}


impl NodeRef {
    pub fn new(
        prefix: Ipv4Net,
        left: Option<NodeRef>,
        right: Option<NodeRef>,
        parent: Option<NodeRef>,
    ) -> Self {
        let node = Node {
            prefix,
            left,
            right,
            parent,
        };

        NodeRef(Rc::new(RefCell::new(node)))
    }
}
impl Deref for NodeRef {
    type Target = Rc<RefCell<Node>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeRef {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Eq for Node {}

impl PartialEq<Self> for Node {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}

impl PartialOrd<Self> for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.prefix.partial_cmp(&other.prefix)
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        self.prefix.cmp(&other.prefix)
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Node");

        debug.field("prefix", &self.prefix);
        debug.field("left", &self.left.as_ref().map(|noderef| noderef.borrow().prefix));
        debug.field("right", &self.right.as_ref().map(|noderef| noderef.borrow().prefix));
        debug.field("parent", &self.parent.as_ref().map(|noderef| noderef.borrow().prefix));

        debug.finish()
    }
}

pub fn compute_branch(parent: &Ipv4Net, child: &Ipv4Net) -> Branch {
    let prefix_max_len = parent.max_prefix_len();
    let parent_len = parent.prefix_len();
    // shift to get next bit of the child network address
    // the next bit is the bit in the child following the parent network address
    let shift = prefix_max_len - parent_len - 1;

    // if the next bit is one the child goes to the left (we could do the opposite)
    match (child.network().to_bits() >> shift) & 1 == 1 {
        true => Branch::Left,
        false => Branch::Right
    }
}

pub fn common_node(node: &NodeRef, route: &Ipv4Net) -> NodeRef {
    let first = node.borrow().prefix;
    let first_addr = first.network().to_bits();
    let second_addr = route.network().to_bits();

    let common_bits = (first_addr ^ second_addr).leading_zeros();
    let common_mask = u32::MAX << (u32::BITS - common_bits);

    let common_route = Ipv4Net::new(
        Ipv4Addr::from_bits(first_addr & common_mask),
        common_bits as u8,
    ).unwrap();

    NodeRef::new(common_route, None, None, node.borrow().parent.clone())
}
impl Node {
    pub fn set_right_node(&mut self, child: Option<NodeRef>) {
        self.right = child
    }

    pub fn set_left_node(&mut self, child: Option<NodeRef>) {
        self.left = child
    }

    pub fn set_child_node(&mut self, child: Option<NodeRef>, branch: Branch) {
        match branch {
            Branch::Left => self.set_left_node(child),
            Branch::Right => self.set_right_node(child)
        }
    }

    pub fn has_direct_child(&self, child: NodeRef) -> Option<Branch> {
        return if let Some(left) = &self.left && child.eq(left) {
            Some(Branch::Left)
        } else if let Some(right) = &self.right && child.eq(right) {
            Some(Branch::Right)
        } else {
            None
        };
    }
}

pub fn set_child_node_and_parent(parent: NodeRef, child: NodeRef) {
    let branch = compute_branch(&parent.borrow().prefix, &child.borrow().prefix);

    parent.borrow_mut().set_child_node(Some(child.clone()), branch);
    child.borrow_mut().parent = Some(parent);
}

pub fn insert_parent_above(parent: NodeRef, child: NodeRef) {
    let old_parent = child.borrow().parent.clone();
    set_child_node_and_parent(parent.clone(), child);
    if let Some(old_parent) = old_parent && old_parent != parent {
        set_child_node_and_parent(old_parent, parent);
    }
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Branch {
    Left,
    Right,
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum LookupResult {
    Empty,
    ClosestMatch {
        node: NodeRef,
        branch: Option<Branch>,
    },
    Found(NodeRef),
}

impl PrefixTree {
    pub fn set_top(&mut self, top: Option<NodeRef>) {
        self.top = top;
    }

    pub fn lookup(&self, prefix: &Ipv4Net) -> LookupResult {
        if let None = self.top {
            return LookupResult::Empty;
        };

        let mut root = self.top.clone().unwrap();
        while root.borrow().prefix.contains(prefix) && root.borrow().prefix.prefix_len() <= prefix.prefix_len() {
            // Route Found
            if root.borrow().prefix.prefix_len() == prefix.prefix_len() {
                return LookupResult::Found(root.clone());
            }

            // Walk down left or right based on address bits
            // If we don't have a prefix where we should walk next then we need to insert there
            root = {
                let branch = compute_branch(&root.borrow().prefix, prefix);
                let branch_value = match branch {
                    Branch::Left => &root.borrow().left,
                    Branch::Right => &root.borrow().right
                };

                match branch_value {
                    None => return LookupResult::ClosestMatch { node: root.clone(), branch: Some(branch) },
                    Some(new_root) => new_root.clone()
                }
            };
        }

        LookupResult::ClosestMatch {
            node: root,
            branch: None,
        }
    }

    // TODO check if changing the common_node algorithm to only count bits up to prefix.prefix_len() is better than checking if prefix.contains
    //  we can either put a max on the common prefix length computed that is equal to prefix.prefix_length()
    //  or check if the returned value is greater than prefix.prefix_length(). one may be better
    //  to avoid useless allocations

    pub fn insert(&mut self, prefix: Ipv4Net) {

        // Find where we should be inserting
        let lookup = self.lookup(&prefix);

        let root = match lookup {
            // If no route in tree it's easy: new prefix is the first entry
            LookupResult::Empty => {
                self.top = Some(NodeRef::new(prefix, None, None, None));
                return;
            }
            // Route already exists. Nothing to do
            LookupResult::Found(_) => return,

            // Use the closest match after lookup
            LookupResult::ClosestMatch { node, branch } => {
                match branch {
                    // The prefix we looked up is supposed to be on branch 'branch' of our 'node'
                    Some(branch) => {
                        node.borrow_mut().set_child_node(
                            Some(NodeRef::new(prefix, None, None, Some(node.clone()))),
                            branch,
                        );
                        return;
                    }

                    // The prefix we looked up is supposed to be in place of 'node'
                    None => node,
                }
            }
        };

        // Now, root is either where the prefix is different, or where it has a bigger prefix length
        // We know the prefix is not contained by the node. However, the node may be contained by prefix
        let potential_top = if prefix.contains(&root.borrow().prefix) {
            let new_node = NodeRef::new(prefix, None, None, root.borrow().parent.clone());

            // Since new_node contains node we make it the parent of node
            insert_parent_above(new_node.clone(), root);

            new_node
        } else {
            // If the prefix does not contain the root (the root does not contain the prefix
            // or else the lookup would have returned either an empty branch or a child of root)
            // We need a common parent for both of them
            let common_node = common_node(&root, &prefix);
            let new_node = NodeRef::new(prefix, None, None, Some(common_node.clone()));

            // Put the children on the branch they belong on
            insert_parent_above(common_node.clone(), root);
            set_child_node_and_parent(common_node.clone(), new_node.clone());

            common_node
        };

        // If the new potential top has no parent it means it took the spot of the previous
        // table top
        if potential_top.borrow().parent.is_none() {
            self.set_top(Some(potential_top))
        };
    }

    pub fn delete(&mut self, prefix: Ipv4Net) {
        let node = match self.lookup(&prefix) {
            // If we do not find the exact prefix we have nothing to remove
            LookupResult::Empty
            | LookupResult::ClosestMatch { .. } => return,

            LookupResult::Found(node) => node
        };

        let child = match (&node.borrow().left, &node.borrow().right) {
            // Both children are used so we still need this node
            (Some(_), Some(_)) => return,
            (Some(child), None)
            | (None, Some(child)) => {
                Some(child.clone())
            }
            (None, None) => None
        };

        let parent = node.borrow().parent.clone();

        if let Some(child) = &child {
            child.borrow_mut().parent = parent.clone()
        }

        if let Some(parent) = parent {
            let branch = parent.borrow().has_direct_child(node).unwrap();
            parent.borrow_mut().set_child_node(child, branch);
        } else {
            self.set_top(child)
        }

        // TODO opti remove parent if not needed as well (use structural node type)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::Ipv4Net;

    use crate::capi::features::prefix_tree::PrefixTree;

    #[test]
    pub fn test_radix() {
        let mut tree = PrefixTree::default();

        tree.insert(Ipv4Net::from_str("10.10.10.10/32").unwrap());
        tree.insert(Ipv4Net::from_str("10.10.10.0/24").unwrap());
        tree.insert(Ipv4Net::from_str("0.0.0.0/0").unwrap());
        tree.insert(Ipv4Net::from_str("10.10.0.0/16").unwrap());
        tree.insert(Ipv4Net::from_str("10.10.11.10/32").unwrap());
        tree.insert(Ipv4Net::from_str("10.10.11.0/24").unwrap());
        println!("{:#?}", tree);

        tree.delete(Ipv4Net::from_str("0.0.0.0/0").unwrap());
        tree.delete(Ipv4Net::from_str("10.10.10.0/24").unwrap());
        tree.delete(Ipv4Net::from_str("10.10.10.0/23").unwrap());
        tree.delete(Ipv4Net::from_str("10.10.10.10/32").unwrap());
        println!("{:#?}", tree);
    }
}
