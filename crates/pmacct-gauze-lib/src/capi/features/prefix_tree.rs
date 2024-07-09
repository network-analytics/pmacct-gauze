#![feature(let_chains)]

use std::cell::RefCell;
use std::cmp::{Ordering, PartialEq};
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use ipnet::{Ipv4Net, Ipv6Net};

use crate::capi::features::prefix_tree::NodeType::*;

pub trait Prefix: Ord + PartialOrd + PartialEq + Eq + Debug + Clone {
    fn common_route(&self, other: &Self) -> Self;
    fn is_left_of(&self, parent: &Self) -> bool;
    fn contains(&self, child: &Self) -> bool;
    fn max_prefix_len(&self) -> u8;
    fn prefix_len(&self) -> u8;
}

impl Prefix for Ipv4Net {
    fn common_route(&self, other: &Self) -> Self {
        let first_addr = self.network().to_bits();
        let second_addr = other.network().to_bits();

        let common_bits = (first_addr ^ second_addr).leading_zeros();
        let common_mask = u32::MAX << (u32::BITS - common_bits);

        Ipv4Net::new(
            Ipv4Addr::from_bits(first_addr & common_mask),
            common_bits as u8,
        ).unwrap()
    }

    fn is_left_of(&self, parent: &Self) -> bool {
        let prefix_max_len = parent.max_prefix_len();
        let parent_len = parent.prefix_len();
        // shift to get next bit of the child network address
        // the next bit is the bit in the child following the parent network address
        let shift = prefix_max_len - parent_len - 1;

        // if the next bit is one the child goes to the left (we could do the opposite)
        (self.network().to_bits() >> shift) & 1 == 1
    }

    fn contains(&self, child: &Self) -> bool {
        Ipv4Net::contains(self, child)
    }

    fn max_prefix_len(&self) -> u8 {
        self.max_prefix_len()
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len()
    }
}

impl Prefix for Ipv6Net {
    fn common_route(&self, other: &Self) -> Self {
        let first_addr = self.network().to_bits();
        let second_addr = other.network().to_bits();

        let common_bits = (first_addr ^ second_addr).leading_zeros();
        let common_mask = u128::MAX << (u128::BITS - common_bits);

        Ipv6Net::new(
            Ipv6Addr::from_bits(first_addr & common_mask),
            common_bits as u8,
        ).unwrap()
    }

    fn is_left_of(&self, parent: &Self) -> bool {
        let prefix_max_len = parent.max_prefix_len();
        let parent_len = parent.prefix_len();
        // shift to get next bit of the child network address
        // the next bit is the bit in the child following the parent network address
        let shift = prefix_max_len - parent_len - 1;

        // if the next bit is one the child goes to the left (we could do the opposite)
        (self.network().to_bits() >> shift) & 1 == 1
    }

    fn contains(&self, child: &Self) -> bool {
        Ipv6Net::contains(self, child)
    }

    fn max_prefix_len(&self) -> u8 {
        Ipv6Net::max_prefix_len(self)
    }

    fn prefix_len(&self) -> u8 {
        Ipv6Net::prefix_len(self)
    }
}

#[derive(Default, Clone)]
pub struct PrefixTree<Pfx>
where
    Pfx: Prefix,
{
    top: Option<TreeRef<Pfx>>,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct TreeRef<Pfx: Prefix>(Rc<RefCell<Node<Pfx>>>);

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum NodeType {
    Entry,
    Structural,
}

#[derive(Clone)]
pub struct Node<Pfx: Prefix> {
    pub(crate) node_type: NodeType,
    pub(crate) prefix: Pfx,
    left: Option<TreeRef<Pfx>>,
    right: Option<TreeRef<Pfx>>,
    parent: Option<TreeRef<Pfx>>,
}

impl<Pfx: Prefix> Debug for PrefixTree<Pfx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut nodes = BTreeSet::new();
        self.walk(|node| {
            nodes.insert(node);
        });

        let mut debug = f.debug_struct("PrefixTree");
        debug.field("top", &self.top);
        debug.field("nodes", &nodes);
        debug.finish()
    }
}


impl<Pfx> TreeRef<Pfx>
where
    Pfx: Prefix,
{
    pub fn new(
        node_type: NodeType,
        prefix: Pfx,
        left: Option<TreeRef<Pfx>>,
        right: Option<TreeRef<Pfx>>,
        parent: Option<TreeRef<Pfx>>,
    ) -> Self {
        let node = Node {
            node_type,
            prefix,
            left,
            right,
            parent,
        };

        TreeRef(Rc::new(RefCell::new(node)))
    }
}
impl<Pfx: Prefix> Deref for TreeRef<Pfx> {
    type Target = Rc<RefCell<Node<Pfx>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Pfx: Prefix> DerefMut for TreeRef<Pfx> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<Pfx> Eq for Node<Pfx> where Pfx: Prefix {}

impl<Pfx> PartialEq<Self> for Node<Pfx>
where
    Pfx: Prefix,
{
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}

impl<Pfx> PartialOrd<Self> for Node<Pfx>
where
    Pfx: Prefix,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.prefix.partial_cmp(&other.prefix)
    }
}

impl<Pfx> Ord for Node<Pfx>
where
    Pfx: Prefix,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.prefix.cmp(&other.prefix)
    }
}

impl<Pfx: Prefix> Debug for Node<Pfx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Node");
        debug.field("type", &self.node_type);
        debug.field("prefix", &self.prefix);
        debug.field("left", &self.left.as_ref().map(|noderef| noderef.borrow().prefix.clone()));
        debug.field("right", &self.right.as_ref().map(|noderef| noderef.borrow().prefix.clone()));
        debug.field("parent", &self.parent.as_ref().map(|noderef| noderef.borrow().prefix.clone()));

        debug.finish()
    }
}

pub fn compute_branch<Pfx: Prefix>(parent: &Pfx, child: &Pfx) -> Branch {
    match child.is_left_of(parent) {
        true => Branch::Left,
        false => Branch::Right
    }
}

pub fn common_node<Pfx: Prefix>(node: &TreeRef<Pfx>, route: &Pfx) -> TreeRef<Pfx> {
    let common_route = (&node.borrow().prefix).common_route(route);
    TreeRef::new(Structural, common_route, None, None, node.borrow().parent.clone())
}

impl<Pfx: Prefix> Node<Pfx> {
    pub fn set_right_node(&mut self, child: Option<TreeRef<Pfx>>) {
        self.right = child
    }

    pub fn set_left_node(&mut self, child: Option<TreeRef<Pfx>>) {
        self.left = child
    }

    pub fn set_branch(&mut self, branch: Branch, child: Option<TreeRef<Pfx>>) {
        match branch {
            Branch::Left => self.set_left_node(child),
            Branch::Right => self.set_right_node(child)
        }
    }

    pub fn has_direct_child(&self, child: TreeRef<Pfx>) -> Option<Branch> {
        return if let Some(left) = &self.left && child.eq(left) {
            Some(Branch::Left)
        } else if let Some(right) = &self.right && child.eq(right) {
            Some(Branch::Right)
        } else {
            None
        };
    }

    pub fn get_branch(&self, branch: Branch) -> Option<TreeRef<Pfx>> {
        match branch {
            Branch::Left => self.left.clone(),
            Branch::Right => self.right.clone()
        }
    }

    pub fn child_count(&self) -> usize {
        let mut result = 0;
        if let Some(_) = &self.left { result += 1 }
        if let Some(_) = &self.right { result += 1 }
        result
    }
}

pub fn set_child_node_and_parent<Pfx: Prefix>(parent: TreeRef<Pfx>, child: TreeRef<Pfx>) {
    let branch = compute_branch(&parent.borrow().prefix, &child.borrow().prefix);

    parent.borrow_mut().set_branch(branch, Some(child.clone()));
    child.borrow_mut().parent = Some(parent);
}

pub fn insert_parent_above<Pfx: Prefix>(parent: TreeRef<Pfx>, child: TreeRef<Pfx>) {
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

impl Branch {
    pub fn other(self) -> Self {
        match self {
            Branch::Left => Branch::Right,
            Branch::Right => Branch::Left
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum LookupResult<Pfx: Prefix> {
    Empty,
    ClosestMatch {
        node: TreeRef<Pfx>,
        branch: Option<Branch>,
    },
    Found(TreeRef<Pfx>),
}

impl<Pfx: Prefix> PrefixTree<Pfx> {
    pub fn set_top(&mut self, top: Option<TreeRef<Pfx>>) {
        self.top = top;
    }

    pub fn walk(&self, mut callback: impl FnMut(TreeRef<Pfx>)) {
        if self.top.is_none() {
            return;
        }

        let mut vec = Vec::new();
        vec.push(self.top.clone().unwrap());

        while let Some(node) = vec.pop() {
            if let Some(right) = &node.borrow().right {
                vec.push(right.clone())
            }
            if let Some(left) = &node.borrow().left {
                vec.push(left.clone());
            }
            callback(node);
        }
    }

    pub fn lookup(&self, prefix: &Pfx) -> LookupResult<Pfx> {
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

    pub fn insert(&mut self, prefix: Pfx) {

        // Find where we should be inserting
        let lookup = self.lookup(&prefix);

        let root = match lookup {
            // If no route in tree it's easy: new prefix is the first entry
            LookupResult::Empty => {
                self.top = Some(TreeRef::new(Entry, prefix, None, None, None));
                return;
            }
            // Route already exists. Nothing to do
            LookupResult::Found(node) => {
                if node.borrow().node_type == Structural {
                    node.borrow_mut().node_type = Entry;
                }
                return;
            }

            // Use the closest match after lookup
            LookupResult::ClosestMatch { node, branch } => {
                match branch {
                    // The prefix we looked up is supposed to be on branch 'branch' of our 'node'
                    Some(branch) => {
                        node.borrow_mut().set_branch(
                            branch,
                            Some(TreeRef::new(Entry, prefix, None, None, Some(node.clone()))),
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
            let new_node = TreeRef::new(Entry, prefix, None, None, root.borrow().parent.clone());

            // Since new_node contains node we make it the parent of node
            insert_parent_above(new_node.clone(), root);

            new_node
        } else {
            // If the prefix does not contain the root (the root does not contain the prefix
            // or else the lookup would have returned either an empty branch or a child of root)
            // We need a common parent for both of them
            let common_node = common_node(&root, &prefix);
            let new_node = TreeRef::new(Entry, prefix, None, None, Some(common_node.clone()));

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

    // FIXME ensure that we destroy tree by removing the parent of each Node we let go of
    pub fn delete(&mut self, prefix: &Pfx) {
        let node = match self.lookup(prefix) {
            // If we do not find the exact prefix we have nothing to remove
            LookupResult::Empty
            | LookupResult::ClosestMatch { .. } => return,
            LookupResult::Found(node) if node.borrow().node_type == Structural => return,

            LookupResult::Found(node) => node,
        };

        // Both children are used so we still need this node, mark it as Structural
        if node.borrow().left.is_some() && node.borrow().right.is_some() {
            node.borrow_mut().node_type = Structural;
            // TODO optimize by merging if parent is also structural
            return;
        }

        // Find child of removed node
        let child = if let Some(child) = &node.borrow().left {
            Some(child.clone())
        } else if let Some(child) = &node.borrow().right {
            Some(child.clone())
        } else {
            None
        };

        // Find parent of removed node
        let parent = node.borrow().parent.clone();

        // The parent of child becomes the parent of node. It can be None
        if let Some(child) = &child {
            child.borrow_mut().parent = parent.clone()
        }

        // If removed node had no parent it was the table top and the child becomes it
        if let None = parent {
            self.set_top(child);
            return;
        }

        // If removed node had a parent then the only child of node becomes the child of parent
        let parent = parent.unwrap();
        let branch = parent.borrow().has_direct_child(node).unwrap();
        parent.borrow_mut().set_branch(branch, child.clone());

        //              grandparent
        //             /            \
        //       parent               some_other_node
        //      /      \
        //  node       some_node
        //      \
        //      child
        // we removed node so now we have
        //              grandparent
        //             /            \
        //       parent               some_other_node
        //      /      \
        //  child       some_node
        //  (None)
        // if child was None and parent structural (must have 2 children) then parent has no use anymore
        // and we replace parent by some_node
        // TODO move the final step of removing superfluous structural nodes if child is None
        if parent.borrow().node_type == Structural && child.is_none() {
            // If some_node is None then I fucked up somewhere
            let some_node = parent.borrow().get_branch(branch.other()).unwrap();

            if let Some(grandparent) = &parent.borrow().parent {
                let grandparent = grandparent.clone();
                set_child_node_and_parent(grandparent, some_node);
            } else {
                some_node.borrow_mut().parent = None;
                self.set_top(Some(some_node))
            }
        }
    }
}

impl<Pfx: Prefix> Drop for PrefixTree<Pfx> {
    fn drop(&mut self) {
        self.walk(|node| {
            node.borrow_mut().parent = None
        });
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

        tree.delete(&Ipv4Net::from_str("0.0.0.0/0").unwrap());
        tree.delete(&Ipv4Net::from_str("10.10.10.0/24").unwrap());
        tree.delete(&Ipv4Net::from_str("10.10.10.0/23").unwrap());
        tree.delete(&Ipv4Net::from_str("10.10.10.10/32").unwrap());
        println!("{:#?}", tree);
    }
}