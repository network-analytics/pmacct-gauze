use std::cmp::PartialEq;
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Classic implementation of a Prefix Tree: each node is simply allocated and holds a reference to its children and parent
pub mod classic;
/// Variant of the classic implementation in which the node does not hold a reference to the parent but only the prefix len of its parent
/// this reduces the footprint of the tree very slightly (one less Rc<RefCell<T>> so we replace a pointer, flag and counter by an u8
/// Because we do not have back-pointers anymore we can replace Rc<RefCell<.>> by Box<.> and gain even more space
// pub mod no_parent;
/// Tree implementation using a List(Vec or any other list) and nodes holding ID/Indices instead of references to other nodes
/// With this tree we should look at performance with different Lists: Vec, TypedArena.
/// We can also experiment with ID allocators that give related nodes similar IDs
pub mod indexed_tree;

/// https://www.quora.com/What-are-the-best-steps-to-implement-a-tree-data-structure
pub mod no_index_tree;

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

pub fn compute_branch<Pfx: Prefix>(parent: &Pfx, child: &Pfx) -> Branch {
    match child.is_left_of(parent) {
        true => Branch::Left,
        false => Branch::Right
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
pub enum LookupResult<ClosestMatch, Result> {
    Empty,
    ClosestMatch(ClosestMatch),
    Found(Result),
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum NodeType {
    Entry,
    Structural,
}
