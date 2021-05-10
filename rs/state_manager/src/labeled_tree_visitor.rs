use ic_canonical_state::{Control, Visitor};
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree};

/// Visitor that materializes the tree being traversed as a `LabeledTree`.
#[derive(Default)]
pub struct LabeledTreeVisitor {
    // The stack of values under construction. The bottom value will become the
    // result of the traversal.
    value_stack: Vec<LabeledTree<Vec<u8>>>,
    // The stack of labels for opened and not yet closed edges.
    label_stack: Vec<Label>,
}

impl LabeledTreeVisitor {
    // Pops the value off the stack and appends it into the parent fork.  Called
    // when leaving a node (either leaf or fork).
    fn link_top_value_to_parent(&mut self) {
        assert_eq!(self.label_stack.len() + 1, self.value_stack.len());

        let label = match self.label_stack.pop() {
            Some(l) => l,
            None => return,
        };

        let entry = self.value_stack.pop().expect("unbalanced tree traversal");

        if let LabeledTree::SubTree(ref mut map) =
            self.value_stack.last_mut().expect("label without a root")
        {
            map.try_append(label, entry).unwrap();
        }
    }
}

impl Visitor for LabeledTreeVisitor {
    type Output = LabeledTree<Vec<u8>>;

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        self.value_stack.push(LabeledTree::SubTree(FlatMap::new()));
        Ok(())
    }

    fn enter_edge(&mut self, label: &[u8]) -> Result<Control, Self::Output> {
        self.label_stack.push(Label::from(label));
        Ok(Control::Continue)
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        self.link_top_value_to_parent();
        Ok(())
    }

    fn visit_blob(&mut self, value: &[u8]) -> Result<(), Self::Output> {
        self.value_stack.push(LabeledTree::Leaf(value.to_vec()));
        self.link_top_value_to_parent();
        Ok(())
    }

    fn visit_num(&mut self, value: u64) -> Result<(), Self::Output> {
        self.value_stack
            .push(LabeledTree::Leaf(value.to_be_bytes().to_vec()));
        self.link_top_value_to_parent();
        Ok(())
    }

    fn finish(mut self) -> Self::Output {
        assert!(
            self.label_stack.is_empty(),
            "unbalanced tree traversal, unclosed labels: {:?}",
            self.label_stack
        );

        assert!(self.value_stack.len() <= 1, "incomplete tree traversal");

        self.value_stack
            .pop()
            .expect("cannot construct an empty tree")
    }
}

#[cfg(test)]
mod tests;
