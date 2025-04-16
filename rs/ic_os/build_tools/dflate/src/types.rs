use tar::GnuSparseHeader;

use crate::tar_util::num_field_wrapper_into;

#[derive(Debug)]
pub struct Block {
    pub offset: u64,
    pub size: u64,
}

impl Block {
    pub fn new(start: u64, end: u64) -> Self {
        Block {
            offset: start,
            size: end - start,
        }
    }

    pub fn to_gnu_sparse(&self) -> GnuSparseHeader {
        let mut offset = [0; 12];
        num_field_wrapper_into(&mut offset, self.offset);

        let mut numbytes = [0; 12];
        num_field_wrapper_into(&mut numbytes, self.size);

        GnuSparseHeader { offset, numbytes }
    }
}

#[derive(Debug)]
pub struct State {
    pub name: String,
    pub blocks: Vec<Block>,
    pub stripped_size: u64,
    status: Status,
}

#[derive(Debug)]
enum Status {
    InBlock(u64),
    NotInBlock,
}

impl State {
    pub fn new(name: String) -> Self {
        Self {
            name,
            status: Status::NotInBlock,
            blocks: Vec::new(),
            stripped_size: 0,
        }
    }

    pub fn is_in_block(&self) -> bool {
        match self.status {
            Status::InBlock(_) => true,
            Status::NotInBlock => false,
        }
    }

    pub fn start_block(&mut self, offset: u64) {
        match self.status {
            Status::NotInBlock => self.status = Status::InBlock(offset),
            _ => panic!("Invalid state transition"),
        }
    }

    pub fn end_block(&mut self, offset: u64) {
        match self.status {
            Status::InBlock(start) => {
                let block = Block::new(start, offset);
                self.stripped_size += block.size;
                self.blocks.push(block);
                self.status = Status::NotInBlock;
            }
            _ => panic!("Invalid state transition"),
        }
    }

    pub fn terminate_list(&mut self, offset: u64) {
        self.blocks.push(Block::new(offset, offset));
    }
}
