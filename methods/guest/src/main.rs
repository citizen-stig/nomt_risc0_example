use risc0_zkvm::guest::env;
use nomt_core::{hasher::Sha2Hasher, proof, trie::LeafData};

fn verify_nomt_witness() {
    let prev_root: nomt_core::trie::Node = env::read();

    // TODO: Read witness and the rest from https://github.com/thrumdev/nomt/blob/5111c2712a526882ae3aa8bf24be923e394d9fe9/examples/witness_verification/src/main.rs
}


fn main() {
    // TODO: Implement your guest code here

    // read the input
    let input: u32 = env::read();

    // TODO: do something with the input

    // write public output to the journal
    env::commit(&input);
}
