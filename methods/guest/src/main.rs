use nomt_core::trie::ValueHash;
use nomt_core::witness::Witness;
use nomt_core::{hasher::Sha2Hasher, proof, trie::LeafData};
use risc0_zkvm::guest::env;
use sha2::Digest;

fn verify_nomt_witness() {
    let prev_root: nomt_core::trie::Node = env::read();
    let witness: Witness = env::read();

    // Read as in example: https://github.com/thrumdev/nomt/blob/5111c2712a526882ae3aa8bf24be923e394d9fe9/examples/witness_verification/src/main.rs
    let mut updates = Vec::new();

    // A witness is composed of multiple WitnessedPath objects,
    // which stores all the necessary information to verify the operations
    // performed on the same path
    for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
        // Constructing the verified operations
        let verified = witnessed_path
            .inner
            .verify::<Sha2Hasher>(&witnessed_path.path.path(), prev_root)
            .unwrap();

        // Among all read operations performed the ones that interact
        // with the current verified path are selected
        //
        // Each witnessed operation contains an index to the path it needs to be verified against
        //
        // This information could already be known if we committed the batch initially,
        // and thus, the witnessed field could be discarded entirely.
        for read in witness
            .operations
            .reads
            .iter()
            .skip_while(|r| r.path_index != i)
            .take_while(|r| r.path_index == i)
        {
            match read.value {
                // Check for non-existence if the return value was None
                None => assert!(verified.confirm_nonexistence(&read.key).unwrap()),
                // Verify the correctness of the returned value when it is Some(_)
                Some(ref v) => {
                    let leaf = LeafData {
                        key_path: read.key,
                        value_hash: sha2::Sha256::digest(v).into(),
                    };
                    assert!(verified.confirm_value(&leaf).unwrap());
                }
            }
        }

        // The correctness of write operations cannot be easily verified like reads.
        // Write operations need to be collected.
        // All writes that have worked on shared prefixes,
        // such as the witnessed_path, need to be bundled together.
        // Later, it needs to be verified that all these writes bring
        // the new trie to the expected state
        let mut write_ops = Vec::new();
        for write in witness
            .operations
            .writes
            .iter()
            .skip_while(|r| r.path_index != i)
            .take_while(|r| r.path_index == i)
        {
            write_ops.push((
                write.key,
                write
                    .value
                    .as_ref()
                    .map(|v| ValueHash::from(sha2::Sha256::digest(v))),
            ));
        }

        if !write_ops.is_empty() {
            updates.push(proof::PathUpdate {
                inner: verified,
                ops: write_ops,
            });
        }
    }

    let new_root = proof::verify_update::<Sha2Hasher>(prev_root, &updates).unwrap();
    env::commit(&new_root);
}

fn main() {
    // read the sample input
    let _input: u32 = env::read();
    // env::commit(&input);

    verify_nomt_witness();
}
