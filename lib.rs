use num_bigint::BigInt;
use num::{Num};
use std::cell::RefCell;
use once_cell::sync::OnceCell;
use std::thread::LocalKey;
use std::os::raw::c_void;
use std::slice;
use ark_ff::Zero;
use lazy_static::lazy_static;
use std::sync::Mutex;

use mina_curves::pasta::fields::Fp;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::fp_kimchi,
    poseidon::{ArithmeticSponge, Sponge},
};

use std::thread;

fn main() {
    // Example data for trees
    let data1 = vec![Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4)];
    let data2 = vec![Fp::from(5), Fp::from(6), Fp::from(7), Fp::from(8)];

    // Thread 1: Working with the first tree
    let handle1 = thread::spawn(move || {
        let root1 = create_merkle_tree(data1.as_ptr(), data1.len());
        println!("Root of the first tree: {:?}", get_merkle_root());
        add_leaf_to_tree(Fp::from(9));
        println!("Updated root of the first tree: {:?}", get_merkle_root());
        clear_merkle_tree();
    });

    // Thread 2: Working with the second tree
    let handle2 = thread::spawn(move || {
        let root2 = create_merkle_tree(data2.as_ptr(), data2.len());
        println!("Root of the second tree: {:?}", get_merkle_root());
        add_leaf_to_tree(Fp::from(10));
        println!("Updated root of the second tree: {:?}", get_merkle_root());
        clear_merkle_tree();
    });

    // Wait for both threads to complete
    handle1.join().unwrap();
    handle2.join().unwrap();
}


//type Field = Fp;

/// The type for Poseidon hasher.
///
/// # Examples
///
/// ```rs
/// let poseidon_hasher = create_poseidon_hasher();
/// ```
///
pub type PoseidonHasher = ArithmeticSponge<Fp, PlonkSpongeConstantsKimchi>;

thread_local! {
    static LOCAL_HASHER: RefCell<PoseidonHasher> = RefCell::new(create_poseidon_hasher());
}

thread_local! {
    static LOCAL_TREE: RefCell<Vec<Vec<MerkleNode>>> = RefCell::new(Vec::new());
}

/*
static GLOBAL_HASHER: Lazy<Mutex<PoseidonHasher>> = Lazy::new(|| {
    Mutex::new(create_poseidon_hasher())
});
*/

/// Creates a new Posedion hasher.
///
/// # Examples
///
/// ```rs
/// let poseidon_hasher = create_poseidon_hasher();
/// ```
///
pub fn create_poseidon_hasher() -> PoseidonHasher {
    PoseidonHasher::new(fp_kimchi::static_params())
}

/// Returns the hash of the input using the given Poseidon hasher.
///
/// # Examples
///
/// ```rs
/// let hash = poseidon_hash(&mut poseidon_hasher, &input);
/// ```
///
#[inline]
pub fn poseidon_hash(input: &[Fp]) -> Fp {

	LOCAL_HASHER.with(|hasher| {
		let mut hasher = hasher.borrow_mut();
		hasher.reset();
		hasher.absorb(input);
		hasher.squeeze()
	})
}

// A new function that takes Fp as an argument and returns the hashed field
#[no_mangle]
pub extern "C" fn hashp(fp: Fp) -> Fp {
        poseidon_hash(&[fp])

}

// Functions that takes Fps as an arguments and returns the hashed field
#[no_mangle]
pub extern "C" fn hashpd(output: *mut Fp, fp: Fp, fpd: Fp) -> Fp {
        let mut h = poseidon_hash(&[fp, fpd]);
        unsafe {
        	if !output.is_null() {
         		*output = h;
        	}
	}
	h
}


#[repr(C)]
struct MerkleNode {
    hash: Fp,
    left: *const MerkleNode,
    right: *const MerkleNode,
}

impl MerkleNode {
    // Create a new node with no children
    fn new(hash: Fp) -> Self {
        MerkleNode {
            hash,
            left: std::ptr::null_mut(),
            right: std::ptr::null_mut(),
        }
    }
}


fn build_merkle_tree(data: Vec<Fp>) -> Fp {
    let mut current_level = data;

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let hash = match chunk {
                [left, right] => poseidon_hash(&[*left, *right]),
                [left] => *left, // In case of an odd number of elements, just carry the last one forward
                _ => unreachable!(),
            };
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0] // The final hash, the root of the Merkle tree
}

// Remember to provide a function to free the allocated MerkleNode to avoid memory leaks


/////////////////////////////////////////

struct MerkleTree {
    root: MerkleNode,
    levels: Vec<Vec<MerkleNode>>, // Keep track of all node level vectors for cleanup
}

fn build_full_merkle_tree(data: Vec<Fp>) -> MerkleNode {
  LOCAL_TREE.with(|levels| {
    // Use the borrowed value of `tree` here

    let leaf_count = data.len();
    //let mut levels: Vec<Vec<MerkleNode>> = Vec::new();
    let mut levels = levels.borrow_mut();
    levels.clear(); // Clear existing tree levels if any


    let mut nodes = Vec::with_capacity(leaf_count);
    for fp in data {
        nodes.push(MerkleNode {
            hash: fp,
            left: std::ptr::null_mut(),
            right: std::ptr::null_mut(),
        });
    }
    levels.push(nodes);

    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut new_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            let node = match chunk {
                [left, right] => {
                    MerkleNode {
                        hash: poseidon_hash(&[left.hash, right.hash]),
                        left: left as *const _ as *mut _, 
                        right: right as *const _ as *mut _, 
                    }
                },
                [left] => {
                    MerkleNode {
                        hash: left.hash,
                        left: left as *const _ as *mut _,
                        right: std::ptr::null_mut(),
                    }
                },
                _ => unreachable!(),
            };
            new_level.push(node);
        }
        levels.push(new_level);
    }
    if let Some(mut last_level) = levels.pop() {
        return last_level.remove(0);
    }

    levels.remove(0).remove(0)
  })   
}


#[no_mangle]
pub extern "C" fn create_merkle_tree(data: *const Fp, count: usize) -> *mut MerkleNode {
    if data.is_null() || count == 0 {
        return std::ptr::null_mut();
    }

    let input_slice = unsafe { slice::from_raw_parts(data, count) };
    let root_node = build_full_merkle_tree(input_slice.to_vec());
    Box::into_raw(Box::new(root_node))
}

pub fn get_merkle_path_impl(leaf_index: usize) -> Vec<Fp> {
    let mut path = Vec::new();

    LOCAL_TREE.with(|tree| {
        let tree = tree.borrow();

        if tree.is_empty() {
            return;
        }

        let mut current_index = leaf_index;
        for level in 0..tree.len() - 1 {
            let nodes = &tree[level];
            if nodes.len() <= current_index {
                break; // Safety check
            }

            let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
            // Check if sibling index is out of bounds (can happen if the last node is duplicated)
            let sibling_index = sibling_index.min(nodes.len() - 1);
            
            if let Some(this_node) = nodes.get(current_index){ 
                if current_index < sibling_index {path.push(unsafe { (*this_node).hash });} // Push the hash of this node
            }

            if let Some(sibling_node) = nodes.get(sibling_index) {
                path.push(unsafe { (*sibling_node).hash }); // Push the hash of the sibling node
            }

            if let Some(this_node) = nodes.get(current_index){ 
                if current_index > sibling_index {path.push(unsafe { (*this_node).hash });} // Push the hash of this node
            }

            current_index /= 2; // Move to the next level
        }
    });

    path
}


#[no_mangle]
pub extern "C" fn get_merkle_path(leaf_index: usize, out_path: *mut Fp, out_path_len: *mut usize) -> usize {
    let path = get_merkle_path_impl(leaf_index); // Assume this function returns Vec<Fp>
    unsafe {
        if !out_path.is_null() && !out_path_len.is_null() {
            let out_path_slice = std::slice::from_raw_parts_mut(out_path, *out_path_len);
            for (i, node) in path.iter().enumerate() {
                if i >= *out_path_len { break; }
                out_path_slice[i] = *node;
            }
            *out_path_len = path.len();
        }
    }
    0 // Return success code
}

////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn logfp(fp: Fp) -> Fp {

        let fp_string = fp.to_string(); // Convert it to a string
        //println!("Fp as string: {}", fp_string);

	let large_string = fp_string;  
	// Start and end indices of the slice
	let start = 8; // Indexing starts from 0, so position 9 is index 8
	let end = 72; // Extract up to, but not including, index 72

	// Slice the string
        let mut extracted_hex = "1a3f4b2c3d4a5e6f7b8c9d0aebfc1a3f4b2c3d4a5e6f7b8c9d0aebfc"; //random hex string
	if large_string.len() >= end {
		extracted_hex = &large_string[start..end];
		//println!("Extracted Hex: {}", extracted_hex);
	} else {
		println!("The string is too short to extract the specified range.");
	}

	match BigInt::from_str_radix(extracted_hex, 16) {
		Ok(decimal) => println!("{}", decimal),
		Err(e) => println!("Failed to parse '{}': {}", extracted_hex, e),
	}

	fp  
    }

////////////////////////////////////////////////////

fn add_one_leaf(new_leaf: Fp) {
    LOCAL_TREE.with(|levels| {
        let mut levels = levels.borrow_mut();
        if levels.is_empty() {
            // No tree exists, create a new one with the new leaf
            levels.push(vec![MerkleNode::new(new_leaf)]);
        } else {
            // Add the new leaf to the bottom level
            let mut current_level = levels.pop().unwrap();
            current_level.push(MerkleNode::new(new_leaf));
            levels.push(current_level);

            // Update the tree by recalculating the hashes up to the root
            let mut level_index = levels.len() - 1;
            while level_index > 0 {
                let mut parent_level = Vec::new();
                let current_level = &levels[level_index];
                for chunk in current_level.chunks(2) {
                    let hash = match chunk {
                        [left, right] => poseidon_hash(&[left.hash, right.hash]),
                        [left] => left.hash,
                        _ => unreachable!(),
                    };
                    parent_level.push(MerkleNode {
                        hash,
                        left: &chunk[0],
                        right: if chunk.len() > 1 { &chunk[1] } else { &chunk[0] },
                    });
                }
                levels[level_index - 1] = parent_level;
                level_index -= 1;
            }
        }
    });
}

fn get_root() -> Fp {
    LOCAL_TREE.with(|levels| {
        let levels = levels.borrow();
        if levels.is_empty() {
            Fp::zero()
        } else {
            levels.last().unwrap()[0].hash
        }
    })
}

#[no_mangle]
pub extern "C" fn add_leaf_to_tree(new_leaf: Fp) {
    add_one_leaf(new_leaf);
}

#[no_mangle]
pub extern "C" fn get_merkle_root() -> Fp {
    get_root()
}

fn clear_levels() {
    LOCAL_TREE.with(|levels| {
        let mut levels = levels.borrow_mut();
        levels.clear();
    });
}

#[no_mangle]
pub extern "C" fn clear_merkle_tree() {
    clear_levels();
}

