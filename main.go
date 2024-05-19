package main

// #cgo LDFLAGS: -L. -lsimple_example -ldl
// #include <stdint.h>
//
// typedef struct {
//     uint64_t limbs[4];
// } Fp;
//
// Fp hashp(Fp fp);
//
// Fp hashpd(Fp* out, Fp fp, Fp fpd);
//
// Fp logfp(Fp fp);
//
// typedef struct MerkleNode {
//     Fp hash;
//     struct MerkleNode* left;
//     struct MerkleNode* right;
// } MerkleNode;
//
// MerkleNode* create_merkle_tree(const Fp* data, size_t count);
// void add_leaf_to_tree(Fp new_leaf);
// Fp get_merkle_root();
// void clear_merkle_tree();
// unsigned int get_merkle_path(size_t leaf_index, Fp* out_path, size_t* out_path_len);
import "C"
import (
    "encoding/binary"
    "errors"
    "fmt"
    "unsafe"

    "go.vocdoni.io/dvote/db"
    "go.vocdoni.io/dvote/db/badgerdb"
)

type MerkleTree struct {
    db         db.Database
    keyIndex   map[string]int
    values     [][]byte
    currentIdx int
}

func fpToBytes(fp *C.Fp) []byte {
    size := unsafe.Sizeof(*fp)
    byteSlice := (*[1 << 30]byte)(unsafe.Pointer(fp))[:size:size]
    return byteSlice
}

func bytesToFp(value []byte) C.Fp {
    fp := (*C.Fp)(unsafe.Pointer(&value[0]))
    return *fp
}

func NewMerkleTree(database db.Database) *MerkleTree {
    return &MerkleTree{
        db:       database,
        keyIndex: make(map[string]int),
        values:   make([][]byte, 0),
    }
}

func (tree *MerkleTree) Add(key, value []byte) error {
    keyStr := string(key)
    if _, exists := tree.keyIndex[keyStr]; exists {
        return errors.New("key already exists")
    }

    tree.keyIndex[keyStr] = tree.currentIdx
    tree.values = append(tree.values, value)
    tree.currentIdx++

    fmt.Printf("Adding leaf: ")
    logFp(bytesToFp(value))

    C.add_leaf_to_tree(bytesToFp(value))

    txn := tree.db.WriteTx()
    defer txn.Discard()
    indexBytes := make([]byte, 8)
    binary.LittleEndian.PutUint64(indexBytes, uint64(tree.keyIndex[keyStr]))
    if err := txn.Set(key, indexBytes); err != nil {
        return err
    }
    if err := txn.Commit(); err != nil {
        return err
    }

    return nil
}

func (tree *MerkleTree) GenProof(key []byte) ([]C.Fp, error) {
    keyStr := string(key)
    idx, exists := tree.keyIndex[keyStr]
    if !exists {
        return nil, errors.New("key does not exist")
    }

    return getMerklePath(uint(idx))
}

func (tree *MerkleTree) Root() []byte {
    rootFp := C.get_merkle_root()
    return fpToBytes(&rootFp)
}

func (tree *MerkleTree) AddBatch(keys, values [][]byte) error {
    if len(keys) != len(values) {
        return errors.New("keys and values length mismatch")
    }

    for i := 0; i < len(keys); i++ {
        keyStr := string(keys[i])
        if _, exists := tree.keyIndex[keyStr]; exists {
            return errors.New("key already exists")
        }

        tree.keyIndex[keyStr] = tree.currentIdx
        tree.currentIdx++
    }

    flatValues := make([]C.Fp, len(values))
    for i, value := range values {
        flatValues[i] = bytesToFp(value)

        fmt.Printf("Batch adding leaf %d : ", i)
        logFp(bytesToFp(value))
    }

    ptr := (*C.Fp)(unsafe.Pointer(&flatValues[0]))
    C.create_merkle_tree(ptr, C.size_t(len(values)))

    return nil
}

func getMerklePath(leafIndex uint) ([]C.Fp, error) {
    const maxPathLength = 256
    outPath := make([]C.Fp, maxPathLength)
    outPathLen := C.size_t(maxPathLength)

    ret := C.get_merkle_path(C.size_t(leafIndex), (*C.Fp)(unsafe.Pointer(&outPath[0])), &outPathLen)
    if ret != 0 {
        return nil, fmt.Errorf("failed to get merkle path")
    }

    goPath := make([]C.Fp, outPathLen)
    copy(goPath, outPath[:outPathLen])

    return goPath, nil
}

func logFp(fp C.Fp) {
    C.logfp(fp)
}

func logBytes(b []byte) {
    fp := *(*C.Fp)(unsafe.Pointer(&b[0]))
    logFp(fp)
}

func printMerklePath(path []C.Fp) {
    for _, element := range path {
        logFp(element)
    }
}

func testSingleAddition(tree *MerkleTree, key, value []byte) {
    err := tree.Add(key, value)
    if err != nil {
        fmt.Printf("An error occurred: %v\n", err)
        return
    }
    fmt.Printf("Added key-value: %s-%s\n", key, value)
    logBytes(value)

    proof, err := tree.GenProof(key)
    if err != nil {
        fmt.Printf("An error occurred: %v\n", err)
        return
    }
    fmt.Printf("Merkle proof for key %s:\n", key)
    printMerklePath(proof)

    root := tree.Root()
    fmt.Printf("Merkle root:\n")
    logBytes(root)
}

func testBatchAddition(tree *MerkleTree, keys, values [][]byte) {
    err := tree.AddBatch(keys, values)
    if err != nil {
        fmt.Printf("An error occurred: %v\n", err)
        return
    }
    fmt.Printf("Added batch keys and values\n")
    for _, value := range values {
        logBytes(value)
    }

    root := tree.Root()
    fmt.Printf("Merkle root after batch add:\n")
    logBytes(root)
}

func testLargeBatchAddition(tree *MerkleTree, largeKeys, largeValues [][]byte) {
    err := tree.AddBatch(largeKeys, largeValues)
    if err != nil {
        fmt.Printf("An error occurred: %v\n", err)
        return
    }
    fmt.Printf("Added large batch of keys and values\n")

    root := tree.Root()
    fmt.Printf("Merkle root after large batch add:\n")
    logBytes(root)

    for i := 0; i < 10; i++ {
        key := largeKeys[i]
        value := largeValues[i]
        proof, err := tree.GenProof(key)
        if err != nil {
            fmt.Printf("An error occurred: %v\n", err)
            continue
        }
        fmt.Printf("Merkle proof for key ")
        logBytes(key)
        fmt.Printf(":\n")
        printMerklePath(proof)
        fmt.Printf("Root:\n")
        logBytes(value)
    }
}

func main() {
    var opts db.Options
    opts.Path = "dbname"
    dbpoint, err := badgerdb.New(opts)
    if err != nil {
        fmt.Printf("An error occurred: %v\n", err)
        return
    }

    tree := NewMerkleTree(dbpoint)

    // Single addition test
    key1 := []byte("key1")
    value1 := []byte("value1")
    testSingleAddition(tree, key1, value1)

    // Batch addition test
    keys := [][]byte{[]byte("key2"), []byte("key3")}
    values := [][]byte{[]byte("value2"), []byte("value3")}
    testBatchAddition(tree, keys, values)

    // More individual additions
    key4 := []byte("key4")
    value4 := []byte("value4")
    testSingleAddition(tree, key4, value4)

    key5 := []byte("key5")
    value5 := []byte("value5")
    testSingleAddition(tree, key5, value5)

    // Adding and verifying a large batch
    largeKeys := make([][]byte, 100)
    largeValues := make([][]byte, 100)
    for i := 0; i < 100; i++ {
        largeKeys[i] = []byte(fmt.Sprintf("largeKey%d", i))
        largeValues[i] = []byte(fmt.Sprintf("largeValue%d", i))
    }
    testLargeBatchAddition(tree, largeKeys, largeValues)
}
