use sha2::Digest;
use sha2::Sha256;

pub fn commit(v: Vec<u8>, r: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();

    let mut to_hash = vec![];
    to_hash.extend(v);
    to_hash.extend(r);

    hasher.update(to_hash);

    hasher.finalize().to_vec()
}

pub fn open(c: Vec<u8>, o: Vec<u8>) -> Option<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(o.clone());
    let res = hasher.finalize().to_vec();
    if res != c {
        return None;
    }
    Some(o)
}
