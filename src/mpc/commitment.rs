use crate::mpc::PlayerState;
use crate::protocol::Facilitator;
use crate::protocol::OnlineMessage;
use sha2::Digest;
use sha2::Sha256;

pub fn commit<F: Facilitator>(v: Vec<u8>, r: Vec<u8>, state: &PlayerState<F>) {
    let mut o = vec![];
    o.extend(v);
    o.extend(r);

    let mut hasher = Sha256::new();
    hasher.update(o);
    let c = hasher.finalize().to_vec();

    state
        .facilitator
        .broadcast(&OnlineMessage::ShareCommitment(c));
}

pub fn open(c: Vec<u8>, o: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(o.clone());
    let res = hasher.finalize().to_vec();
    if res != c {
        return Err("Hash of o does not equal c");
    }
    Ok(o)
}
