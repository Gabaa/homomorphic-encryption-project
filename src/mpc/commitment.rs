use crate::protocol::Facilicator;
use crate::mpc::PlayerState;
use crate::protocol::OnlineMessage;
use sha2::Digest;
use sha2::Sha256;

pub fn commit<F: Facilicator>(v: Vec<u8>, r: Vec<u8>, state: &PlayerState<F>) {
    let mut o = vec![];
    o.extend(v);
    o.extend(r);

    let mut hasher = Sha256::new();
    hasher.update(o);
    let c = hasher.finalize().to_vec();

    state.facilitator.broadcast(&OnlineMessage::ShareCommitment(c));
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
