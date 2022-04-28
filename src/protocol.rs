use std::net::SocketAddr;

use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    encryption::{Ciphertext, PublicKey},
    poly::Polynomial,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyMaterial {
    pub pk: PublicKey,
    pub sk_i1: Polynomial,
    pub sk_i2: Polynomial,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PrepMessage {
    Start(SocketAddr),
    PlayerConnected(SocketAddr),
    KeyMaterial(KeyMaterial),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum OnlineMessage {
    SharePoly(Polynomial),
    ShareCiphertext(Ciphertext),
    ShareInteger(Integer),
    ShareCommitment(Vec<u8>),
    ShareCommitOpen(Vec<u8>),
    BeginInput,
}

pub trait Facilicator {
    fn player_count(&self) -> usize;
    fn player_number(&self) -> usize;
    fn send(&self, player: usize, msg: &OnlineMessage);
    fn broadcast(&self, msg: &OnlineMessage);
    fn receive(&self) -> (usize, OnlineMessage);
    fn receive_many(&self, n: usize) -> Vec<(usize, OnlineMessage)>;
    fn stop(self);
}
