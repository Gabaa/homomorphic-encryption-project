use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{encryption::PublicKey, poly::Polynomial};

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
}

pub trait Facilicator {
    fn player_count(&self) -> usize;
    fn player_number(&self) -> usize;
    fn send(&mut self, player: usize, msg: &OnlineMessage);
    fn broadcast(&mut self, msg: &OnlineMessage);
    fn receive(&mut self) -> (usize, OnlineMessage);
    fn receive_many(&mut self, n: usize) -> Vec<(usize, OnlineMessage)>;
}
