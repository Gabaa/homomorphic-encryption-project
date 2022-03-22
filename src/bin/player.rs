use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
};

use homomorphic_encryption_project::protocol::{Facilicator, OnlineMessage, PrepMessage};

struct FacilitatorImpl {
    players: Vec<SocketAddr>,
    player_number: usize,
    listener: TcpListener,
}

impl FacilitatorImpl {
    fn new(players: Vec<SocketAddr>, listener: TcpListener) -> Self {
        let player_number = players
            .iter()
            .position(|&addr| addr == listener.local_addr().unwrap())
            .unwrap();

        Self {
            players,
            player_number,
            listener,
        }
    }
}

impl Facilicator for FacilitatorImpl {
    fn player_count(&self) -> usize {
        self.players.len()
    }

    fn player_number(&self) -> usize {
        self.player_number
    }

    fn send(&mut self, player: usize, msg: &OnlineMessage) {
        let stream = TcpStream::connect(self.players[player]).unwrap();
        serde_json::to_writer(stream, msg).unwrap();
    }

    fn broadcast(&mut self, msg: &OnlineMessage) {
        for i in 0..self.player_count() {
            self.send(i, msg);
        }
    }

    fn receive(&mut self) -> (usize, OnlineMessage) {
        let (stream, addr) = self.listener.accept().unwrap();
        let msg: OnlineMessage = serde_json::from_reader(stream).unwrap();

        let player_number = self
            .players
            .iter()
            .position(|&player_addr| player_addr == addr)
            .unwrap();

        (player_number, msg)
    }

    fn receive_many(&mut self, n: usize) -> Vec<(usize, OnlineMessage)> {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let msg = self.receive();
            msgs.push(msg);
        }
        msgs
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("localhost:0")?;

    println!("Connecting to dealer...");
    let stream = TcpStream::connect("localhost:9000")?;

    // Send start
    println!("Sending Start...");
    let start_msg = PrepMessage::Start(listener.local_addr()?);
    serde_json::to_writer(stream, &start_msg)?;

    // Wait to receive all players and key material
    println!("Waiting for players to connect...");
    let mut players = vec![];
    let key_material;
    loop {
        // TODO: Should we check whether this is actually the dealer or not?
        let (stream, _) = listener.accept()?;
        match serde_json::from_reader::<_, PrepMessage>(stream).unwrap() {
            PrepMessage::PlayerConnected(player_addr) => {
                println!("New player connected: {}", player_addr);
                players.push(player_addr);
            }
            PrepMessage::KeyMaterial(km) => {
                key_material = km;
                break;
            }
            _ => todo!("got weird message"),
        };
    }
    println!("Received key material: {:?}", key_material);

    let _facilitator = FacilitatorImpl::new(players, listener);
    // TODO: Give this value to the library

    Ok(())
}
