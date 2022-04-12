use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread::{self, JoinHandle},
};

use homomorphic_encryption_project::{
    encryption::{secure_params, Parameters},
    mpc::{online, prep, PlayerState},
    protocol::{Facilicator, OnlineMessage, PrepMessage},
};
use num::{bigint::RandBigInt, BigInt, Zero};
use rand::rngs::OsRng;

struct FacilitatorImpl {
    players: Vec<SocketAddr>,
    player_number: usize,
    rx: Receiver<(SocketAddr, OnlineMessage)>,
    join_handle: JoinHandle<()>,
    stop_signal: Arc<AtomicBool>,
}

impl FacilitatorImpl {
    fn new(players: Vec<SocketAddr>, listener: TcpListener) -> Self {
        let player_number = players
            .iter()
            .position(|&addr| addr == listener.local_addr().unwrap())
            .unwrap();

        let (tx, rx) = mpsc::channel();
        let stop_signal = Arc::new(AtomicBool::new(false));

        let stop_signal_clone = stop_signal.clone();
        let join_handle = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();

            while !stop_signal_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (msg, sender): (OnlineMessage, SocketAddr) =
                            serde_json::from_reader(stream).unwrap();
                        tx.send((sender, msg)).unwrap();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{}", e),
                }
            }
        });

        Self {
            players,
            player_number,
            rx,
            join_handle,
            stop_signal,
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

    fn send(&self, player: usize, msg: &OnlineMessage) {
        let stream = TcpStream::connect(self.players[player]).unwrap();
        serde_json::to_writer(stream, &(msg, self.players[self.player_number])).unwrap();
    }

    fn broadcast(&self, msg: &OnlineMessage) {
        for i in 0..self.player_count() {
            self.send(i, msg);
        }
    }

    fn receive(&self) -> (usize, OnlineMessage) {
        let (addr, msg) = self.rx.recv().unwrap();

        let player_number = match self
            .players
            .iter()
            .position(|&player_addr| player_addr == addr)
        {
            Some(n) => n,
            None => panic!(
                "Could not find player with addr {} ({:?})",
                addr, self.players
            ),
        };

        (player_number, msg)
    }

    fn receive_many(&self, n: usize) -> Vec<(usize, OnlineMessage)> {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let msg = self.receive();
            msgs.push(msg);
        }
        msgs
    }

    fn stop(self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        self.join_handle.join().unwrap();
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

    let facilitator = FacilitatorImpl::new(players, listener);

    let params = secure_params();
    let state = PlayerState::new(facilitator);
    let input = OsRng.gen_bigint_range(&BigInt::zero(), &BigInt::from(50_u32));

    add_private_inputs(state, params, input)
}

fn add_private_inputs(
    mut state: PlayerState<FacilitatorImpl>,
    params: Parameters,
    input: BigInt,
) -> Result<(), io::Error> {
    let player_count = state.facilitator.player_count();

    println!("Begin preprocessing...");
    prep::protocol::initialize(&params, &mut state);

    let mut pairs = Vec::with_capacity(player_count);
    for _ in 0..player_count {
        let pair = prep::protocol::pair(&params, &state);
        pairs.push(pair);
    }
    println!("Finished with preprocessing!");

    println!("Sharing inputs...");
    let mut input_shares = Vec::with_capacity(player_count);
    for i in 0..player_count {
        let r_pair = pairs.pop().unwrap();
        let input_share = if i == state.facilitator.player_number() {
            println!("My input is: {}", input);
            online::protocol::give_input(&params, input.clone(), r_pair, &state)
        } else {
            online::protocol::receive_input(r_pair, &state)
        };
        input_shares.push(input_share);
    }
    println!("Finished sharing all inputs!");

    println!("Adding all inputs together...");
    let added_shares = input_shares
        .iter()
        .fold((BigInt::zero(), BigInt::zero()), |a, b| {
            online::protocol::add(&a, b)
        });
    println!("Finished adding all inputs!");

    println!("Getting output...");
    let output = online::protocol::output(&params, added_shares, &state);

    println!("Output is {}", output);

    state.stop();

    Ok(())
}
