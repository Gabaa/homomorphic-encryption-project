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
    prob::sample_single,
    protocol::{Facilicator, KeyMaterial, OnlineMessage, PrepMessage},
};
use rug::Integer;

struct FacilitatorImpl {
    players: Vec<SocketAddr>,
    player_number: usize,
    receivers: Vec<Receiver<OnlineMessage>>,
    join_handle: JoinHandle<()>,
    stop_signal: Arc<AtomicBool>,
}

impl FacilitatorImpl {
    fn new(players: Vec<SocketAddr>, listener: TcpListener) -> Self {
        let player_number = players
            .iter()
            .position(|&addr| addr == listener.local_addr().unwrap())
            .unwrap();

        let mut transmitters = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..players.len() {
            let (tx, rx) = mpsc::channel();
            transmitters.push(tx);
            receivers.push(rx);
        }
        let stop_signal = Arc::new(AtomicBool::new(false));

        let cloned_players = players.clone();

        let stop_signal_clone = stop_signal.clone();
        let join_handle = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();

            while !stop_signal_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (msg, sender): (OnlineMessage, SocketAddr) =
                            serde_json::from_reader(stream).unwrap();

                        let player_number = match cloned_players
                            .iter()
                            .position(|&player_addr| player_addr == sender)
                        {
                            Some(n) => n,
                            None => {
                                panic!(
                                    "Could not find player with addr {} ({:?})",
                                    sender, cloned_players
                                )
                            }
                        };

                        transmitters[player_number].send(msg).unwrap();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{}", e),
                }
            }
        });

        Self {
            players,
            player_number,
            receivers,
            join_handle,
            stop_signal,
        }
    }
}

impl Facilitator for FacilitatorImpl {
    fn player_count(&self) -> usize {
        self.players.len()
    }

    fn player_number(&self) -> usize {
        self.player_number
    }

    fn send(&self, player: usize, msg: &OnlineMessage) {
        println!("send to   [{:02}] {:?}", player, msg);

        let stream = TcpStream::connect(self.players[player]).unwrap();
        serde_json::to_writer(stream, &(msg, self.players[self.player_number])).unwrap();
    }

    fn broadcast(&self, msg: &OnlineMessage) {
        for i in 0..self.player_count() {
            self.send(i, msg);
        }
    }

    fn receive(&self, player: usize) -> OnlineMessage {
        let msg = self.receivers[player].recv().unwrap();

        println!("recv from [{:02}] {:?}", player, msg);
        msg
    }

    fn receive_from_all(&self) -> Vec<OnlineMessage> {
        let n = self.player_count();
        let mut msgs = Vec::with_capacity(n);
        for i in 0..n {
            let msg = self.receive(i);
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
    let (listener, players, key_material) = initialize_mpc()?;

    let facilitator = FacilitatorImpl::new(players, listener);

    let params = secure_params();
    let state = PlayerState::new(facilitator, key_material);

    let input = sample_single(&Integer::from(50));

    let protocol = Protocol::X1MulX2PlusX3;
    protocol.run(state, params, input)
}

fn initialize_mpc() -> Result<(TcpListener, Vec<SocketAddr>, KeyMaterial), io::Error> {
    let listener = TcpListener::bind("localhost:0")?;

    println!("Connecting to dealer...");
    let stream = TcpStream::connect("localhost:9000")?;

    println!("Sending Start...");
    let start_msg = PrepMessage::Start(listener.local_addr()?);
    serde_json::to_writer(stream, &start_msg)?;

    println!("Waiting for players to connect...");
    let mut players = vec![];

    let key_material;
    loop {
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
    println!("Received key material!");

    Ok((listener, players, key_material))
}

#[allow(dead_code)]
enum Protocol {
    AddAll,
    MulAll,
    X1MulX2PlusX3,
}

impl Protocol {
    fn run(
        self,
        mut state: PlayerState<FacilitatorImpl>,
        params: Parameters,
        input: Integer,
    ) -> io::Result<()> {
        match self {
            Protocol::AddAll => {
                let player_count = state.facilitator.player_count();

                println!("Begin preprocessing...");
                prep::protocol::initialize(&params, &mut state);

                let mut pairs = Vec::with_capacity(player_count);
                for _ in 0..player_count {
                    let pair = prep::protocol::pair(&params, &state);
                    pairs.push(pair);
                }

                println!("Sharing inputs...");
                let mut input_shares = Vec::with_capacity(player_count);
                for i in 0..player_count {
                    let r_pair = pairs.pop().unwrap();
                    let input_share = if i == state.facilitator.player_number() {
                        println!("My input is: {}", input);
                        online::protocol::give_input(&params, input.clone(), r_pair, &state)
                    } else {
                        online::protocol::receive_input(r_pair, i, &state)
                    };
                    input_shares.push(input_share);
                }

                println!("Adding all inputs together...");
                let added_shares = input_shares
                    .iter()
                    .fold((Integer::ZERO, Integer::ZERO), |a, b| {
                        online::protocol::add(&a, b)
                    });

                println!("Getting output...");
                let output = online::protocol::output(&params, added_shares, &state);

                println!("Output is {} (input {})", output, input);

                state.stop();

                Ok(())
            }
            Protocol::MulAll => {
                let player_count = state.facilitator.player_count();

                println!("Begin preprocessing...");
                prep::protocol::initialize(&params, &mut state);

                let mut pairs = Vec::with_capacity(player_count + (player_count - 1));
                for _ in 0..player_count {
                    let pair = prep::protocol::pair(&params, &state);
                    pairs.push(pair);
                }

                let mut triples = Vec::with_capacity(player_count - 1);
                for _ in 0..(player_count - 1) {
                    let triple = prep::protocol::triple(&params, &state);
                    triples.push(triple);
                    let triple = prep::protocol::triple(&params, &state);
                    triples.push(triple);

                    //Extra pair for multiply
                    let pair = prep::protocol::pair(&params, &state);
                    pairs.push(pair);
                }

                println!("Sharing inputs...");
                let mut input_shares = Vec::with_capacity(player_count);
                for i in 0..player_count {
                    let r_pair = pairs.pop().unwrap();
                    let input_share = if i == state.facilitator.player_number() {
                        println!("My input is: {}", input);
                        online::protocol::give_input(&params, input.clone(), r_pair, &state)
                    } else {
                        online::protocol::receive_input(r_pair, i, &state)
                    };
                    input_shares.push(input_share);
                }

                println!("Multiplying all inputs together...");
                let mut multiplied_shares = input_shares[0].clone();
                for input_share in input_shares.iter().skip(1) {
                    multiplied_shares = online::protocol::multiply(
                        &params,
                        multiplied_shares,
                        input_share.clone(),
                        triples.pop().unwrap(),
                        triples.pop().unwrap(),
                        pairs.pop().unwrap().0,
                        &mut state,
                    );
                }

                println!("Getting output...");
                let output = online::protocol::output(&params, multiplied_shares, &state);

                println!("Output is {} (input {})", output, input);

                state.stop();

                Ok(())
            }
            Protocol::X1MulX2PlusX3 => {
                let player_count = state.facilitator.player_count();
                assert!(player_count == 3, "incorrect number of players");

                println!("Begin preprocessing...");
                prep::protocol::initialize(&params, &mut state);

                let mut pairs = Vec::with_capacity(player_count + (player_count - 1));
                for _ in 0..player_count {
                    let pair = prep::protocol::pair(&params, &state);
                    pairs.push(pair);
                }

                let mut triples = Vec::with_capacity(player_count - 1);
                for _ in 0..(player_count - 1) {
                    let triple = prep::protocol::triple(&params, &state);
                    triples.push(triple);
                    let triple = prep::protocol::triple(&params, &state);
                    triples.push(triple);

                    //Extra pair for multiply
                    let pair = prep::protocol::pair(&params, &state);
                    pairs.push(pair);
                }

                println!("Sharing inputs...");
                let mut input_shares = Vec::with_capacity(player_count);
                for i in 0..player_count {
                    let r_pair = pairs.pop().unwrap();
                    let input_share = if i == state.facilitator.player_number() {
                        println!("My input is: {}", input);
                        online::protocol::give_input(&params, input.clone(), r_pair, &state)
                    } else {
                        online::protocol::receive_input(r_pair, i, &state)
                    };
                    input_shares.push(input_share);
                }

                println!("Multiplying x_1 with x_2...");
                let mut multiplied_shares = input_shares[0].clone();
                multiplied_shares = online::protocol::multiply(
                    &params,
                    multiplied_shares,
                    input_shares[1].clone(),
                    triples.pop().unwrap(),
                    triples.pop().unwrap(),
                    pairs.pop().unwrap().0,
                    &mut state,
                );

                println!("Adding x_3 to previous result...");
                let added_share =
                    online::protocol::add(&multiplied_shares, &input_shares[2].clone());

                println!("Getting output...");
                let output = online::protocol::output(&params, added_share, &state);

                println!("Output is {} (input {})", output, input);

                state.stop();

                Ok(())
            }
        }
    }
}
