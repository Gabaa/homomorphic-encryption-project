//! Preprocessing phase (Multiparty Computation from Somewhat Homomorphic Encryption, sec. 5)

use crate::{encryption::Parameters, mpc::Player};

/// Represents the preprocessing protocol (fig. 7)
pub struct ProtocolPrep {}

impl ProtocolPrep {
    /// Implements the Initialize step
    pub fn initialize(params: &Parameters, players: &Vec<Player>) {
        todo!()
    }

    /// Implements the Pair step
    pub fn pair() {
        todo!()
    }

    /// Implements the Triple step
    pub fn triple() {
        todo!()
    }
}

/// Implements Protocol Reshare (fig. 4)
pub fn reshare() {
    todo!()
}

/// Implements Protocol PBracket (fig. 5)
pub fn p_bracket() {
    todo!()
}

/// Implements Protocol PAngle (fig. 6)
pub fn p_angle() {
    todo!()
}
