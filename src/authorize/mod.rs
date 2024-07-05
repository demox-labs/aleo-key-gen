use std::str::FromStr;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use snarkvm::{circuit::Aleo, prelude::{Network, PrivateKey, ProgramID, Serialize}, synthesizer::{Process, Program}};

#[derive(Serialize)]
pub struct AuthorizationResponse {
    pub authorization: String,
    pub fee_authorization: String
}

pub(crate) fn authorize_transaction<N: Network, A: Aleo<Network = N>>(
    programs: Vec<String>,
    private_key: &PrivateKey<N>,
    program_id: &str,
    function: &str,
    inputs: Vec<String>,
    fee_microcredits: u64,
) -> Result<String, String> {
    println!("{}", &format!("Authorizing function: {function} on-chain"));
    
    let mut process_native = Process::load().map_err(|err| err.to_string())?;
    let process = &mut process_native;

    println!("{}", "Loading program");
    // For each program load it into the process
    for program in programs.iter() {
        let program = Program::from_str(program).map_err(|e| e.to_string())?;
        process.add_program(&program).map_err(|e| e.to_string())?;
    }

    println!("{}", "Check program imports are valid and add them to the process");
    let program_id = ProgramID::from_str(program_id).map_err(|e| e.to_string())?;
    
    println!("{}", "Creating authorization");
    let rng = &mut ChaCha20Rng::from_entropy();
    let authorization = process
        .authorize::<A, _>(
            private_key,
            program_id,
            function,
            inputs.iter(),
            rng,
        )
        .map_err(|err| err.to_string())?;

    let execution_id = authorization.to_execution_id().map_err(|e| e.to_string())?;

    let fee_authorization = 
      process.authorize_fee_public::<A, _>(&private_key, fee_microcredits, 0u64, execution_id, rng).map_err(|e| e.to_string())?;

    let authorization_response = AuthorizationResponse {
        authorization: authorization.to_string(),
        fee_authorization: fee_authorization.to_string()
    };

    let authorization_response = serde_json::to_string(&authorization_response)
        .map_err(|_| "Could not serialize authorization response".to_string())?;

    Ok(authorization_response)
}