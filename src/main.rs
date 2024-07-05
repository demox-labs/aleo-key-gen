use age::secrecy::Secret;
use age::x25519;
use age::{Encryptor, Decryptor};
use rand_chacha::rand_core::SeedableRng;
use snarkvm::prelude::*;
use snarkvm::console::account::{PrivateKey, Address};
use rand_chacha::ChaCha20Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::env;
use std::io::{Cursor, Read, Write};
use base64::{decode, encode};
use rpassword::read_password;

fn generate_keypair(rng: &mut ChaCha20Rng) -> (PrivateKey<MainnetV0>, Address<MainnetV0>) {
    let private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();
    let address = Address::try_from(&private_key).unwrap();
    (private_key, address)
}

fn main() {
    // Read the command and arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [<args>]", args[0]);
        eprintln!("Commands:");
        eprintln!("  generate <desired_suffix> <sample_size>");
        eprintln!("  decrypt <encrypted_key_file> <password1> <password2>");
        std::process::exit(1);
    }

    let command = &args[1];
    match command.as_str() {
        "generate" => {
            if args.len() != 4 {
                eprintln!("Usage: {} generate <desired_suffix> <sample_size>", args[0]);
                std::process::exit(1);
            }
            let desired_suffix = &args[2];
            let sample_size: usize = args[3].parse().unwrap();

            // Read passwords from users securely
            let passwords = read_passwords(4u8);

            generate_keys(desired_suffix, sample_size, &passwords);
        }
        "decrypt" => {
            if args.len() != 3 {
                eprintln!("Usage: {} decrypt <encrypted_key_file> <password1> <password2>", args[0]);
                std::process::exit(1);
            }
            let encrypted_key_file = &args[2];
            let passwords = read_passwords(2u8);
            assert_eq!(passwords.len(), 2);
            let password1 = &passwords[0];
            let password2 = &passwords[1];
            decrypt_command(encrypted_key_file, password1, password2);
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}


fn get_password(password_number: u8) -> String {
    loop {
        println!("Enter password {}: ", password_number);
        let password = read_password().expect("Error reading password");
        println!("Confirm password {}: ", password_number);
        let confirm_password = read_password().expect("Error reading password");
        if password == confirm_password {
            return password;
        } else {
            println!("Passwords do not match, try again.");
        }
    }
}

fn read_passwords(num_passwords: u8) -> Vec<String> {
    let mut passwords = vec![];
    for i in 0..num_passwords {
        let password = get_password(i + 1);
        
        passwords.push(password);
    }
    passwords
}

fn generate_keys(desired_suffix: &str, sample_size: usize, passwords: &Vec<String>) {
    let guess_count = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicUsize::new(0));

    rayon::scope(|s| {
        for _ in 0..num_cpus::get() {
            let guess_count = Arc::clone(&guess_count);
            let found = Arc::clone(&found);
            let desired_suffix = desired_suffix.to_string();
            let passwords = passwords.clone();

            s.spawn(move |_| {
                let mut rng = ChaCha20Rng::from_entropy();
                while found.load(Ordering::Relaxed) < sample_size {
                    let (private_key, address) = generate_keypair(&mut rng);
                    guess_count.fetch_add(1, Ordering::Relaxed);

                    if guess_count.load(Ordering::Relaxed) % 1000 == 0 {
                        println!("Number of guesses: {}", guess_count.load(Ordering::Relaxed));
                    }

                    if address.to_string().ends_with(&desired_suffix) {
                        // We found an address with the desired suffix, print it
                        println!("Found address: {}", address.to_string());
                        found.fetch_add(1, Ordering::Relaxed);

                        // Encrypt the private key with passwords from two people
                        for i in 0..passwords.len() {
                            for j in i + 1..passwords.len() {
                                let password1 = &passwords[i];
                                let password2 = &passwords[j];
                                let concatenated_password = password1.to_owned() + password2;
                                let encrypted_key = encrypt_private_key(&private_key, &concatenated_password).unwrap();
                                // Decrypt the encrypted key & verify it
                                let decrypted_key = decrypt_private_key(&encrypted_key, &concatenated_password).unwrap();
                                assert_eq!(private_key, decrypted_key);
                                // Print the index of each password pair & the encrypted key
                                println!("{}: {} {} {}", address.to_string(), i, j, encrypted_key);
                            }
                        }
                    }
                }
            });
        }
    });

    println!("Sample collection completed.");
    println!("Number of guesses: {}", guess_count.load(Ordering::Relaxed));
}

fn encrypt_private_key(private_key: &PrivateKey<MainnetV0>, password: &str) -> Result<String, Box<dyn std::error::Error>> {
  let encryptor = age::Encryptor::with_user_passphrase(Secret::new(password.to_owned()));

  let mut encrypted = vec![];
  let mut writer = encryptor.wrap_output(&mut encrypted)?;
  writer.write_all(&private_key.to_bytes_le().unwrap())?;
  writer.finish()?;

  Ok(encode(&encrypted))
}

fn decrypt_private_key(encrypted_private_key: &str, password: &str) -> Result<PrivateKey<MainnetV0>, Box<dyn std::error::Error>> {
  // Decode the base64-encoded string
  let encrypted_bytes = decode(encrypted_private_key)?;

  // Create a Decryptor from the byte slice
  let decryptor = match Decryptor::new(Cursor::new(encrypted_bytes))? {
      Decryptor::Passphrase(decryptor) => decryptor,
      _ => return Err("Unexpected recipient type".into()),
  };

  // Decrypt the data
  let mut decrypted = vec![];
  let mut reader = decryptor.decrypt(&Secret::new(password.to_owned()), None)?;
  reader.read_to_end(&mut decrypted)?;

  // Convert the decrypted bytes back into a PrivateKey
  let private_key = PrivateKey::<MainnetV0>::read_le(&*decrypted)?;

  Ok(private_key)
}

fn decrypt_command(encrypted_key_file: &str, password1: &str, password2: &str) {
    let concatenated_password = password1.to_owned() + password2;
    let private_key = decrypt_private_key(encrypted_key_file, &concatenated_password).unwrap();
    println!("Decrypted address: {}", Address::try_from(&private_key).unwrap().to_string());
    println!("Decrypted private key: {}", private_key.to_string());
}