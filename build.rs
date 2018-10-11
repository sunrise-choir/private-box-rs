use std::process::{Command, ExitStatus};
use std::env;

fn main() {
    env::var("SODIUM_STATIC").and_then(|_|{
        env::var("SODIUM_LIB_DIR").expect("SODIUM_LIB_DIR was not set");
        env::var("SODIUM_INSTALL_DIR").expect("SODIUM_INSTALL_DIR was not set");
        
        Command::new("make").args(&["clean"])
            .status(); //Clean might fail if the project wasn't configured or was cleaned already. Just ignore result.
        Command::new("make").args(&["libsodium", "-j4"])
            .status().expect("could not make libsodium");
        Ok(0)
    })
    .unwrap();
}
