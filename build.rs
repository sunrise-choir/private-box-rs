use std::process::Command;
use std::env;

fn main() {

    env::var("SODIUM_STATIC").expect("SODIUM_STATIC was not set");
    env::var("SODIUM_STATIC").and_then(|_|{
        env::var("SODIUM_LIB_DIR").expect("SODIUM_LIB_DIR was not set");
        env::var("SODIUM_INSTALL_DIR").expect("SODIUM_INSTALL_DIR was not set");

        //Command::new("make").args(&["clean"])
        //    .status().expect("could not clean libsodium");
        Command::new("make").args(&["libsodium", "-j4"])
                       .status().expect("could not make libsodium");
        Ok(0)
    }).unwrap();


}
