use std::{env, error::Error, io, net::SocketAddr, path::Path};

use mousevpn_config::{load_toml, ServerConfig};
use mousevpn_server::{generate_example_configs, run};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag, path] if flag == "--check-config" => {
            let config: ServerConfig = load_toml(Path::new(path))?;
            config.validate()?;
            println!("configuration valid");
        }
        [flag, path] if flag == "--config" => {
            let config: ServerConfig = load_toml(Path::new(path))?;
            run(&config.validate()?)?;
        }
        [command, server_flag, server_path, client_flag, client_path, endpoint_flag, endpoint]
            if command == "generate-example"
                && server_flag == "--server-config"
                && client_flag == "--client-config"
                && endpoint_flag == "--server-endpoint" =>
        {
            generate_example_configs(
                Path::new(server_path),
                Path::new(client_path),
                endpoint.parse::<SocketAddr>()?,
            )?;
            println!("created {server_path} and {client_path}");
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage:\n  mousevpn-server --config <server.toml>\n  mousevpn-server --check-config <server.toml>\n  mousevpn-server generate-example --server-config <server.toml> --client-config <client.toml> --server-endpoint <IP:PORT>",
    )
}
