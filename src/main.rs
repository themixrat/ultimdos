use std::{
    fs,
    io::{stdin, stdout},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use dns_lookup::lookup_host;
use rand::Rng;
use rust_mc_proto::{
    DataBufferReader, DataBufferWriter, MCConnTcp, MinecraftConnection, Packet, ProtocolError,
};
use serde_json::Value;
use socks::Socks5Stream;
use std::io::Read;
use std::io::Write;
use uuid::Uuid;

const PROTOCOL_VERSION: u16 = 763;
const ALL_PLAYERS_FILE: &str = "all_players.txt";
const PROXIES_FILE: &str = "proxies.txt";

fn build_packet(
    id: u8,
    builder: impl Fn(&mut Packet) -> Result<(), ProtocolError>,
) -> Result<Packet, ProtocolError> {
    let mut packet = Packet::empty(id);
    builder(&mut packet)?;
    Ok(packet)
}

fn send_handshake<T: Read + Write>(
    conn: &mut MinecraftConnection<T>,
    protocol_version: u16,
    server_address: &str,
    server_port: u16,
    next_state: u8,
) -> Result<(), ProtocolError> {
    conn.write_packet(&build_packet(0x00, |p| {
        p.write_u16_varint(protocol_version)?;
        p.write_string(server_address)?;
        p.write_unsigned_short(server_port)?;
        p.write_u8_varint(next_state)
    })?)
}

fn send_status_request<T: Read + Write>(
    conn: &mut MinecraftConnection<T>,
) -> Result<(), ProtocolError> {
    conn.write_packet(&Packet::empty(0x00))
}

fn read_status_response<T: Read + Write>(
    conn: &mut MinecraftConnection<T>,
) -> Result<String, ProtocolError> {
    conn.read_packet()?.read_string()
}

fn get_input(prompt: &str) -> String {
    stdout().write(prompt.as_bytes()).unwrap();
    stdout().flush().unwrap();
    loop {
        match stdin().lines().next() {
            Some(i) => match i {
                Ok(k) => return k,
                Err(_) => {}
            },
            None => {}
        }
    }
}

macro_rules! error_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Err(()),
        }
    };
}

macro_rules! none_return {
    ( $e:expr ) => {
        match $e {
            Some(x) => x,
            None => return Err(()),
        }
    };
}

fn parse_players<T: Read + Write>(
    conn: &mut MinecraftConnection<T>,
    host: &str,
    port: u16,
) -> Result<Vec<String>, ()> {
    send_handshake(conn, PROTOCOL_VERSION, &host, port, 1).unwrap();
    send_status_request(conn).unwrap();

    let motd = error_return!(read_status_response(conn));
    let motd: Value = error_return!(serde_json::from_str(&motd));
    let motd = none_return!(motd.as_object());

    let sample = none_return!(none_return!(motd.get("players")).as_object());
    let sample = none_return!(match sample.get("sample") {
        Some(v) => v,
        None => {
            return Ok(Vec::new());
        }
    }
    .as_array());

    let mut players: Vec<String> = Vec::new();

    for sam in sample {
        players.push(
            none_return!(none_return!(none_return!(sam.as_object()).get("name")).as_str())
                .to_string(),
        )
    }

    Ok(players)
}

fn save_all_players(players: &Vec<String>) {
    let mut text = String::new();

    for pl in players {
        text.push_str(&(pl.to_string() + "\n"))
    }

    fs::write(ALL_PLAYERS_FILE, text.as_bytes()).unwrap();
}

fn load_all_players() -> Vec<String> {
    let text = fs::read_to_string(ALL_PLAYERS_FILE).unwrap();

    let mut players = Vec::new();

    for line in text.split("\n") {
        if line == "" {
            break;
        }
        players.push(line.to_string());
    }

    players
}

fn add_all_players(all_players: &mut Vec<String>, now_players: &Vec<String>) {
    for pl in now_players {
        if !all_players.contains(pl) {
            all_players.push(pl.clone())
        }
    }
}

fn load_proxies() -> Vec<String> {
    let text = fs::read_to_string(PROXIES_FILE).unwrap();

    let mut proxies = Vec::new();

    for line in text.split("\n") {
        if line == "" {
            continue;
        }
        proxies.push(line.to_string());
    }

    proxies
}

fn connect_with_proxy(
    proxy: &str,
    server: &str,
) -> Result<MinecraftConnection<Socks5Stream>, ProtocolError> {
    Ok(MinecraftConnection::new(
        match Socks5Stream::connect(proxy, server) {
            Ok(i) => i,
            Err(_) => return Err(ProtocolError::StreamConnectError),
        },
    ))
}

fn send_player<T: Read + Write>(
    conn: &mut MinecraftConnection<T>,
    player: &str,
    host: &str,
    port: u16,
) -> Result<(), ProtocolError> {
    send_handshake(conn, PROTOCOL_VERSION, host, port, 2).unwrap();

    conn.write_packet(&build_packet(0x00, |p| {
        p.write_string(player)?;

        let mut hash = md5::compute(format!("OfflinePlayer:{}", player)).0;
        hash[6] = hash[6] & 0x0f | 0x30;
        hash[8] = hash[8] & 0x3f | 0x80;
        let uuid = Uuid::from_bytes(hash);
        p.write_uuid(&uuid)?;

        Ok(())
    })?)?;

    let mut login = true;

    loop {
        let mut packet = match conn.read_packet() {
            Ok(i) => i,
            Err(e) => {
                println!("error: {:?}", e);
                break;
            }
        };

        // println!("packet ({}) length: {}", {
        //     let id = format!("{:X?}", packet.id);
        //     if id.len() == 1 {
        //         format!("0x0{}", id)
        //     } else {
        //         format!("0x{}", id)
        //     }
        // }, packet.buffer.len());

        match packet.id {
            0x03 => {
                if login {
                    conn.set_compression(packet.read_usize_varint()?)
                } else {
                    let keep_alive_id = packet.read_long()?;
                    // println!("keep_alive: {}", keep_alive_id);
                    conn.write_packet(&build_packet(0x03, |p| p.write_long(keep_alive_id))?)?;
                }
            }
            0x02 => {
                if login {
                    // conn.write_packet(&build_packet(0x03, |p| p.write_bytes(&[0;10]))?)?;
                    login = false;

                    println!("connected: {}", player);
                } else {
                    conn.write_packet(&Packet::empty(0x02))?;
                }
            }
            0x00 => {
                let message = match packet.read_string() {
                    Ok(i) => i,
                    Err(_) => {
                        continue;
                    }
                };

                println!("disconnect message: {}", message);
                match message.as_str() {
                    "{\"text\":\"Connection throttled! Please wait before reconnecting.\"}" => {
                        thread::sleep(Duration::from_secs(4));
                        return Err(ProtocolError::WriteError);
                    }, "{\"color\":\"dark_red\",\"text\":\"Игрок с данным никнеймом уже играет на сервере!\"}" => {
                        break;
                    }_ => {
                        break;
                    }
                }
            }
            0x23 => {
                let keep_alive_id = packet.read_long()?;
                // println!("keep_alive: {}", keep_alive_id);
                conn.write_packet(&build_packet(0x12, |p| p.write_long(keep_alive_id))?)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn connect_player(
    proxies: Arc<Mutex<Vec<String>>>,
    player: &str,
    host: &str,
    port: u16,
    server: &str,
) -> Result<String, ProtocolError> {
    if proxies.lock().unwrap().len() > 0 {
        // println!("123");
        let mut rng = rand::thread_rng();

        let mut proxy;

        {
            let prox = proxies.lock().unwrap();
            proxy = prox[rng.gen_range(0..prox.len())].clone();
        }

        // println!("123");
        let mut conn = match connect_with_proxy(&proxy, &server) {
            Ok(i) => i,
            Err(e) => {
                println!("bad proxy: {}, ({})", proxy, proxies.lock().unwrap().len());
                if proxies.lock().unwrap().len() > 1 {
                    match proxies.lock().unwrap().iter().position(|x| x == &proxy) {
                        Some(i) => {
                            proxies.lock().unwrap().remove(i);
                        }
                        None => {}
                    };
                }

                return Ok("disconnect".to_string());
            }
        };

        send_player(&mut conn, &player, &host, port)?;
    } else {
        send_player(
            &mut MinecraftConnection::connect(&server)?,
            &player,
            &host,
            port,
        )?;
    }

    Ok("disconnect".to_string())
}

fn spawn_connection(
    player: String,
    proxies: Arc<Mutex<Vec<String>>>,
    host: String,
    port: u16,
    spawned: Arc<Mutex<Vec<String>>>,
) {
    if spawned.lock().unwrap().contains(&player) {
        return;
    }

    let local_proxies = proxies.clone();
    let local_player = player.clone();
    let local_spawned = spawned.clone();

    let server = host.clone() + ":" + &port.to_string();

    thread::spawn(move || {
        local_spawned.lock().unwrap().push(local_player.clone());

        println!("try to connect: {}", local_player);

        loop {
            match connect_player(local_proxies.clone(), &local_player, &host, port, &server) {
                Ok(i) => (),
                Err(e) => {
                    println!("error: {:?}", e);
                }
            };

            println!("disconnected: {}", local_player);
            // thread::sleep(Duration::from_secs(5));
        }

        let mut sp = local_spawned.lock().unwrap();
        let index = sp.iter().position(|x| *x == local_player).unwrap();
        sp.remove(index);
    });

    // thread::sleep(Duration::from_secs(1));
}

fn domain_to_ip(domain: &str) -> String {
    let host = lookup_host(domain).unwrap()[0];
    if let IpAddr::V4(host) = host {
        let octets = host.octets();

        octets[0].to_string()
            + "."
            + &octets[0].to_string()
            + "."
            + &octets[0].to_string()
            + "."
            + &octets[0].to_string()
    } else {
        String::new()
    }
}

fn main() {
    let ip = get_input("ip: ");

    let host = &get_input("host: ");
    let port: u16 = get_input("port: ").parse().unwrap();

    let proxies = Arc::new(Mutex::new(load_proxies()));

    let mut all_players = load_all_players();
    let mut players = Vec::new();

    let mut started = true;
    let spawned = Arc::new(Mutex::new(Vec::new()));

    loop {
        let mut conn = match MCConnTcp::connect(&ip) {
            Ok(i) => i,
            Err(_) => {
                println!("connection skazalo bye bye");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let mut now_players = match parse_players(&mut conn, host, port) {
            Ok(i) => i,
            Err(_) => {
                println!("players coulnd not parsed lol! XD");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        for i in 0..now_players.len() {
            let val = now_players.get(i);
            if let Some(val) = val {
                if val == "Anonymous Player" || val == "PansanGG_" || val == "IlyiCraft" {
                    now_players.remove(i);
                }
            }
        }

        add_all_players(&mut all_players, &now_players);
        save_all_players(&all_players);

        if started {
            for pl in &all_players {
                if !now_players.contains(pl) {
                    spawn_connection(
                        pl.to_string(),
                        proxies.clone(),
                        host.to_string(),
                        port,
                        spawned.clone(),
                    );
                }
            }

            started = false;
        }

        let mut left_players = Vec::new();

        // println!("players: {:?}", &players);

        for pl in &players {
            if !now_players.contains(pl) {
                left_players.push(pl.clone());
            }
        }

        // println!("now players: {:?}", now_players);

        players = now_players;

        if left_players.len() > 0 {
            for player in left_players {
                spawn_connection(
                    player,
                    proxies.clone(),
                    host.to_string(),
                    port,
                    spawned.clone(),
                );
            }
        }

        thread::sleep(Duration::from_secs(1));
    }
}
