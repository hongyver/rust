
//
// remote sign
//
use std::{env, string};
use std::process::Command;

use std::fs::File;

use std::str::{self, FromStr};
use std::path::Path;
use std::ffi::OsStr;

// use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{prelude::*, Days, Months};
use chrono_tz::Asia::Seoul;
use chrono_tz::Tz;

use std::io::prelude::*;
use std::io::{self, Write};
use std::io::BufReader;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use local_ip_address::local_ip;


// 시간 측정
// use std::time::Instant;
// let start = Instant::now();
// // do stuff
// let elapsed = start.elapsed();
// // Debug format
// println!("Debug: {:?}", elapsed); 
// // Format as milliseconds rounded down
// // Since Rust 1.33:
// println!("Millis: {} ms", elapsed.as_millis());
// // Before Rust 1.33:
// println!("Millis: {} ms", (elapsed.as_secs() * 1_000) + (elapsed.subsec_nanos() / 1_000_000) as u64);


fn print_usage(prog_name: &String) -> () {
	println!("usage:");
	println!("\t{} {}", prog_name, "-s <PORT>");
	println!("\t{} {}", prog_name, "-s 8090");
	println!("\t{} {}", prog_name, "-evo <IP> <PORT> <filename>");
	println!("\t{} {}", prog_name, "-evo 10.10.110.185 8090 remote_sign");
	println!("\t{} {}", prog_name, "-ev 10.10.110.185 8090 remote_sign");
	println!("\t{} {}", prog_name, "-evo : over write. -ev : create new signed file");

}

pub fn progressbar(value: usize, target_value: usize) -> () {
    let mut percent = (value * 100) / target_value;
    if percent >= 100 {
        percent = 100;
    };
    let n = (4 * percent) / 10 ;

    let var1 = "=".repeat(n).to_string();
    let var2 = "-".repeat(40-n).to_string();
    let s = format!("[{}{}] {}%", var1, var2, percent);

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    io::stdout().write_all("\r".as_bytes()).unwrap();
    handle.write_all(s.as_bytes()).unwrap();
    handle.flush().unwrap();
}

fn main() -> std::io::Result<()> {

	let args: Vec<String> = env::args().collect();
	if args.len() < 2 {
		print_usage(&args[0]);
		return Ok(());
	}

	let arg = args[1].as_str();
	match arg {
		"-s" => {
			loop {
				let ip = local_ip().unwrap();
				let port = args[2].to_string();
				receive_file(&ip, &port);
			}
		},
		"-ev" | "-evo" => {
			let srv_ip: IpAddr = args[2].parse().expect("parse failed");
			let port = args[3].to_string();
			let file_name: String = args[4].to_string();

			send_file(arg, 1, &srv_ip, &port, &file_name)
		},
		_ => Ok(print_usage(&args[0])),
	}?;

	return Ok(());
}

// client
fn get_tcp_connect(ip: &IpAddr, port: &String) -> std::io::Result<easytcp::tcp_aes_cbc::SecureTcp> {

	let key = "hongyver";
	let tcp = easytcp::tcp_aes_cbc::connect(&ip.to_string(), port, key)?;

	return Ok(tcp)
}

pub fn send_file(arg: &str, sign_type: u8, srv_ip: &IpAddr, port: &String, file_path: &str) -> std::io::Result<()> {
	
	let client_ip = local_ip().unwrap();
	println!("Send : {}", file_path);

	let tcp = get_tcp_connect(&srv_ip, &port)?;

	// Send header to server : type, ip, file name
	let sign_type: Vec<u8> = vec![sign_type];
	tcp.send(sign_type)?;

	let data = client_ip.to_string();
	tcp.send(data.into_bytes().to_vec())?;

	let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
	tcp.send(file_name.as_bytes().to_vec());

	// Send a file to server
	let file = File::open(file_path)?;
	let file_length: u64 = file.metadata().unwrap().len();
	let mut br = BufReader::with_capacity(4096, file);

	tcp.send(file_length.to_be_bytes().to_vec())?;
	let mut progress: usize = 0;

	loop {
		progressbar(progress, file_length.try_into().unwrap());
		let buffer = br.fill_buf()?;
		let bufferlen = buffer.len();
		if bufferlen == 0 {
				break;
		}
		tcp.send(buffer.to_vec()).unwrap();
		br.consume(bufferlen);
		progress = progress + 4096;
	}
	println!("");
	
	// receive a file to signed
	let package_len = tcp.recive()?;
	let package_len_bytes: [u8; 8] = package_len[0..8].try_into().unwrap();
	let n = u64::from_be_bytes(package_len_bytes);

	let return_file: String;

	if arg == "-evo" {
		return_file = file_path.to_string();
	} else {
		let now: DateTime<Tz> = Utc::now().with_timezone(&Seoul);
		return_file = "signed_".to_owned() + &now.format("%Y_%m%d_%H%M%S_%f").to_string() + "_" + file_name;		
	}

	println!("{}", return_file);

	let mut f = File::create(return_file)?;
	let mut pkglen = n;

	loop {
		if pkglen == 0 {
				break;
		}
		let data = tcp.recive()?;
		let datalen: u64 = data.len().try_into().unwrap();
		pkglen = pkglen - datalen;
		f.write_all(&data)?;

	}
	f.sync_data()?;
	drop(f);

	return Ok(());
}


//server
fn get_tcp_listen(ip: &IpAddr, port: &String) -> std::io::Result<easytcp::tcp_aes_cbc::SecureTcp> {

	let key = "hongyver";
	let tcp = easytcp::tcp_aes_cbc::listen(&ip.to_string(), port, key)?;

	return Ok(tcp)
}

pub fn receive_file(ip: &IpAddr, port: &String) -> std::io::Result<()> {

	println!("Start remote sign server : {:?}", ip);

	loop {
		
		println!("Waiting.....");

		// receive header : type, ip, file name
		let tcp = get_tcp_listen(&ip, &port)?;

		println!("Receiving.....");
		let sign_type_data = tcp.recive()?;
		let sign_type: u8 = sign_type_data[0].try_into().unwrap();
		match sign_type {
			1 => println!(" + sign_type : EV"),
			_ => println!(" + sign_type : ETC"),
		}

		let client_ip_data = tcp.recive()?;
	    let client_ip = match str::from_utf8(&client_ip_data) {
			Ok(v) => v,
			Err(e) => panic!(" + Invalid UTF-8 sequence: {}", e),
		};
		println!(" + client_ip : {}", client_ip);

		let file_name_data = tcp.recive()?;
	    let file_name = match str::from_utf8(&file_name_data) {
			Ok(v) => v, 
			Err(e) => panic!(" + Invalid UTF-8 sequence: {}", e),
		};

		let now: DateTime<Tz> = Utc::now().with_timezone(&Seoul);
		let sign_file_name = "./bin/".to_owned() + client_ip + "_" + &now.format("%Y_%m%d_%H%M%S_%f").to_string() + "_" + file_name;
		println!(" + file_name : {}", sign_file_name);

		// recevie file
		let package_len = tcp.recive()?;
		let package_len_bytes: [u8; 8] = package_len[0..8].try_into().unwrap();
		let n = u64::from_be_bytes(package_len_bytes);
	
		let mut f = File::create(&sign_file_name)?;
		let mut pkglen = n;
	
		loop {
			if pkglen == 0 {
					break;
			}
			let data = tcp.recive()?;
			let datalen: u64 = data.len().try_into().unwrap();
			pkglen = pkglen - datalen;
			f.write_all(&data)?;
		}
		f.sync_data()?;
		drop(f);
		
		// do sign
		println!("");
		println!("Try to sign!");
		let output = if cfg!(target_os = "windows") {
			Command::new("cmd")
				.args(["/C", ".\\sign\\signtool"])
				.args(["sign", "/debug", "/a", "/v", "/ph", "/as"])
				.args(["/d", "nProtect Online Security V1.0", "/du", "http://www.nProtect.com", "/fd", "sha256"])
				.args(["/s", "My", "/n", "INCA Internet Co.,Ltd.", "/td", "sha256"])
				.args(["/tr", "http://timestamp.digicert.com"])
				.arg(&sign_file_name)
				//.arg("./bin/1.exe")
				.output()
				.expect("failed to execute process")		
		} else {
			// not support
			Command::new("sh")
				.arg("-c")
				.arg("echo not support")
				.output()
				.expect("failed to execute process")
		};

		if output.status.success() {
	
			// send file
			println!("Success and send a file to client.");
			let file = File::open(&sign_file_name)?;
			let file_length: u64 = file.metadata().unwrap().len();
			let mut br = BufReader::with_capacity(4096, file);
		
			tcp.send(file_length.to_be_bytes().to_vec())?;
			let mut progress: usize = 0;
		
			loop {
				progressbar(progress, file_length.try_into().unwrap());
				let buffer = br.fill_buf()?;
				let bufferlen = buffer.len();
				if bufferlen == 0 {
						break;
				}
				tcp.send(buffer.to_vec())?;
				br.consume(bufferlen);
				progress = progress + 4096;

			}
		} else {
			println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
		}
		println!("");
	}

	return Ok(());
}