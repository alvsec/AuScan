//! Reescribe direcciones IPv4 y MAC de un fichero de entrada según una
//! tabla de sustitución explícita, y las escribe por stdout. Falla si
//! encuentra alguna dirección que la tabla no cubre: es preferible que
//! el operador la añada a mano a que se cuele sin que nadie la vea en
//! un fixture commiteado.
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::ExitCode;

use auscan_lib::gen_fixtures::reescribir;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let [_, entrada, tabla] = args.as_slice() else {
        eprintln!("uso: gen-fixtures <entrada> <tabla.json>");
        return ExitCode::FAILURE;
    };

    let texto = match fs::read_to_string(entrada) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer {entrada}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tabla_json = match fs::read_to_string(tabla) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer {tabla}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sustituciones: HashMap<String, String> = match serde_json::from_str(&tabla_json) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("tabla de sustitución inválida: {e}");
            return ExitCode::FAILURE;
        }
    };

    match reescribir(&texto, &sustituciones) {
        Ok(salida) => {
            print!("{salida}");
            ExitCode::SUCCESS
        }
        Err(sin_mapear) => {
            eprintln!("direcciones sin mapear en la tabla de sustitución:");
            for a in sin_mapear {
                eprintln!("  {a}");
            }
            ExitCode::FAILURE
        }
    }
}
