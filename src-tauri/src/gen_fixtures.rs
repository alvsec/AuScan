//! Sustitución de direcciones para producir fixtures sintéticos a partir
//! de una captura real. Función pura: sin ella no hay manera de testear
//! la sustitución sin escribir ficheros reales de por medio.
//!
//! IPv6 queda fuera a propósito — mismo alcance que el adaptador de
//! nmap en esta fase.

use std::collections::HashMap;

use regex::Regex;

fn patron_ipv4() -> Regex {
    Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("patrón ipv4 inválido")
}

fn patron_mac() -> Regex {
    Regex::new(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b").expect("patrón mac inválido")
}

/// Sustituye toda dirección IPv4 o MAC de `texto` según `tabla`. Si
/// encuentra alguna que la tabla no cubre, no sustituye nada: devuelve
/// la lista completa de direcciones sin mapear, para que el operador
/// las añada antes de volver a intentarlo.
pub fn reescribir(texto: &str, tabla: &HashMap<String, String>) -> Result<String, Vec<String>> {
    let re_ip = patron_ipv4();
    let re_mac = patron_mac();

    let mut sin_mapear = Vec::new();
    for m in re_ip.find_iter(texto) {
        if !tabla.contains_key(m.as_str()) {
            sin_mapear.push(m.as_str().to_string());
        }
    }
    for m in re_mac.find_iter(texto) {
        if !tabla.contains_key(m.as_str()) {
            sin_mapear.push(m.as_str().to_string());
        }
    }
    if !sin_mapear.is_empty() {
        sin_mapear.sort();
        sin_mapear.dedup();
        return Err(sin_mapear);
    }

    let intermedio = re_ip.replace_all(texto, |c: &regex::Captures| {
        tabla
            .get(&c[0])
            .cloned()
            .expect("ya verificado que toda dirección está mapeada")
    });
    let final_ = re_mac.replace_all(&intermedio, |c: &regex::Captures| {
        tabla
            .get(&c[0])
            .cloned()
            .expect("ya verificado que toda dirección está mapeada")
    });
    Ok(final_.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustituye_todas_las_apariciones_de_una_ip_mapeada() {
        let texto = "addr=\"203.0.113.9\" otro=\"203.0.113.9\"";
        let mut tabla = HashMap::new();
        tabla.insert("203.0.113.9".to_string(), "198.51.100.20".to_string());
        let resultado = reescribir(texto, &tabla).unwrap();
        assert_eq!(resultado, "addr=\"198.51.100.20\" otro=\"198.51.100.20\"");
    }

    #[test]
    fn sustituye_una_mac_mapeada() {
        let texto = "vendor addr=\"02:aa:bb:cc:dd:01\"";
        let mut tabla = HashMap::new();
        tabla.insert(
            "02:aa:bb:cc:dd:01".to_string(),
            "0a:11:22:33:44:01".to_string(),
        );
        let resultado = reescribir(texto, &tabla).unwrap();
        assert_eq!(resultado, "vendor addr=\"0a:11:22:33:44:01\"");
    }

    #[test]
    fn falla_y_lista_las_direcciones_sin_mapear_sin_tocar_nada() {
        let texto = "203.0.113.9 y 203.0.113.10";
        let mut tabla = HashMap::new();
        tabla.insert("203.0.113.9".to_string(), "198.51.100.20".to_string());
        let err = reescribir(texto, &tabla).unwrap_err();
        assert_eq!(err, vec!["203.0.113.10".to_string()]);
    }

    #[test]
    fn el_texto_sin_direcciones_pasa_intacto() {
        let texto = "<hostnames><hostname name=\"host.example\"/></hostnames>";
        let tabla = HashMap::new();
        assert_eq!(reescribir(texto, &tabla).unwrap(), texto);
    }
}
