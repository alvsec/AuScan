//! Punto de entrada del binario de test `parsers`.
//!
//! Cargo descubre binarios de test en `tests/*.rs` (un nivel, no
//! recursivo) o en `tests/<nombre>/main.rs` cuando el binario se
//! reparte en varios ficheros. Este directorio usa la segunda forma:
//! un fichero por adaptador declarado aquí como módulo.
mod nmap_discovery;
mod nmap_portsweep;
