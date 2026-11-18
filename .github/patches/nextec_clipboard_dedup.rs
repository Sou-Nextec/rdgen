// Nextec: elimina as regravações repetidas da área de transferência do Windows no cliente RustDesk.
//
// Problema: com a sincronização de área de transferência ligada, cada cópia local gera de 3 a 5 mensagens
// "clipboard updated on client" (o host devolve o conteúdo que acabou de receber e o cliente regrava cada
// uma), e cada regravação vira uma entrada nova no histórico do Windows (Win+V).
//
// Solução: lembrar uma assinatura do conteúdo (hash) do último conteúdo APLICADO (gravado vindo do host) e do
// último ENVIADO (lido localmente e mandado ao host). Se o host devolve algo com a mesma assinatura dentro de
// 60 s, a gravação é ignorada.
//
// Este arquivo só usa `std`: o CI roda `rustc --test` nele sem compilar o RustDesk. O arquivo vai para
// `src/nextec_clipboard_dedup.rs` do RustDesk e é ligado por `.github/patches/clipboardDedup.diff`.
#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Janela em que um conteúdo repetido é tratado como eco.
pub const JANELA: Duration = Duration::from_secs(60);

/// Assinatura de um conjunto de itens da área de transferência. Não depende da ordem dos itens e ignora os
/// itens com nome especial (marcadores internos como `dyn.com.rustdesk.owner`, que mudam a cada gravação).
pub struct Assinatura {
    soma: u64,
    itens: usize,
}

impl Assinatura {
    pub fn novo() -> Self {
        Assinatura { soma: 0, itens: 0 }
    }

    /// Soma um item. `nome_especial` não vazio significa item especial: é ignorado.
    pub fn item(
        &mut self,
        formato: i32,
        comprimido: bool,
        largura: i32,
        altura: i32,
        nome_especial: &str,
        conteudo: &[u8],
    ) {
        if !nome_especial.is_empty() {
            return;
        }
        let mut h = DefaultHasher::new();
        formato.hash(&mut h);
        comprimido.hash(&mut h);
        largura.hash(&mut h);
        altura.hash(&mut h);
        conteudo.len().hash(&mut h);
        h.write(conteudo);
        // Soma (e não encadeia) para a ordem dos itens não mudar o resultado.
        self.soma = self.soma.wrapping_add(h.finish());
        self.itens += 1;
    }

    /// `None` quando não sobrou nenhum item comparável (só itens especiais): nesse caso não se deduplica.
    pub fn fim(self) -> Option<u64> {
        if self.itens == 0 {
            return None;
        }
        let mut h = DefaultHasher::new();
        self.soma.hash(&mut h);
        self.itens.hash(&mut h);
        Some(h.finish())
    }
}

struct Estado {
    aplicado: Option<(u64, Instant)>,
    enviado: Option<(u64, Instant)>,
}

fn recente(marca: Option<(u64, Instant)>, sig: u64, agora: Instant) -> bool {
    match marca {
        Some((s, quando)) => s == sig && agora.saturating_duration_since(quando) < JANELA,
        None => false,
    }
}

impl Estado {
    const fn novo() -> Self {
        Estado {
            aplicado: None,
            enviado: None,
        }
    }

    /// Verdadeiro quando o conteúdo deve ser gravado. Ao devolver verdadeiro já registra o conteúdo como
    /// aplicado (a checagem e o registro são atômicos porque as gravações rodam em threads separadas).
    fn deve_aplicar(&mut self, sig: u64, agora: Instant) -> bool {
        if recente(self.enviado, sig, agora) || recente(self.aplicado, sig, agora) {
            return false;
        }
        self.aplicado = Some((sig, agora));
        // A área de transferência local passa a ter este conteúdo: o último enviado deixou de valer.
        self.enviado = None;
        true
    }

    fn enviado(&mut self, sig: u64, agora: Instant) {
        self.enviado = Some((sig, agora));
        // Se o conteúdo local mudou para algo diferente do que foi aplicado, o aplicado deixou de valer
        // (senão o host copiar de novo aquele conteúdo seria ignorado sem a área local tê-lo).
        if let Some((s, _)) = self.aplicado {
            if s != sig {
                self.aplicado = None;
            }
        }
    }
}

static ESTADO: Mutex<Estado> = Mutex::new(Estado::novo());

fn estado() -> std::sync::MutexGuard<'static, Estado> {
    // Mutex envenenado não pode derrubar a área de transferência: o estado é só um par de marcas.
    ESTADO.lock().unwrap_or_else(|e| e.into_inner())
}

/// Chamar antes de gravar no Windows o que veio do host. Falso: é eco, não gravar.
pub fn deve_aplicar(sig: u64) -> bool {
    estado().deve_aplicar(sig, Instant::now())
}

/// Chamar quando o conteúdo local foi lido para ser enviado ao host.
pub fn enviado(sig: u64) {
    estado().enviado(sig, Instant::now())
}

#[cfg(test)]
mod testes {
    use super::*;

    fn sig_texto(t: &str) -> u64 {
        let mut a = Assinatura::novo();
        a.item(0, false, 0, 0, "", t.as_bytes());
        a.fim().unwrap()
    }

    #[test]
    fn assinatura_igual_para_mesmo_conteudo_e_diferente_para_outro() {
        assert_eq!(sig_texto("abc"), sig_texto("abc"));
        assert_ne!(sig_texto("abc"), sig_texto("abd"));
    }

    #[test]
    fn assinatura_considera_formato_compressao_e_dimensoes() {
        let f = |formato, comp, w, h| {
            let mut a = Assinatura::novo();
            a.item(formato, comp, w, h, "", &[1, 2, 3, 4]);
            a.fim().unwrap()
        };
        let base = f(3, false, 1, 1);
        assert_ne!(base, f(4, false, 1, 1));
        assert_ne!(base, f(3, true, 1, 1));
        assert_ne!(base, f(3, false, 2, 1));
        assert_ne!(base, f(3, false, 1, 2));
    }

    #[test]
    fn assinatura_ignora_itens_especiais_e_a_ordem() {
        let mut a = Assinatura::novo();
        a.item(0, false, 0, 0, "", b"texto");
        a.item(5, false, 0, 0, "dyn.com.rustdesk.owner", &[0b01]);
        a.item(1, false, 0, 0, "", b"<b>texto</b>");
        let mut b = Assinatura::novo();
        b.item(1, false, 0, 0, "", b"<b>texto</b>");
        b.item(5, false, 0, 0, "dyn.com.rustdesk.owner", &[0b10]);
        b.item(5, false, 0, 0, "XML Spreadsheet", b"qualquer coisa");
        b.item(0, false, 0, 0, "", b"texto");
        assert_eq!(a.fim(), b.fim());
    }

    #[test]
    fn so_itens_especiais_nao_tem_assinatura() {
        let mut a = Assinatura::novo();
        a.item(5, false, 0, 0, "dyn.com.rustdesk.owner", &[1]);
        assert_eq!(a.fim(), None);
        assert_eq!(Assinatura::novo().fim(), None);
    }

    #[test]
    fn conteudo_novo_e_aplicado_e_repetido_dentro_da_janela_e_ignorado() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("x");
        assert!(e.deve_aplicar(x, t0));
        assert!(!e.deve_aplicar(x, t0 + Duration::from_secs(1)));
        assert!(!e.deve_aplicar(x, t0 + Duration::from_secs(59)));
        // Fora da janela volta a gravar.
        assert!(e.deve_aplicar(x, t0 + Duration::from_secs(61)));
        // Conteúdo diferente sempre grava.
        assert!(e.deve_aplicar(sig_texto("y"), t0 + Duration::from_secs(62)));
    }

    // Regressão do defeito: cada cópia local virava 3 a 5 gravações do eco devolvido pelo host.
    #[test]
    fn eco_do_que_foi_enviado_ao_host_nao_e_gravado() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("print do cliente");
        e.enviado(x, t0);
        let gravacoes = (1..=5u64)
            .filter(|i| e.deve_aplicar(x, t0 + Duration::from_millis(300 * i)))
            .count();
        assert_eq!(gravacoes, 0, "o eco do conteúdo enviado não pode ser regravado");
        // Passada a janela, o mesmo conteúdo vindo do host volta a ser aceito.
        assert!(e.deve_aplicar(x, t0 + JANELA + Duration::from_secs(1)));
    }

    #[test]
    fn varios_ecos_do_conteudo_aplicado_geram_uma_gravacao_so() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let y = sig_texto("copiado no host");
        let gravacoes = (0..5u64)
            .filter(|i| e.deve_aplicar(y, t0 + Duration::from_millis(200 * i)))
            .count();
        assert_eq!(gravacoes, 1);
    }

    #[test]
    fn aplicar_esquece_o_ultimo_enviado() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("x");
        let y = sig_texto("y");
        e.enviado(x, t0);
        assert!(e.deve_aplicar(y, t0 + Duration::from_secs(1)));
        // A área local agora tem y: o host copiar x de novo precisa ser gravado.
        assert!(e.deve_aplicar(x, t0 + Duration::from_secs(2)));
    }

    #[test]
    fn enviar_algo_diferente_esquece_o_ultimo_aplicado() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("x");
        let y = sig_texto("y");
        assert!(e.deve_aplicar(x, t0));
        e.enviado(y, t0 + Duration::from_secs(1));
        // A área local agora tem y: o host copiar x de novo precisa ser gravado.
        assert!(e.deve_aplicar(x, t0 + Duration::from_secs(2)));
    }

    #[test]
    fn reler_o_proprio_conteudo_aplicado_nao_reabre_o_eco() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("x");
        assert!(e.deve_aplicar(x, t0));
        // O monitor local leu de volta o que acabou de ser gravado e o enviou.
        e.enviado(x, t0 + Duration::from_millis(100));
        assert!(!e.deve_aplicar(x, t0 + Duration::from_millis(500)));
    }

    #[test]
    fn instante_anterior_ao_registro_nao_estoura() {
        let t0 = Instant::now();
        let mut e = Estado::novo();
        let x = sig_texto("x");
        e.enviado(x, t0 + Duration::from_secs(5));
        assert!(!e.deve_aplicar(x, t0));
    }

    #[test]
    fn funcoes_publicas_usam_o_estado_global() {
        // Único teste que mexe no estado global (os outros usam Estado local): assinaturas exclusivas.
        let x = sig_texto("global-unico-1");
        let y = sig_texto("global-unico-2");
        enviado(x);
        assert!(!deve_aplicar(x));
        assert!(deve_aplicar(y));
        assert!(!deve_aplicar(y));
    }
}
