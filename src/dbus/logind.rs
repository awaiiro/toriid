//! logind's PrepareForSleep signal: the daemon learns about resume itself instead of relying only on a
//! marker dropped by the system-sleep hook. The hook stays (it works even when the daemon is not up);
//! either one counts.
use futures::StreamExt;
use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
    #[zbus(property)]
    fn preparing_for_sleep(&self) -> zbus::Result<bool>;
}

/// Emits one `()` per resume.
pub async fn resume_events() -> anyhow::Result<tokio::sync::mpsc::UnboundedReceiver<()>> {
    let c = super::system().await?;
    let p = ManagerProxy::new(&c).await?;
    let mut s = p.receive_prepare_for_sleep().await?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(sig) = s.next().await {
            if let Ok(a) = sig.args() {
                if !a.start && tx.send(()).is_err() {
                    break;
                }
            }
        }
    });
    Ok(rx)
}
