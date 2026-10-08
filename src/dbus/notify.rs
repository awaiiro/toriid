//! Desktop notifications (user session bus). Used by the user-side notifier, not by the daemon.
use std::collections::HashMap;
use zbus::proxy;
use zbus::zvariant::Value;

#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<&str>,
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
    fn close_notification(&self, id: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;
}

/// Returns Ok only if delivered; callers use this to decide whether to record the dedup timestamp.
/// An undelivered warning was never sent.
pub async fn send(conn: &zbus::Connection, body: &str, critical: bool) -> anyhow::Result<u32> {
    show(conn, 0, "Network", body, critical).await
}

/// A titled, replaceable card. Non-zero `replaces` = replace that card in place (updates on the same
/// matter do not stack a new card). expire is always 0: some notification daemons ignore it (they pick
/// the popup duration and keep the card in the center), so the caller withdraws it with close().
pub async fn show(conn: &zbus::Connection, replaces: u32, summary: &str, body: &str, critical: bool) -> anyhow::Result<u32> {
    show_with(conn, replaces, summary, body, critical, &[]).await
}

/// With buttons: actions = [(key, label)]. A click yields ActionInvoked(id, key); see actions()
pub async fn show_with(conn: &zbus::Connection, replaces: u32, summary: &str, body: &str, critical: bool, actions: &[(&str, &str)]) -> anyhow::Result<u32> {
    let p = NotificationsProxy::new(conn).await?;
    let mut hints = HashMap::new();
    hints.insert("urgency", Value::U8(if critical { 2 } else { 1 }));
    let flat: Vec<&str> = actions.iter().flat_map(|(k, t)| [*k, *t]).collect();
    Ok(p.notify("net", replaces, "network-wireless", summary, body, flat, hints, 0).await?)
}

/// Stream of button clicks: (notification id, action key)
pub async fn actions(conn: &zbus::Connection) -> anyhow::Result<impl futures::Stream<Item = (u32, String)>> {
    use futures::StreamExt;
    let p = NotificationsProxy::new(conn).await?;
    let s = p.receive_action_invoked().await?;
    Ok(s.filter_map(|sig| async move { sig.args().ok().map(|a| (a.id, a.action_key)) }))
}

pub async fn close(conn: &zbus::Connection, id: u32) {
    if id == 0 {
        return;
    }
    if let Ok(p) = NotificationsProxy::new(conn).await {
        let _ = p.close_notification(id).await;
    }
}
