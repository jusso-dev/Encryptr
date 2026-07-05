//! Data access layer. Each repository owns the SQL for one aggregate and
//! exposes typed methods to the service layer. SQLx binds every parameter, so
//! all statements are prepared and injection-safe.

pub mod audit;
pub mod conversations;
pub mod keys;
pub mod messages;
pub mod sessions;
pub mod users;
