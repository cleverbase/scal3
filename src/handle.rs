use std::collections::HashMap;
use std::sync::Mutex;
use crate::domain::Authentication;
use once_cell::sync::Lazy;

static CONTEXTS: Lazy<Mutex<HashMap<u64, Box<Authentication>>>> = Lazy::new(Default::default);
static NEXT_ID: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

pub fn insert_authentication(authentication: Authentication) -> u64 {
    let mut authentications = CONTEXTS.lock().unwrap();
    let mut next = NEXT_ID.lock().unwrap();
    let id = *next;
    *next += 1;
    authentications.insert(id, Box::new(authentication));
    id
}

pub fn get_authentication(id: u64) -> Option<Box<Authentication>> {
    CONTEXTS.lock().unwrap().remove(&id)
}
