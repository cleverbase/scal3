use alloc::collections::BTreeMap;
use alloc::boxed::Box;
use spin::Mutex;
use crate::domain::Authentication;
use spin::Once;

static CONTEXTS: Once<Mutex<BTreeMap<u64, Box<Authentication>>>> = Once::new();
static NEXT_ID: Once<Mutex<u64>> = Once::new();

fn get_contexts() -> &'static Mutex<BTreeMap<u64, Box<Authentication>>> {
    CONTEXTS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn get_next_id() -> &'static Mutex<u64> {
    NEXT_ID.call_once(|| Mutex::new(1))
}

pub fn insert_authentication(authentication: Authentication) -> u64 {
    let mut authentications = get_contexts().lock();
    let mut next = get_next_id().lock();
    let id = *next;
    *next += 1;
    authentications.insert(id, Box::new(authentication));
    id
}

pub fn get_authentication(id: u64) -> Option<Box<Authentication>> {
    get_contexts().lock().remove(&id)
}
