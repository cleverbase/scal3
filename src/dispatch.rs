use crate::api::{
    Acceptance, AuthenticateRequest, ChallengeRequest, PassRequest, ProveRequest, ProviderState,
    SubscriberState, Verification, VerifyRequest,
};
use crate::handle::get_authentication;
use crate::{Error, ErrorResponse, Response};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Request {
    Register(SubscriberState),
    Accept(ProviderState),
    Challenge(ChallengeRequest),
    Authenticate(AuthenticateRequest),
    Pass(PassRequest),
    Prove(ProveRequest),
    Verify(VerifyRequest),
}

pub(crate) fn dispatch(input: &[u8]) -> Vec<u8> {
    let response = match minicbor_serde::from_slice::<Request>(input) {
        Err(_) => Response::Error(ErrorResponse {
            error: Error::BadRequest,
        }),
        Ok(Request::Register(args)) => match args.handle() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(Some(registration)) => Response::Register(Some(registration)),
            Some(None) => Response::Error(ErrorResponse {
                error: Error::InvalidInput,
            }),
        },
        Ok(Request::Accept(args)) => match args.handle() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(Ok(())) => Response::Accept(Acceptance::Accepted),
            Some(Err(_)) => Response::Accept(Acceptance::Rejected),
        },
        Ok(Request::Authenticate(args)) => match args.handle2() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(response) => Response::Authenticate(response),
        },
        Ok(Request::Challenge(args)) => match args.handle() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(c) => Response::Challenge(crate::api::ChallengeResponse::challenge(c)),
        },
        Ok(Request::Pass(args)) => match args.authentication {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(id) => match get_authentication(id) {
                None => Response::Error(ErrorResponse {
                    error: Error::InvalidInput,
                }),
                Some(authentication) => match args.handle(*authentication) {
                    None => Response::Error(ErrorResponse {
                        error: Error::InvalidInput,
                    }),
                    Some(Some((k, p))) => Response::Pass(crate::api::Attempt {
                        sender: Some(k),
                        pass: Some(p),
                    }),
                    Some(None) => Response::Error(ErrorResponse {
                        error: Error::InvalidInput,
                    }),
                },
            },
        },
        Ok(Request::Prove(args)) => match args.handle() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(Some((a, p, c))) => Response::Prove(Some(crate::api::Transcript {
                authenticator: Some(a),
                proof: Some(p),
                client: Some(c),
            })),
            Some(None) => Response::Prove(None),
        },
        Ok(Request::Verify(args)) => match args.handle() {
            None => Response::Error(ErrorResponse {
                error: Error::MissingValue,
            }),
            Some(Ok(())) => Response::Verify(Verification::Verified),
            Some(Err(_)) => Response::Verify(Verification::Rejected),
        },
    };
    minicbor_serde::to_vec(&response).expect("failed to serialize response")
}
