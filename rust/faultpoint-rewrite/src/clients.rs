use std::path::Path;

use syn::{Expr, ImplItem, Item, parse_quote};

/// Reqwest has no global request-and-result hook; its instrumented dependency copy keeps Pending's public type.
pub fn rewrite_reqwest(copy: &Path) {
    let path = copy.join("src/async_impl/client.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read reqwest client"))
        .expect("cannot parse reqwest client");
    let mut changed = 0;
    for item in &mut syntax.items {
        match item {
            Item::Impl(implementation) => {
                let owner = &implementation.self_ty;
                if owner == &parse_quote!(Client) && implementation.trait_.is_none() {
                    let method = implementation.items.iter_mut().find_map(|item| match item {
                        ImplItem::Fn(method) if method.sig.ident == "execute_request" => Some(method),
                        _ => None,
                    });
                    if let Some(method) = method {
                        let mut original = method.clone();
                        original.sig.ident = syn::Ident::new("faultpoint_execute_request", original.sig.ident.span());
                        method.block = parse_quote!({
                            if !::faultpoint::core().enabled {
                                return self.faultpoint_execute_request(req);
                            }
                            let url = req.url().clone();
                            let authority = match url.port() {
                                Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
                                None => url.host_str().unwrap_or_default().to_owned(),
                            };
                            let locator = ::faultpoint::client::locator(req.method().as_str(), &authority, url.path());
                            let context = ::faultpoint::client::context(req.headers());
                            let deadline = [self.inner.total_timeout.fetch(req.extensions()).copied(), self.inner.read_timeout]
                                .into_iter().flatten().min().map(|duration| ::faultpoint::client::Deadline {
                                    duration, failure: || crate::error::request(crate::error::TimedOut),
                                });
                            let client = self.clone();
                            let operation = async move { client.faultpoint_execute_request(req).await };
                            Pending {
                                inner: PendingInner::Faultpoint(Box::pin(::faultpoint::client::call(
                                    locator, context, operation,
                                    move |rule| {
                                        if rule.action.parameters.contains_key("code") {
                                            ::faultpoint::core().abort(&format!("rule {}: HTTP failures use status, not code", rule.id));
                                        }
                                        if let Some(error) = rule.text("error") {
                                            if rule.action.parameters.contains_key("status") {
                                                ::faultpoint::core().abort(&format!("rule {}: an HTTP failure names either status or error", rule.id));
                                            }
                                            return Err(match error {
                                                "timeout" => crate::error::request(crate::error::TimedOut),
                                                "refused" => crate::error::request(::std::io::Error::new(
                                                    ::std::io::ErrorKind::ConnectionRefused, "faultpoint: injected connection refusal")),
                                                other => ::faultpoint::core().abort(&format!("rule {}: unsupported HTTP error {other}", rule.id)),
                                            }.with_url(url.clone()));
                                        }
                                        let status = rule.action.parameters.get("status").map_or(
                                            ::faultpoint::client::DEFAULT_HTTP_FAILURE_STATUS,
                                            |value| value.as_u64().and_then(|value| u16::try_from(value).ok())
                                                .unwrap_or_else(|| ::faultpoint::core().abort("HTTP status must be an integer")));
                                        let mut response = http::Response::builder().status(status).body(Body::empty())
                                            .unwrap_or_else(|error| ::faultpoint::core().abort(&error.to_string()));
                                        response.extensions_mut().insert(crate::response::ResponseUrl(url.clone()));
                                        Ok(Response::from(response))
                                    },
                                    |result| {
                                        let mut detail = ::faultpoint::core::Detail::new();
                                        let (outcome, successful) = match result {
                                            Ok(response) => {
                                                detail.insert("status", response.status().as_u16().to_string());
                                                detail.insert("sent", "true".into());
                                                (format!("{}xx", response.status().as_u16() / 100),
                                                 response.status().is_success() || response.status().is_redirection())
                                            }
                                            Err(error) => {
                                                let mut source = ::std::error::Error::source(error);
                                                let mut refused = false;
                                                while let Some(error) = source {
                                                    refused |= error.downcast_ref::<::std::io::Error>()
                                                        .is_some_and(|error| error.kind() == ::std::io::ErrorKind::ConnectionRefused);
                                                    source = error.source();
                                                }
                                                detail.insert("error", if error.is_timeout() { "timeout" } else if refused { "refused" }
                                                    else { ::std::any::type_name::<crate::Error>() }.into());
                                                if refused { detail.insert("sent", "false".into()); }
                                                (if error.is_timeout() { "timeout" } else if refused { "refused" } else { "error" }.into(), false)
                                            }
                                        };
                                        ::faultpoint::client::Completion { outcome, detail, successful }
                                    },
                                    deadline,
                                ))),
                            }
                        });
                        implementation.items.push(ImplItem::Fn(original));
                        changed += 1;
                    }
                } else if owner == &parse_quote!(Pending) {
                    for item in &mut implementation.items {
                        if let ImplItem::Fn(method) = item {
                            if let Some(syn::Stmt::Expr(Expr::Match(result), None)) = method.block.stmts.last_mut() {
                                match method.sig.ident.to_string().as_str() {
                                    "poll" => {
                                        result.arms.push(parse_quote!(PendingInner::Faultpoint(future) => future.as_mut().poll(cx)));
                                        changed += 1;
                                    }
                                    "fmt" => {
                                        result.arms.push(parse_quote!(PendingInner::Faultpoint(_) => f.debug_struct("Pending").finish_non_exhaustive()));
                                        changed += 1;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Item::Enum(choices) if choices.ident == "PendingInner" => {
                choices.variants.push(parse_quote!(Faultpoint(
                    Pin<Box<dyn Future<Output = Result<Response, crate::Error>> + Send>>
                )));
                changed += 1;
            }
            _ => {}
        }
    }
    if changed != 4 {
        panic!("reqwest's client layout is unsupported: rewrote {changed} of 4 boundaries");
    }
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write reqwest client");
}

/// Tonic's interceptor sees only a request; the unary boundary must also see the decoded response and Status.
pub fn rewrite_tonic(copy: &Path) {
    let path = copy.join("src/client/grpc.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic client"))
        .expect("cannot parse tonic client");
    let mut changed = 0;
    for item in &mut syntax.items {
        if let Item::Impl(implementation) = item && implementation.self_ty.as_ref() == &parse_quote!(Grpc<T>) {
            for item in &mut implementation.items {
                if let ImplItem::Fn(method) = item && method.sig.ident == "unary" {
                    let original = method.block.clone();
                    method.block = parse_quote!({
                        if !::faultpoint::core().enabled {
                            return (async move #original).await;
                        }
                        let locator = ::faultpoint::client::locator("gRPC",
                            self.config.origin.authority().map_or("", |authority| authority.as_str()), path.path());
                        let headers = request.metadata().clone().into_headers();
                        let context = ::faultpoint::client::context(&headers);
                        #[cfg(any(feature = "server", feature = "channel"))]
                        let deadline = crate::transport::try_parse_grpc_timeout(&headers).unwrap_or_else(|invalid| {
                            // Tonic's native transport ignores malformed timeout metadata.
                            tracing::trace!("Error parsing `grpc-timeout` header {:?}", invalid);
                            None
                        }).map(|duration| ::faultpoint::client::Deadline {
                            duration, failure: || Status::from_error(Box::new(crate::TimeoutExpired(()))),
                        });
                        #[cfg(not(any(feature = "server", feature = "channel")))]
                        let deadline = None;
                        ::faultpoint::client::call(locator, context, async move #original,
                            |rule| {
                                if rule.action.parameters.contains_key("status") || rule.action.parameters.contains_key("error") {
                                    ::faultpoint::core().abort(&format!("rule {}: a gRPC failure names its native code", rule.id));
                                }
                                let code = rule.text("code").map_or(::faultpoint::client::DEFAULT_GRPC_FAILURE_CODE, |code| {
                                    code.parse::<i32>().ok().filter(|code| (1..=16).contains(code))
                                        .unwrap_or_else(|| ::faultpoint::core().abort(&format!("rule {}: gRPC code must be from 1 to 16", rule.id)))
                                });
                                Err(Status::new(Code::from_i32(code), "faultpoint: injected gRPC failure"))
                            },
                            |result| {
                                let detail = match result {
                                    Ok(_) => ::faultpoint::core::Detail::from([("code", "0".into()), ("sent", "true".into())]),
                                    Err(status) => ::faultpoint::core::Detail::from([
                                        ("code", (status.code() as i32).to_string()), ("error", format!("{:?}", status.code()))]),
                                };
                                ::faultpoint::client::Completion {
                                    outcome: if result.is_ok() { "2xx" } else { "error" }.into(), detail, successful: result.is_ok(),
                                }
                            },
                            deadline,
                        ).await
                    });
                    changed += 1;
                }
            }
        }
    }
    if changed != 1 {
        panic!("tonic's client layout is unsupported: rewrote {changed} of 1 unary boundary");
    }
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic client");
    expose_tonic_deadline(copy);
}

/// Reuse the transport's timeout parser within the same instrumented crate.
pub fn expose_tonic_deadline(copy: &Path) {
    let path = copy.join("src/transport/service/grpc_timeout.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic timeout"))
        .expect("cannot parse tonic timeout");
    let mut changed = 0;
    for item in &mut syntax.items {
        if let Item::Fn(parser) = item && parser.sig.ident == "try_parse_grpc_timeout" {
            parser.vis = parse_quote!(pub(crate));
            changed += 1;
        }
    }
    if changed != 1 {
        panic!("tonic's timeout layout is unsupported: found {changed} of 1 parser");
    }
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic timeout");
    let path = copy.join("src/transport/mod.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic transport"))
        .expect("cannot parse tonic transport");
    syntax.items.push(parse_quote!(pub(crate) use service::grpc_timeout::try_parse_grpc_timeout;));
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic transport");
}
