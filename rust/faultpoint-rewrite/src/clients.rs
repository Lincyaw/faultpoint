use std::path::Path;

use syn::{Expr, ImplItem, Item, parse_quote};
use syn::visit_mut::{self, VisitMut};

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
                                    ::faultpoint::client::Deadlines { request: deadline, transport: None },
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
    let failure: Expr = parse_quote!(|rule| Err(Status::new(Code::from_i32(
        ::faultpoint::client::grpc_failure_code(rule)), "faultpoint: injected gRPC failure")));
    let classify: Expr = parse_quote!(|result| {
        let detail = match result {
            Ok(_) => ::faultpoint::core::Detail::from([("code", "0".into()), ("sent", "true".into())]),
            Err(status) => ::faultpoint::core::Detail::from([
                ("code", (status.code() as i32).to_string()), ("error", format!("{:?}", status.code()))]),
        };
        ::faultpoint::client::Completion {
            outcome: if result.is_ok() { "2xx" } else { "error" }.into(), detail, successful: result.is_ok(),
        }
    });
    let path = copy.join("src/client/grpc.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic client"))
        .expect("cannot parse tonic client");
    let mut changed = 0;
    for item in &mut syntax.items {
        if let Item::Struct(config) = item && config.ident == "GrpcConfig" {
            let syn::Fields::Named(fields) = &mut config.fields else { panic!("tonic GrpcConfig has named fields"); };
            fields.named.push(parse_quote!(faultpoint_channel: Option<::faultpoint::client::ChannelMetadata>));
            changed += 1;
        }
        if let Item::Impl(implementation) = item && implementation.self_ty.as_ref() == &parse_quote!(Grpc<T>) {
            for item in &mut implementation.items {
                if let ImplItem::Fn(method) = item && method.sig.ident == "ready" {
                    let original = method.block.clone();
                    method.block = parse_quote!({
                        if !::faultpoint::core().enabled { return (async #original).await; }
                        let probe = ::faultpoint::client::EndpointProbe::default();
                        let result = probe.capture(async #original).await;
                        self.config.faultpoint_channel = probe.channel();
                        result
                    });
                    changed += 1;
                }
                if let ImplItem::Fn(method) = item && method.sig.ident == "unary" {
                    let original = method.block.clone();
                    method.block = parse_quote!({
                        if !::faultpoint::core().enabled {
                            return (async move #original).await;
                        }
                        let mut request = request;
                        let authority = self.config.origin.authority().or_else(|| self.config.faultpoint_channel.as_ref()
                            .and_then(|channel| channel.uri.as_ref()).and_then(|uri| uri.authority()));
                        let locator = ::faultpoint::client::locator(::faultpoint::client::GRPC_METHOD,
                            authority.map_or("", |authority| authority.as_str()), path.path());
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
                        let direct = self.config.faultpoint_channel.as_ref().map_or(
                            self.config.origin.authority().is_some(), |channel| channel.uri.is_some());
                        if !direct {
                            let call = ::faultpoint::client::DeferredCall::new(locator, context,
                                self.config.origin.authority().map(|authority| authority.as_str().to_owned()));
                            request.extensions_mut().insert(call.transport.clone());
                            return call.call(async move #original, #failure, #classify, deadline).await;
                        }
                        let transport = self.config.faultpoint_channel.as_ref().and_then(|channel| channel.timeout)
                            .map(|duration| ::faultpoint::client::Deadline {
                                duration, failure: || Status::from_error(Box::new(crate::TimeoutExpired(()))),
                            });
                        ::faultpoint::client::call(locator, context, async move #original, #failure, #classify,
                            ::faultpoint::client::Deadlines { request: deadline, transport }).await
                    });
                    changed += 1;
                }
            }
        }
    }
    struct GrpcConstructors(usize);
    impl VisitMut for GrpcConstructors {
        fn visit_expr_struct_mut(&mut self, expression: &mut syn::ExprStruct) {
            if expression.path == parse_quote!(GrpcConfig) {
                expression.fields.push(parse_quote!(faultpoint_channel: None));
                self.0 += 1;
            }
            visit_mut::visit_expr_struct_mut(self, expression);
        }
    }
    let mut constructors = GrpcConstructors(0);
    constructors.visit_file_mut(&mut syntax);
    if changed != 3 || constructors.0 != 2 {
        panic!("tonic's client layout is unsupported: rewrote {changed} of 3 boundaries and {} of 2 constructors", constructors.0);
    }
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic client");
    expose_tonic_deadline(copy);
    rewrite_tonic_channel(copy);
    rewrite_tonic_connection(copy);
}

/// The channel knows a fixed endpoint before buffering; balanced channels defer to the selected connection.
pub fn rewrite_tonic_channel(copy: &Path) {
    let path = copy.join("src/transport/channel/mod.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic channel"))
        .expect("cannot parse tonic channel");
    let mut changed = 0;
    for item in &mut syntax.items {
        match item {
            Item::Struct(channel) if channel.ident == "Channel" => {
                let syn::Fields::Named(fields) = &mut channel.fields else { panic!("tonic Channel has named fields") };
                fields.named.push(parse_quote!(faultpoint_uri: Option<Uri>));
                fields.named.push(parse_quote!(faultpoint_timeout: Option<std::time::Duration>));
                changed += 1;
            }
            Item::Struct(future) if future.ident == "ResponseFuture" => {
                let field = future.fields.iter_mut().find(|field| field.ident.as_ref().is_some_and(|name| name == "inner"))
                    .expect("tonic ResponseFuture has inner");
                field.ty = parse_quote!(FaultpointResponseFuture);
                changed += 1;
            }
            Item::Impl(implementation) => {
                let owner = &implementation.self_ty;
                for item in &mut implementation.items {
                    let ImplItem::Fn(method) = item else { continue };
                    if owner == &parse_quote!(Channel) {
                        match method.sig.ident.to_string().as_str() {
                            "new" | "connect" | "balance" => {
                                let origin: Expr = if method.sig.ident == "balance" { parse_quote!(None) }
                                    else { parse_quote!(Some(endpoint.uri.clone())) };
                                let timeout: Expr = if method.sig.ident == "balance" { parse_quote!(None) }
                                    else { parse_quote!(endpoint.timeout) };
                                method.block.stmts.insert(0, parse_quote!(let faultpoint_uri = #origin;));
                                method.block.stmts.insert(1, parse_quote!(let faultpoint_timeout = #timeout;));
                                let Some(syn::Stmt::Expr(tail, None)) = method.block.stmts.last_mut()
                                    else { panic!("tonic channel constructor has a tail") };
                                let construction = match tail {
                                    Expr::Struct(construction) => construction,
                                    Expr::Call(call) => match call.args.first_mut() {
                                        Some(Expr::Struct(construction)) => construction,
                                        _ => panic!("tonic connect returns a Channel"),
                                    },
                                    _ => panic!("tonic channel constructor returns a Channel"),
                                };
                                construction.fields.push(parse_quote!(faultpoint_uri));
                                construction.fields.push(parse_quote!(faultpoint_timeout));
                                changed += 1;
                            }
                            "call" => {
                                method.block = parse_quote!({
                                    let mut request = request;
                                    if let Some(uri) = &self.faultpoint_uri {
                                        if let Some(call) = request.extensions_mut().remove::<::faultpoint::client::TransportCall>() {
                                        let path = request.uri().path().to_owned();
                                        let future = call.execute(::faultpoint::client::TransportTarget {
                                            uri, path: &path, deadline: self.faultpoint_timeout.map(|duration| ::faultpoint::client::Deadline {
                                                duration, failure: || super::Error::from_source(crate::TimeoutExpired(())),
                                            }),
                                        },
                                            || ResponseFuture { inner: FaultpointResponseFuture::Native(Service::call(&mut self.svc, request)) },
                                            |rule| Ok(crate::Status::new(crate::Code::from_i32(
                                                ::faultpoint::client::grpc_failure_code(rule)), "faultpoint: injected gRPC failure").into_http()));
                                        return ResponseFuture { inner: FaultpointResponseFuture::Call(future) };
                                        }
                                    }
                                    ResponseFuture { inner: FaultpointResponseFuture::Native(Service::call(&mut self.svc, request)) }
                                });
                                changed += 1;
                            }
                            "poll_ready" => {
                                method.block.stmts.insert(0, parse_quote!(::faultpoint::client::EndpointProbe::record(
                                    self.faultpoint_uri.clone(), self.faultpoint_timeout);));
                                changed += 1;
                            }
                            _ => {}
                        }
                    } else if owner == &parse_quote!(ResponseFuture) && method.sig.ident == "poll" {
                        method.block = parse_quote!({
                            match &mut self.inner {
                                FaultpointResponseFuture::Native(inner) => Pin::new(inner).poll(cx).map_err(super::Error::from_source),
                                FaultpointResponseFuture::Call(future) => future.as_mut().poll(cx),
                            }
                        });
                        changed += 1;
                    }
                }
            }
            _ => {}
        }
    }
    if changed != 8 { panic!("tonic channel layout is unsupported: rewrote {changed} of 8 boundaries"); }
    syntax.items.push(parse_quote!(enum FaultpointResponseFuture {
        Native(buffer::future::ResponseFuture<<Svc as Service<Request<BoxBody>>>::Future>),
        Call(BoxFuture<'static, Result<Response<BoxBody>, super::Error>>),
    }));
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic channel");
}

/// A balanced channel learns its destination at the selected connection's tower boundary.
pub fn rewrite_tonic_connection(copy: &Path) {
    let path = copy.join("src/transport/channel/service/connection.rs");
    let mut syntax = syn::parse_file(&std::fs::read_to_string(&path).expect("cannot read tonic connection"))
        .expect("cannot parse tonic connection");
    let mut changed = 0;
    for item in &mut syntax.items {
        match item {
            Item::Struct(connection) if connection.ident == "Connection" => {
                let syn::Fields::Named(fields) = &mut connection.fields else { panic!("tonic Connection has named fields") };
                fields.named.push(parse_quote!(faultpoint_uri: Uri));
                fields.named.push(parse_quote!(faultpoint_timeout: Option<std::time::Duration>));
                changed += 1;
            }
            Item::Impl(implementation) if implementation.self_ty.as_ref() == &parse_quote!(Connection) => {
                for item in &mut implementation.items {
                    let ImplItem::Fn(method) = item else { continue };
                    match method.sig.ident.to_string().as_str() {
                        "new" => {
                            let Some(syn::Stmt::Expr(Expr::Struct(construction), None)) = method.block.stmts.last_mut()
                                else { panic!("tonic Connection new returns Self"); };
                            construction.fields.push(parse_quote!(faultpoint_uri: endpoint.uri));
                            construction.fields.push(parse_quote!(faultpoint_timeout: endpoint.timeout));
                            changed += 1;
                        }
                        "call" => {
                            let original = method.block.stmts.clone();
                            method.block = parse_quote!({
                                let mut req = req;
                                if let Some(call) = req.extensions_mut().remove::<::faultpoint::client::TransportCall>() {
                                    let path = req.uri().path().to_owned();
                                    return call.execute(::faultpoint::client::TransportTarget {
                                        uri: &self.faultpoint_uri, path: &path,
                                        deadline: self.faultpoint_timeout.map(|duration| ::faultpoint::client::Deadline {
                                            duration, failure: || Box::new(crate::TimeoutExpired(())) as crate::Error,
                                        }),
                                    },
                                        || self.inner.call(req),
                                        |rule| Ok(crate::Status::new(crate::Code::from_i32(
                                            ::faultpoint::client::grpc_failure_code(rule)), "faultpoint: injected gRPC failure").into_http()));
                                }
                                #(#original)*
                            });
                            changed += 1;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if changed != 3 { panic!("tonic connection layout is unsupported: rewrote {changed} of 3 boundaries"); }
    std::fs::write(path, prettyplease::unparse(&syntax)).expect("cannot write tonic connection");
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
