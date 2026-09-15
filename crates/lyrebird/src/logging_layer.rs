use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
};

use tracing_subscriber::{layer::Layer, layer::SubscriberExt, Registry};

pub(super) type DynamicLogLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

pub(super) struct LogConfig {
    pub(super) filter: Arc<tracing_subscriber::EnvFilter>,
    pub(super) sink: Arc<DynamicLogLayer>,
}

pub(super) struct ManagedLayer {
    pub(super) inner: Arc<RwLock<LogConfig>>,
    spans: Mutex<HashMap<tracing::span::Id, Arc<tracing_subscriber::EnvFilter>>>,
    callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
}

type LayeredSubscriber = tracing_subscriber::layer::Layered<ManagedLayer, Registry>;

pub(super) struct OwnedDispatcher {
    pub(super) inner: Arc<RwLock<LogConfig>>,
    pub(super) callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
    subscriber: LayeredSubscriber,
}

impl Layer<Registry> for ManagedLayer {
    fn on_layer(&mut self, subscriber: &mut Registry) {
        if let Ok(mut layer) = self.inner.write() {
            if let Some(sink) = Arc::get_mut(&mut layer.sink) {
                sink.on_layer(subscriber);
            }
        }
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        let mut callsites = self
            .callsites
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !callsites.iter().any(|known| std::ptr::eq(*known, metadata)) {
            callsites.push(metadata);
        }
        let filter = self.current_filter();
        let _ = <tracing_subscriber::EnvFilter as Layer<Registry>>::register_callsite(
            &*filter, metadata,
        );
        let filters: Vec<_> = self
            .spans
            .lock()
            .map(|spans| spans.values().cloned().collect())
            .unwrap_or_default();
        let mut registered = HashSet::from([Arc::as_ptr(&filter)]);
        for active in filters {
            if registered.insert(Arc::as_ptr(&active)) {
                let _ = <tracing_subscriber::EnvFilter as Layer<Registry>>::register_callsite(
                    &*active, metadata,
                );
            }
        }
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) -> bool {
        let filter = self.new_span_filter(&ctx);
        let enabled = filter.enabled(metadata, ctx.clone());
        enabled
            && self
                .inner
                .read()
                .map(|layer| Arc::clone(&layer.sink))
                .map(|sink| sink.enabled(metadata, ctx))
                .unwrap_or(false)
    }

    fn event_enabled(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) -> bool {
        self.inner
            .read()
            .map(|layer| Arc::clone(&layer.sink))
            .map(|sink| sink.event_enabled(event, ctx))
            .unwrap_or(false)
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_event(event, ctx);
        }
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.new_span_filter(&ctx);
        if let Ok(mut spans) = self.spans.lock() {
            spans.insert(id.clone(), Arc::clone(&filter));
        }
        filter.on_new_span(attrs, id, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_new_span(attrs, id, ctx);
        }
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.filter_for_id(span);
        filter.on_record(span, values, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_record(span, values, ctx);
        }
    }

    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_follows_from(span, follows, ctx);
        }
    }

    fn on_enter(
        &self,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.filter_for_id(id);
        filter.on_enter(id, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_enter(id, ctx);
        }
    }

    fn on_exit(
        &self,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.filter_for_id(id);
        filter.on_exit(id, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_exit(id, ctx);
        }
    }

    fn on_close(
        &self,
        id: tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.filter_for_id(&id);
        filter.on_close(id.clone(), ctx.clone());
        if let Ok(mut spans) = self.spans.lock() {
            spans.remove(&id);
        }
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_close(id, ctx);
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
}

impl ManagedLayer {
    pub(super) fn new(
        inner: Arc<RwLock<LogConfig>>,
        callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
    ) -> Self {
        Self {
            inner,
            spans: Mutex::new(HashMap::new()),
            callsites,
        }
    }

    fn current_filter(&self) -> Arc<tracing_subscriber::EnvFilter> {
        self.inner
            .read()
            .map(|layer| Arc::clone(&layer.filter))
            .unwrap_or_else(|_| Arc::new(tracing_subscriber::EnvFilter::new("off")))
    }

    fn new_span_filter(
        &self,
        ctx: &tracing_subscriber::layer::Context<'_, Registry>,
    ) -> Arc<tracing_subscriber::EnvFilter> {
        let current = ctx.current_span().id().cloned();
        if let Some(id) = current {
            if let Ok(spans) = self.spans.lock() {
                if let Some(filter) = spans.get(&id) {
                    return Arc::clone(filter);
                }
            }
        }
        self.inner
            .read()
            .map(|layer| Arc::clone(&layer.filter))
            .unwrap_or_else(|_| Arc::new(tracing_subscriber::EnvFilter::new("off")))
    }

    fn filter_for_id(&self, id: &tracing::span::Id) -> Arc<tracing_subscriber::EnvFilter> {
        self.spans
            .lock()
            .ok()
            .and_then(|spans| spans.get(id).cloned())
            .or_else(|| {
                self.inner
                    .read()
                    .ok()
                    .map(|layer| Arc::clone(&layer.filter))
            })
            .unwrap_or_else(|| Arc::new(tracing_subscriber::EnvFilter::new("off")))
    }
}

impl OwnedDispatcher {
    pub(super) fn new(inner: Arc<RwLock<LogConfig>>) -> Self {
        let callsites = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(ManagedLayer::new(
            Arc::clone(&inner),
            Arc::clone(&callsites),
        ));
        Self {
            inner,
            callsites,
            subscriber,
        }
    }
}

impl tracing::Subscriber for OwnedDispatcher {
    fn on_register_dispatch(&self, dispatch: &tracing::Dispatch) {
        self.subscriber.on_register_dispatch(dispatch);
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        self.subscriber.register_callsite(metadata)
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        self.subscriber.enabled(metadata)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        self.subscriber.max_level_hint()
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.subscriber.new_span(span)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.subscriber.record(span, values);
    }

    fn record_follows_from(&self, span: &tracing::span::Id, follows: &tracing::span::Id) {
        self.subscriber.record_follows_from(span, follows);
    }

    fn event_enabled(&self, event: &tracing::Event<'_>) -> bool {
        self.subscriber.event_enabled(event)
    }

    fn event(&self, event: &tracing::Event<'_>) {
        self.subscriber.event(event);
    }

    fn enter(&self, span: &tracing::span::Id) {
        self.subscriber.enter(span);
    }

    fn exit(&self, span: &tracing::span::Id) {
        self.subscriber.exit(span);
    }

    fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
        self.subscriber.clone_span(id)
    }

    fn try_close(&self, id: tracing::span::Id) -> bool {
        self.subscriber.try_close(id)
    }

    fn current_span(&self) -> tracing_core::span::Current {
        self.subscriber.current_span()
    }
}
