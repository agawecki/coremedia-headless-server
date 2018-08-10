package com.coremedia.caas.server.controller.base;

import com.coremedia.blueprint.base.settings.SettingsService;
import com.coremedia.caas.config.ProcessingDefinition;
import com.coremedia.caas.config.ProcessingDefinitionCacheKey;
import com.coremedia.caas.execution.ExecutionContext;
import com.coremedia.caas.server.service.request.ClientIdentification;
import com.coremedia.caas.server.service.request.GlobalParameters;
import com.coremedia.caas.service.ServiceRegistry;
import com.coremedia.caas.service.repository.RootContext;
import com.coremedia.caas.service.security.AccessControlViolation;
import com.coremedia.cache.Cache;
import com.coremedia.cache.CacheKey;
import com.coremedia.cap.multisite.Site;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Objects;
import graphql.ExecutionInput;
import graphql.ExecutionResult;
import graphql.GraphQL;
import graphql.GraphQLError;
import graphql.execution.instrumentation.InstrumentationContext;
import graphql.execution.instrumentation.InstrumentationState;
import graphql.execution.instrumentation.SimpleInstrumentation;
import graphql.execution.instrumentation.parameters.InstrumentationExecutionParameters;
import graphql.execution.instrumentation.parameters.InstrumentationFieldFetchParameters;
import graphql.schema.DataFetcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.ServletWebRequest;

import javax.validation.constraints.NotNull;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import static graphql.execution.instrumentation.SimpleInstrumentationContext.whenCompleted;

public abstract class GraphQLControllerBase extends ControllerBase {

  private static final Logger LOG = LoggerFactory.getLogger(GraphQLControllerBase.class);


  @Autowired
  private ApplicationContext applicationContext;

  @Autowired
  private Cache cache;

  @Autowired
  private ServiceRegistry serviceRegistry;

  @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
  @Autowired
  private SettingsService settingsService;

  @Autowired
  @Qualifier("staticProcessingDefinitions")
  private Map<String, ProcessingDefinition> staticProcessingDefinitions;


  public GraphQLControllerBase(String timerName) {
    super(timerName);
  }


  private Map<String, Object> getQueryArgs(ServletWebRequest request) {
    return request.getParameterMap().entrySet().stream()
            .filter(e -> !GlobalParameters.GLOBAL_BLACKLIST.contains(e.getKey()))
            .filter(e -> {
              String[] v = e.getValue();
              return v != null && v.length > 0 && v[0] != null;
            })
            .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue()[0]));
  }

  private Object runQuery(@NotNull RootContext rootContext, @NotNull ClientIdentification clientIdentification, @NotNull String queryName, @NotNull String viewName, Map<String, Object> queryArgs) {
    boolean doCache = true;
    if (!doCache) {
      return evalQuery(rootContext, clientIdentification, queryName, viewName, queryArgs);
    }
    JsonResult jsonResult = cache.get(new GraphQLQueryCacheKey(rootContext, clientIdentification, queryName, viewName, queryArgs));

    return ResponseEntity
            .ok()
            .contentType(MediaType.APPLICATION_JSON)
            .eTag(jsonResult.eTag)
            //.lastModified(jsonResult.timestamp.toEpochMilli()) inaccurate fallback, etag is superior
            .body(jsonResult.json);
  }

  private Object evalQuery(@NotNull RootContext rootContext, @NotNull ClientIdentification clientIdentification, @NotNull String queryName, @NotNull String viewName, Map<String, Object> queryArgs) {
    String definitionName = clientIdentification.getDefinitionName();
    // repository defined runtime definition
    ProcessingDefinitionCacheKey processingDefinitionCacheKey = new ProcessingDefinitionCacheKey(rootContext.getSite().getSiteIndicator(), settingsService, applicationContext);
    ProcessingDefinition resolvedDefinition = cache.get(processingDefinitionCacheKey).get(definitionName);
    // fallback executable static definition
    if (resolvedDefinition == null || !resolvedDefinition.hasQueryDefinition(queryName, viewName)) {
      resolvedDefinition = staticProcessingDefinitions.get(definitionName);
    }
    if (resolvedDefinition == null || !resolvedDefinition.hasQueryDefinition(queryName, viewName)) {
      LOG.error("No processing definition found for name '{}' and query '{}#{}'", definitionName, queryName, viewName);
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
    ProcessingDefinition processingDefinition = resolvedDefinition;
    // create new runtime context for capturing all required runtime services and state
    ExecutionContext context = new ExecutionContext(processingDefinition, serviceRegistry, rootContext);
    // run query
    ExecutionInput executionInput = ExecutionInput.newExecutionInput()
            .query(processingDefinition.getQuery(queryName, viewName))
            .root(rootContext.getTarget())
            .context(context)
            .variables(queryArgs)
            .build();
    ExecutionResult result = GraphQL.newGraphQL(processingDefinition.getQuerySchema(rootContext.getTarget(), queryName, viewName))
            .preparsedDocumentProvider(processingDefinition.getQueryRegistry())
            .instrumentation(new DependencyTrackingInstrumentation())
            .build()
            .execute(executionInput);
    if (!result.getErrors().isEmpty()) {
      for (GraphQLError error : result.getErrors()) {
        LOG.error("GraphQL execution error: {}", error.toString());
      }
    }
    result.toSpecification();
    return result.getData();
  }

  protected Object execute(String tenantId, String siteId, String queryName, String targetId, String viewName, ServletWebRequest request) {
    try {
      RootContext rootContext;
      if (targetId == null) {
        rootContext = resolveRootContext(tenantId, siteId, request);
      } else {
        rootContext = resolveRootContext(tenantId, siteId, targetId, request);
      }
      // determine client
      ClientIdentification clientIdentification = resolveClient(rootContext, request);
      String clientId = clientIdentification.getId().toString();
      String definitionName = clientIdentification.getDefinitionName();
      // determine query arguments
      Map<String, Object> queryArgs = getQueryArgs(request);
      // initialize expression evaluator
      serviceRegistry.getExpressionEvaluator().init(queryArgs);
      // run query
      return execute(() -> runQuery(rootContext, clientIdentification, queryName, viewName, queryArgs), "tenant", tenantId, "site", siteId, "client", clientId, "pd", definitionName, "query", queryName, "view", viewName);
    } catch (AccessControlViolation e) {
      return handleError(e, request);
    } catch (ResponseStatusException e) {
      return handleError(e, request);
    } catch (Exception e) {
      return handleError(e, request);
    }
  }


  class DependencyTrackingInstrumentationState implements InstrumentationState {
    boolean contextSet = false;
    Cache.Context cacheContext = Cache.currentContext();
  }

  class DependencyTrackingInstrumentation extends SimpleInstrumentation {
    @Override
    public InstrumentationState createState() {
      //
      // instrumentation state is passed during each invocation of an Instrumentation method
      // and allows you to put stateful data away and reference it during the query execution
      //
      return new DependencyTrackingInstrumentationState();
    }

    @Override
    public InstrumentationContext<ExecutionResult> beginExecution(InstrumentationExecutionParameters parameters) {
      return whenCompleted((result, t) -> {
        DependencyTrackingInstrumentationState state = parameters.getInstrumentationState();
        Cache.Context context = Cache.currentContext();
        if (context != state.cacheContext) {
          // will throw IllegalStateException if current context is non-null
          Cache.setContext(state.cacheContext);
          state.contextSet = true;
        }
      });
    }

    @Override
    public DataFetcher<?> instrumentDataFetcher(DataFetcher<?> dataFetcher, InstrumentationFieldFetchParameters parameters) {
      // maybe we haveto check whether dependency tracker is set up for the current thread
      //DependencyTrackingInstrumentationState customInstrumentationState = parameters.getInstrumentationState();
      return super.instrumentDataFetcher(dataFetcher, parameters);
    }

    @Override
    public CompletableFuture<ExecutionResult> instrumentExecutionResult(ExecutionResult executionResult, InstrumentationExecutionParameters parameters) {
      DependencyTrackingInstrumentationState dependencyTrackingInstrumentationState = parameters.getInstrumentationState();
      if (dependencyTrackingInstrumentationState.contextSet) {
        Cache.unsetContext();
      }
      return CompletableFuture.completedFuture(executionResult);
    }

  }

  static class JsonResult {
    String json;
    String eTag;
    Instant timestamp;

    JsonResult(String json, String eTag) {
      this.json = json;
      this.eTag = eTag;
      this.timestamp = Instant.now();
    }
  }

  class GraphQLQueryCacheKey extends CacheKey<JsonResult> {


    @NotNull
    private RootContext rootContext;

    @NotNull
    private ClientIdentification clientIdentification;

    @NotNull
    private String queryName;

    @NotNull
    private String viewName;

    private Map<String, Object> queryArgs;

    GraphQLQueryCacheKey(RootContext rootContext, ClientIdentification clientIdentification, String queryName, String viewName, Map<String, Object> queryArgs) {
      this.rootContext = rootContext;
      this.clientIdentification = clientIdentification;
      this.queryName = queryName;
      this.viewName = viewName;
      this.queryArgs = queryArgs;
    }

    @Override
    public JsonResult evaluate(Cache cache) throws JsonProcessingException, NoSuchAlgorithmException {
      Object o = evalQuery(rootContext, clientIdentification, queryName, viewName, queryArgs);
      ObjectMapper objectMapper = new ObjectMapper();
      String json = objectMapper.writeValueAsString(o);
      objectMapper.writeValueAsString(o);
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(json.getBytes());
      byte[] digest = md.digest();
      String etag = DatatypeConverter
              .printHexBinary(digest).toUpperCase();
      return new JsonResult(json, etag);
    }

    @Override
    public int hashCode() {
      Site site = rootContext.getSite();
      Object  target = rootContext.getTarget();

      int hashCode = Objects.hashCode(site, target, clientIdentification, queryName, viewName, queryArgs);
      return hashCode;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      GraphQLQueryCacheKey dck = (GraphQLQueryCacheKey) o;
      boolean b = queryName.equals(dck.queryName) &&
              viewName.equals(dck.viewName) &&
              clientIdentification.equals(dck.clientIdentification) &&
              Objects.equal(queryArgs, dck.queryArgs) &&
              Objects.equal(rootContext.getSite(), dck.rootContext.getSite());
      return b;
    }
  }


}
