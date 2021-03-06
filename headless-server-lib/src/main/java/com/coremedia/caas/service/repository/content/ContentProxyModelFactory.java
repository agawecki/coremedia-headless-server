package com.coremedia.caas.service.repository.content;

import com.coremedia.caas.service.repository.ProxyModelFactory;
import com.coremedia.caas.service.repository.RootContext;
import com.coremedia.caas.service.repository.content.model.ContentModelFactory;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class ContentProxyModelFactory implements ProxyModelFactory {

  private static final Class<ContentProxyImpl> targetClass = ContentProxyImpl.class;

  private static final Class[] targetClasses = new Class[]{targetClass};


  private Map<String, ContentModelFactory> modelFactories;


  public ContentProxyModelFactory(List<ContentModelFactory> modelFactories) {
    this.modelFactories = modelFactories.stream().collect(Collectors.toMap(ContentModelFactory::getModelName, Function.identity()));
  }


  @Override
  public boolean appliesTo(String modelName, String propertyPath, Object source, RootContext rootContext) {
    return isTargetClass(source) && modelFactories.containsKey(modelName);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T createModel(String modelName, String propertyPath, Object source, RootContext rootContext) {
    return (T) modelFactories.get(modelName).createModel(targetClass.cast(source).getContent(), propertyPath, rootContext);
  }


  /*
   * Accessor support
   */

  boolean isTargetClass(Object source) {
    return targetClass.isInstance(source);
  }

  boolean isExpressionModel(Object source, String modelName) {
    return isTargetClass(source) && modelFactories.containsKey(modelName) && modelFactories.get(modelName).isExpressionModel();
  }


  Object getModel(Object source, String modelName) {
    return targetClass.cast(source).getModel(modelName);
  }

  Class<?>[] getTargetClasses() {
    return targetClasses;
  }
}
