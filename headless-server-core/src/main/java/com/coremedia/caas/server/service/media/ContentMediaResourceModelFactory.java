package com.coremedia.caas.server.service.media;

import com.coremedia.caas.service.repository.RootContext;
import com.coremedia.caas.service.repository.content.model.ContentModelFactory;
import com.coremedia.cap.content.Content;
import com.coremedia.cap.transform.TransformImageService;
import com.coremedia.transform.NamedTransformBeanBlobTransformer;

public class ContentMediaResourceModelFactory implements ContentModelFactory<ContentMediaResourceModel>, MediaResourceModelFactory {

  private NamedTransformBeanBlobTransformer mediaTransformer;
  private TransformImageService transformImageService;


  public ContentMediaResourceModelFactory(NamedTransformBeanBlobTransformer mediaTransformer, TransformImageService transformImageService) {
    this.mediaTransformer = mediaTransformer;
    this.transformImageService = transformImageService;
  }


  @Override
  public boolean isExpressionModel() {
    return false;
  }

  @Override
  public String getModelName() {
    return MODEL_NAME;
  }

  @Override
  public ContentMediaResourceModel createModel(Content content, String propertyPath, RootContext rootContext) {
    return new ContentMediaResourceModel(content, propertyPath, mediaTransformer, transformImageService);
  }
}
